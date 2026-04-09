# Pure Storage Multipath Management Utilities
# Copyright (c) 2026 Jason Cheng (Jason Tools)
# Licensed under the MIT License

package PVE::Storage::Custom::PureStorage::Multipath;

use strict;
use warnings;

use Carp qw(croak);
use IPC::Open3;
use Symbol qw(gensym);
use IO::Select;
use File::Basename qw(basename dirname);
use POSIX ();

use Exporter qw(import);

our @EXPORT_OK = qw(
    rescan_scsi_hosts
    multipath_reload
    multipath_flush
    multipath_resize_map
    get_multipath_device
    get_device_by_wwid
    wait_for_multipath_device
    remove_scsi_device
    rescan_scsi_device
    get_multipath_slaves
    cleanup_lun_devices
    is_device_in_use
    sysfs_write_with_timeout
    sysfs_read_with_timeout
    list_pure_multipath_devices
);

# Constants
use constant {
    MULTIPATHD         => '/sbin/multipathd',
    MULTIPATH          => '/sbin/multipath',
    SG_INQ          => '/usr/bin/sg_inq',
    SCSI_HOST_PATH     => '/sys/class/scsi_host',
    SCSI_DEVICE_PATH   => '/sys/class/scsi_device',
    BLOCK_DEVICE_PATH  => '/sys/class/block',
    DEVICE_WAIT_TIMEOUT   => 60,
    DEVICE_WAIT_INTERVAL  => 2,
};

# Untaint a device name (e.g., sda, dm-0)
sub _untaint_device_name {
    my ($name) = @_;
    return undef unless defined $name;
    # Allow device names like: sda, sda1, dm-0, nvme0n1, 3600a0980...
    if ($name =~ /^([a-zA-Z0-9_\-]+)$/) {
        return $1;
    }
    return undef;
}

# Untaint a device path (e.g., /dev/sda, /dev/mapper/mpath0)
sub _untaint_device_path {
    my ($path) = @_;
    return undef unless defined $path;
    # Allow paths like: /dev/sda, /dev/mapper/3600a0980..., /dev/disk/by-id/...
    if ($path =~ m|^(/dev/[a-zA-Z0-9_\-/\.]+)$|) {
        return $1;
    }
    return undef;
}

# Resolve a device path to the kernel name used in /sys/block/.
# Handles all three forms:
#   /dev/sdX            -> sdX
#   /dev/dm-N           -> dm-N
#   /dev/mapper/<name>  -> dm-N (resolves symlink)
#
# Why this matters: /dev/mapper/<wwid> is a symlink to /dev/dm-N. If you
# `basename()` the mapper path you get the wwid string, then
# /sys/block/<wwid>/{holders,slaves} does NOT exist — those are under
# /sys/block/dm-N/. Without this resolver:
#   - is_device_in_use() would never see LVM/dm-crypt holders → silent
#     data loss when free_image() proceeds to delete an in-use volume.
#   - get_multipath_slaves() would never enumerate the underlying SCSI
#     paths → free_image() would leak SCSI device residue.
sub _resolve_block_device_name {
    my ($device) = @_;
    return undef unless defined $device;

    # If it's a symlink (typical for /dev/mapper/*), resolve to target.
    if (-l $device) {
        my $target = readlink($device);
        if (defined $target) {
            # readlink may return a relative path like "../dm-9".
            if ($target !~ m|^/|) {
                my $dir = dirname($device);
                $target = "$dir/$target";
            }
            # Normalize "/foo/../" sequences.
            while ($target =~ s|/[^/]+/\.\./|/|g) {}
            $device = $target;
        }
    }

    return _untaint_device_name(basename($device));
}

# Untaint a path component
sub _untaint_path {
    my ($path) = @_;
    return undef unless defined $path;
    # Allow safe path characters
    if ($path =~ m|^([a-zA-Z0-9_\-/\.]+)$|) {
        return $1;
    }
    return undef;
}

# Write to a sysfs file in a forked child with timeout.
# Direct writes to /sys/... can enter uninterruptible sleep (D state) if the
# underlying kernel layer is unresponsive (e.g. dead SCSI host or stale device).
# kill -9 cannot recover such a process — only reboot will. Forking lets the
# parent kill the child if it hangs and continue with the next operation.
sub sysfs_write_with_timeout {
    my ($path, $data, $timeout) = @_;
    $timeout //= 10;

    my $pid = fork();
    if (!defined $pid) {
        warn "fork failed for sysfs write to $path: $!\n";
        return 0;
    }

    if ($pid == 0) {
        # Child: do the sysfs write, then exit immediately
        eval {
            open(my $fh, '>', $path) or die "open: $!";
            print $fh $data;
            close($fh);
        };
        POSIX::_exit($@ ? 1 : 0);
    }

    # Parent: wait for child with timeout
    my $deadline = time() + $timeout;
    while (time() < $deadline) {
        my $res = waitpid($pid, POSIX::WNOHANG());
        if ($res > 0) {
            return ($? >> 8) == 0 ? 1 : 0;
        }
        return 1 if $res < 0;
        select(undef, undef, undef, 0.1);
    }

    # Timeout: kill the child
    warn "sysfs write to $path timed out after ${timeout}s, killing child pid $pid\n";
    kill('KILL', $pid);
    my $reaped = waitpid($pid, POSIX::WNOHANG());
    if ($reaped == 0) {
        warn "child pid $pid in uninterruptible sleep, cannot reap\n";
    }
    return 0;
}

# Read a sysfs/proc file in a forked child with alarm-based timeout.
# Reads to /sys/.../wwid, /sys/.../vpd_pg83, /proc/mounts, etc. can also enter
# D state on dead devices. The child reads, the parent waits with alarm.
sub sysfs_read_with_timeout {
    my ($path, $timeout) = @_;
    $timeout //= 5;

    pipe(my $read_fh, my $write_fh) or do {
        warn "pipe failed for sysfs read of $path: $!\n";
        return undef;
    };

    my $pid = fork();
    if (!defined $pid) {
        warn "fork failed for sysfs read of $path: $!\n";
        close($read_fh);
        close($write_fh);
        return undef;
    }

    if ($pid == 0) {
        # Child: read the file, send content through pipe
        close($read_fh);
        eval {
            open(my $fh, '<', $path) or die "open: $!";
            local $/;
            my $data = <$fh>;
            close($fh);
            print $write_fh ($data // '');
        };
        close($write_fh);
        POSIX::_exit($@ ? 1 : 0);
    }

    # Parent: read from pipe with alarm-based timeout
    close($write_fh);
    my $content = '';

    eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm($timeout);

        while (1) {
            my $buf;
            my $bytes = sysread($read_fh, $buf, 65536);
            last if !defined($bytes) || $bytes == 0;
            $content .= $buf;
        }

        alarm(0);
    };
    my $timed_out = $@;
    alarm(0);
    close($read_fh);

    if ($timed_out) {
        warn "sysfs read of $path timed out after ${timeout}s, killing child pid $pid\n";
        kill('KILL', $pid);
        waitpid($pid, POSIX::WNOHANG());
        return undef;
    }

    waitpid($pid, 0);
    return length($content) ? $content : undef;
}

# Run a command and return output
sub _run_cmd {
    my ($cmd, %opts) = @_;

    my $timeout = $opts{timeout} // 30;

    my ($stdout, $stderr) = ('', '');
    my $err = gensym;
    my $pid;

    eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm($timeout);

        $pid = open3(my $in, my $out, $err, @$cmd);
        close($in);

        # Use IO::Select to read stdout and stderr simultaneously
        # to avoid deadlock when stderr buffer fills up
        my $sel = IO::Select->new($out, $err);
        while (my @ready = $sel->can_read()) {
            for my $fh (@ready) {
                my $buf;
                my $bytes = sysread($fh, $buf, 8192);
                if (!defined($bytes) || $bytes == 0) {
                    $sel->remove($fh);
                    next;
                }
                if ($fh == $out) {
                    $stdout .= $buf;
                } else {
                    $stderr .= $buf;
                }
            }
        }

        waitpid($pid, 0);
        alarm(0);
    };

    if ($@) {
        alarm(0);
        if ($@ eq "timeout\n") {
            # Kill the child process on timeout to prevent orphans
            if ($pid) {
                kill('TERM', $pid);
                waitpid($pid, 0);
            }
            croak "Command timed out after ${timeout}s: @$cmd";
        }
        croak "Command failed: $@";
    }

    my $exit_code = $? >> 8;

    if ($exit_code != 0 && !$opts{ignore_errors}) {
        unless ($opts{allow_nonzero}) {
            croak "Command failed (exit $exit_code): @$cmd\nstderr: $stderr";
        }
    }

    return wantarray ? ($stdout, $stderr, $exit_code) : $stdout;
}

# Rescan all SCSI hosts for new devices
sub rescan_scsi_hosts {
    my (%opts) = @_;

    opendir(my $dh, SCSI_HOST_PATH) or croak "Cannot open " . SCSI_HOST_PATH . ": $!";
    my @hosts = grep { /^host\d+$/ } readdir($dh);
    closedir($dh);

    for my $host (@hosts) {
        # Untaint host name (validated by grep above)
        ($host) = $host =~ /^(host\d+)$/;
        next unless $host;

        my $scan_file = SCSI_HOST_PATH . "/$host/scan";
        if (-w $scan_file) {
            # Use forked timeout-protected write to prevent D-state hang on
            # unresponsive HBA / dead session.
            sysfs_write_with_timeout($scan_file, "- - -\n", 10);
        }
    }

    # Give the kernel time to discover devices
    sleep($opts{delay} // 2);

    return 1;
}

# Reload multipath configuration
sub multipath_reload {
    my (%opts) = @_;

    _run_cmd([MULTIPATHD, 'reconfigure'], allow_nonzero => 1, timeout => $opts{timeout} // 30);
    return 1;
}

# Tell multipathd to re-read the size of an existing device-mapper map.
# Required after `volume_resize` or `volume_snapshot_rollback`: the
# underlying SCSI paths have new attributes but the multipath layer above
# still reports the old size until you explicitly resize the map. Without
# this, QEMU's block_resize will fail with "Cannot grow device files" even
# though the array and the SCSI paths have all updated correctly.
sub multipath_resize_map {
    my ($device, %opts) = @_;
    croak "device is required" unless $device;

    my $name = basename($device);
    my $safe_name = _untaint_device_name($name);
    return 0 unless $safe_name;

    eval {
        _run_cmd([MULTIPATHD, 'resize', 'map', $safe_name],
            allow_nonzero => 1, ignore_errors => 1, timeout => $opts{timeout} // 15);
    };
    return $@ ? 0 : 1;
}

# Flush a specific multipath device, with dmsetup fallback if multipath -f
# hangs or fails. NEVER call this without a $device argument: `multipath -F`
# (capital F) flushes ALL unused multipath maps system-wide and can wipe
# customer storage that the plugin does not own.
sub multipath_flush {
    my ($device, %opts) = @_;
    my $timeout = $opts{timeout} // 10;

    croak "multipath_flush requires a device argument; refusing to call 'multipath -F' which would flush ALL maps system-wide"
        unless $device;

    # Try `multipath -f` with timeout
    my (undef, undef, $exit) = eval {
        _run_cmd([MULTIPATH, '-f', $device],
            allow_nonzero => 1, ignore_errors => 1, timeout => $timeout);
    };
    my $err = $@;

    # If multipath -f hung or failed, fall back to dmsetup remove --force
    # which does not wait for queued I/O.
    if ($err || (defined $exit && $exit != 0)) {
        warn "multipath -f $device failed/timed out, trying dmsetup remove --force\n";
        my $name = basename($device);
        my $safe_name = _untaint_device_name($name);
        if ($safe_name) {
            eval {
                _run_cmd(['/sbin/dmsetup', 'remove', '--force', '--retry', $safe_name],
                    allow_nonzero => 1, ignore_errors => 1, timeout => 10);
            };
            warn "dmsetup remove also failed for $safe_name: $@" if $@;
        }
    }

    return 1;
}

# Get multipath device name by WWID
sub get_multipath_device {
    my ($wwid, %opts) = @_;

    croak "wwid is required" unless $wwid;

    my ($stdout) = _run_cmd(
        [MULTIPATHD, 'show', 'maps', 'raw', 'format', '%n %w'],
        allow_nonzero => 1,
        ignore_errors => 1,
    );

    return undef unless defined $stdout;

    for my $line (split /\n/, $stdout) {
        $line =~ s/^\s+|\s+$//g;
        my ($name, $map_wwid) = split /\s+/, $line, 2;
        next unless $name && $map_wwid;

        if (lc($map_wwid) eq lc($wwid)) {
            # Untaint the device path for taint mode compatibility
            my $safe_name = _untaint_device_name($name);
            return undef unless $safe_name;
            return _untaint_device_path("/dev/mapper/$safe_name");
        }
    }

    return undef;
}

# Get device path by WWID
sub get_device_by_wwid {
    my ($wwid, %opts) = @_;

    croak "wwid is required" unless $wwid;

    # First check multipath
    my $mpath = get_multipath_device($wwid);
    return $mpath if $mpath && -b $mpath;

    # Check /dev/disk/by-id (use exact suffix match to avoid substring collisions)
    my $wwid_lc = lc($wwid);
    my @devices = grep { lc(($_=~ m/-([a-f0-9]+)$/i)[0] // '') eq $wwid_lc }
        glob("/dev/disk/by-id/wwn-*"), glob("/dev/disk/by-id/scsi-*");

    if (@devices && -b $devices[0]) {
        # Untaint the device path for taint mode compatibility
        return _untaint_device_path($devices[0]);
    }

    return undef;
}

# Wait for a multipath device to appear
# Options:
#   timeout - max wait time in seconds (default 60)
#   interval - check interval in seconds (default 2)
#   iscsi_rescan - coderef to call for iSCSI rescan (optional)
#   fc_rescan - coderef to call for FC rescan (optional)
sub wait_for_multipath_device {
    my ($wwid, %opts) = @_;

    croak "wwid is required" unless $wwid;

    my $timeout = $opts{timeout} // DEVICE_WAIT_TIMEOUT;
    my $interval = $opts{interval} // DEVICE_WAIT_INTERVAL;
    my $iscsi_rescan = $opts{iscsi_rescan};
    my $fc_rescan = $opts{fc_rescan};
    my $start_time = time();

    while ((time() - $start_time) < $timeout) {
        # Protocol-specific rescan (if provided)
        if ($iscsi_rescan && ref($iscsi_rescan) eq 'CODE') {
            eval { $iscsi_rescan->(); };
        }
        if ($fc_rescan && ref($fc_rescan) eq 'CODE') {
            eval { $fc_rescan->(); };
        }

        # Trigger SCSI rescan
        rescan_scsi_hosts(delay => 1);
        multipath_reload();

        # Trigger udev to update WWIDs (fixes stale WWID cache issue).
        # Use timeout-bounded _run_cmd — bare system('udevadm') can hang.
        eval { _run_cmd(['/sbin/udevadm', 'trigger', '--subsystem-match=block'],
            timeout => 10, allow_nonzero => 1, ignore_errors => 1); };
        eval { _run_cmd(['/sbin/udevadm', 'settle', '--timeout=5'],
            timeout => 10, allow_nonzero => 1, ignore_errors => 1); };

        # Check for device
        my $device = get_device_by_wwid($wwid);
        if ($device && -b $device) {
            return $device;
        }

        sleep($interval);
    }

    return undef;
}

# Remove a SCSI device from the system
sub remove_scsi_device {
    my ($device, %opts) = @_;

    croak "device is required" unless $device;

    my $dev_name = _untaint_device_name(basename($device));
    croak "Invalid device name" unless $dev_name;

    # Untaint device path for system calls
    my $safe_device = _untaint_path($device);

    # Find the SCSI device path
    my $delete_file = BLOCK_DEVICE_PATH . "/$dev_name/device/delete";

    if (-w $delete_file) {
        # Sync and flush first (with timeout to prevent hang on unresponsive device).
        # Bare system('sync') / system('blockdev') can enter D state forever if
        # the device behind it is dead.
        eval { _run_cmd(['/bin/sync'], timeout => 10, allow_nonzero => 1, ignore_errors => 1); };
        if ($safe_device && -b $safe_device) {
            eval { _run_cmd(['/sbin/blockdev', '--flushbufs', $safe_device],
                timeout => 10, allow_nonzero => 1, ignore_errors => 1); };
        }

        sysfs_write_with_timeout($delete_file, "1\n", 10)
            or croak "Failed to write to $delete_file (timed out or error)";

        return 1;
    }

    croak "Cannot find delete file for device $device";
}

# Rescan a specific SCSI device. Use the symlink-resolving helper rather
# than basename() so a caller passing /dev/mapper/<wwid> doesn't silently
# fail (sysfs path /sys/class/block/<wwid>/device/rescan does not exist).
# Current callers always pass /dev/sdX from get_multipath_slaves, but the
# function is exported and a future caller could pass a multipath path.
sub rescan_scsi_device {
    my ($device, %opts) = @_;

    croak "device is required" unless $device;

    my $dev_name = _resolve_block_device_name($device);
    croak "Invalid device name" unless $dev_name;

    my $rescan_file = BLOCK_DEVICE_PATH . "/$dev_name/device/rescan";

    if (-w $rescan_file) {
        sysfs_write_with_timeout($rescan_file, "1\n", 10)
            or croak "Failed to write to $rescan_file (timed out or error)";
        return 1;
    }

    croak "Cannot find rescan file for device $device";
}

# Get all slave devices for a multipath device.
#
# IMPORTANT: must resolve /dev/mapper/<wwid> symlinks to dm-N before
# accessing /sys/block/. basename('/dev/mapper/3624a9370...') returns the
# wwid, but the slaves directory lives under /sys/block/dm-N/, not
# /sys/block/<wwid>/. Without symlink resolution this function silently
# returned an empty list for every multipath device, which in turn caused
# free_image to leak the underlying SCSI devices.
sub get_multipath_slaves {
    my ($mpath_device, %opts) = @_;

    croak "mpath_device is required" unless $mpath_device;

    my $dev_name = _resolve_block_device_name($mpath_device);
    return [] unless $dev_name;

    my $slaves_dir = BLOCK_DEVICE_PATH . "/$dev_name/slaves";

    return [] unless -d $slaves_dir;

    opendir(my $dh, $slaves_dir) or return [];
    my @slaves;
    for my $slave (readdir($dh)) {
        next if $slave =~ /^\./;
        my $safe_slave = _untaint_device_name($slave);
        push @slaves, "/dev/$safe_slave" if $safe_slave;
    }
    closedir($dh);

    return \@slaves;
}

# Clean up multipath and SCSI devices for a LUN
# IMPORTANT: This must be called BEFORE deleting the LUN on the storage system
sub cleanup_lun_devices {
    my ($wwid, %opts) = @_;

    croak "wwid is required" unless $wwid;

    # Get multipath device
    my $mpath = get_multipath_device($wwid);

    if ($mpath && -b $mpath) {
        # Safety: refuse to cleanup devices that are still in use
        if (is_device_in_use($mpath)) {
            croak "Cannot cleanup LUN devices: $mpath is still in use (mounted, held open, or has holders)";
        }

        # Get slave devices first (before we remove the multipath, the
        # /sys/block/.../slaves directory disappears once the map is gone).
        my $slaves = get_multipath_slaves($mpath);
        my $mpath_name = basename($mpath);
        my $safe_name = _untaint_device_name($mpath_name);
        my $safe_mpath = _untaint_device_path($mpath);

        # CRITICAL: Before any flush/sync operation, disable queue_if_no_path
        # on this specific device. Otherwise sync/blockdev/multipath -f will
        # hang forever if all paths are failed and the device has
        # queue_if_no_path enabled. Then use dmsetup message to fail any
        # already-queued I/O immediately.
        if ($safe_name) {
            eval {
                _run_cmd([MULTIPATHD, 'disablequeueing', 'map', $safe_name],
                    allow_nonzero => 1, ignore_errors => 1, timeout => 5);
            };
            eval {
                _run_cmd(['/sbin/dmsetup', 'message', $safe_name, '0', 'fail_if_no_path'],
                    allow_nonzero => 1, ignore_errors => 1, timeout => 5);
            };
        }

        # Step 1: Sync all pending writes (now safe — queueing is disabled).
        eval { _run_cmd(['/bin/sync'], timeout => 10, allow_nonzero => 1, ignore_errors => 1); };

        # Step 2: Flush device buffers.
        if ($safe_mpath) {
            eval { _run_cmd(['/sbin/blockdev', '--flushbufs', $safe_mpath],
                timeout => 10, allow_nonzero => 1, ignore_errors => 1); };
        }

        # Step 3: Remove the multipath device via multipathd.
        if ($safe_name) {
            eval {
                _run_cmd([MULTIPATHD, 'remove', 'map', $safe_name],
                    allow_nonzero => 1, ignore_errors => 1, timeout => 10);
            };
        }

        # Step 4: Try multipath -f as fallback (with dmsetup --force fallback
        # built into multipath_flush).
        eval { multipath_flush($mpath, timeout => 10); };

        # Step 5: Brief pause to let device-mapper settle.
        sleep(1);

        # Step 6: Remove the underlying SCSI slave devices.
        for my $slave (@$slaves) {
            eval { remove_scsi_device($slave); };
        }

        # Step 7: Brief pause for cleanup to complete.
        sleep(1);
    }

    return 1;
}

# List all multipath devices belonging to Pure Storage (WWID prefix 3624a9370).
# Returns array of { name, wwid, paths_failed } where paths_failed is true if
# none of the underlying paths are 'active ready'. Used by orphan cleanup.
sub list_pure_multipath_devices {
    my (%opts) = @_;

    my ($stdout) = eval {
        _run_cmd([MULTIPATHD, 'show', 'maps', 'raw', 'format', '%n %w'],
            allow_nonzero => 1, ignore_errors => 1, timeout => 10);
    };
    return [] unless defined $stdout;

    my @devices;
    for my $line (split /\n/, $stdout) {
        $line =~ s/^\s+|\s+$//g;
        my ($name, $wwid) = split /\s+/, $line, 2;
        next unless $name && $wwid;
        # Pure Storage WWID prefix: 3624a9370
        next unless lc($wwid) =~ /^3624a9370/;
        push @devices, { name => $name, wwid => lc($wwid) };
    }

    return \@devices;
}

# Check if a device is currently in use (mounted, open by process, or has
# holders such as LVM, dm-crypt, dm-raid).
#
# CRITICAL: must resolve /dev/mapper/<wwid> symlinks to dm-N before
# accessing /sys/block/. The previous implementation used
# basename('/dev/mapper/3624a9370...') which returned the wwid, then looked
# at /sys/block/<wwid>/holders — a path that does not exist. The function
# always returned 0 (not in use) for any multipath device, which meant
# free_image() would happily delete a Pure volume that had an LVM volume
# group, dm-crypt container, or other holder on top of it. **DATA LOSS**.
sub is_device_in_use {
    my ($device, %opts) = @_;

    return 0 unless $device && -b $device;

    my $dev_name = _resolve_block_device_name($device);
    return 0 unless $dev_name;

    # Check 1: Is device mounted? Use timeout-protected read because
    # /proc/mounts can stall on a wedged kernel namespace. Match against
    # both the original $device path (could be /dev/mapper/<wwid>) and the
    # resolved kernel name (dm-N) — different mount(8) versions record
    # different forms.
    my $mounts = sysfs_read_with_timeout('/proc/mounts', 5);
    if (defined $mounts) {
        for my $line (split /\n/, $mounts) {
            if ($line =~ /^\Q$device\E\s/ || $line =~ /^\/dev\/\Q$dev_name\E\s/) {
                return 1;  # Device is mounted
            }
        }
    }

    # Check 2: Does device have holders (e.g., LVM, dm-crypt)?
    my $holders_dir = "/sys/block/$dev_name/holders";
    if (-d $holders_dir) {
        opendir(my $dh, $holders_dir);
        my @holders = grep { !/^\./ } readdir($dh);
        closedir($dh);
        if (@holders) {
            return 1;  # Device has holders
        }
    }

    # Check 3: Is device open by any process? Use timeout-protected _run_cmd
    # rather than bare system('fuser') — fuser opens the device path, which on
    # a wedged multipath device with queue_if_no_path can itself enter D state
    # and never return, hanging the parent forever.
    my $safe_device = _untaint_device_path($device);
    if ($safe_device) {
        my (undef, undef, $exit) = eval {
            _run_cmd(['/bin/fuser', '-s', $safe_device],
                timeout => 5, allow_nonzero => 1, ignore_errors => 1);
        };
        if (!$@ && defined $exit && $exit == 0) {
            return 1;  # Device is open by a process
        }
    }

    return 0;  # Device is not in use
}

1;

__END__

=head1 NAME

PVE::Storage::Custom::PureStorage::Multipath - Multipath and SCSI management utilities

=head1 SYNOPSIS

    use PVE::Storage::Custom::PureStorage::Multipath qw(
        rescan_scsi_hosts
        get_multipath_device
        wait_for_multipath_device
    );

    # Rescan for new devices
    rescan_scsi_hosts();

    # Get multipath device by WWID
    my $device = get_multipath_device('3624a9370abc123def456...');

    # Wait for device to appear
    my $device = wait_for_multipath_device($wwid, timeout => 60);

=head1 DESCRIPTION

This module provides multipath and SCSI device management utilities for
the Pure Storage storage plugin.

=cut
