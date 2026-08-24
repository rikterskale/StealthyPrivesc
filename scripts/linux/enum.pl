#!/usr/bin/env perl
# StealthyPrivesc Linux Perl fallback — authorized assessments only.
# Reduced coverage vs python/bash tiers. Enumeration only; no exploitation.
use strict;
use warnings;

my $authorized = 0;
my $json = 0;
for my $arg (@ARGV) {
    if ($arg eq '--authorized' || $arg eq '--i-understand-authorized-use-only') {
        $authorized = 1;
    }
    if ($arg eq '--json') {
        $json = 1;
    }
}
if (($ENV{STEALTHY_AUTHORIZED} // '') eq '1') {
    $authorized = 1;
}
if (!$authorized) {
    print STDERR "Authorization required: pass --authorized or set STEALTHY_AUTHORIZED=1\n";
    exit 2;
}

sub read_file {
    my ($path) = @_;
    open my $fh, '<', $path or return undef;
    local $/;
    my $data = <$fh>;
    close $fh;
    return $data;
}

sub hostname_of {
    my $h = read_file('/etc/hostname');
    if (defined $h) {
        $h =~ s/\s+\z//;
        return $h if length $h;
    }
    my $out = `hostname 2>/dev/null`;
    chomp $out if defined $out;
    return $out || 'unknown';
}

my $user = $ENV{USER} // 'unknown';
my $host = hostname_of();
my $exec_path = $ENV{STEALTHY_EXECUTION_PATH} // 'perl-fallback';
my $primary_launch = $ENV{STEALTHY_PRIMARY_LAUNCH} // 'not_applicable';
my $roe_ref = $ENV{STEALTHY_MANIFEST_ROE_REF} // '';

if ($json) {
    # Minimal schema v2 shell; enrich with `stealthy ingest` when needed.
    my $roe_esc = $roe_ref;
    $roe_esc =~ s/\\/\\\\/g;
    $roe_esc =~ s/"/\\"/g;
    print '{"schema_version":"2","tool":"stealthy-script","coverage_mode":"script",';
    print '"execution_path":"' . $exec_path . '","primary_launch":"' . $primary_launch . '",';
    print '"roe_ref":"' . $roe_esc . '",';
    print '"notes":["perl fallback — reduced coverage"],"findings":[],';
    print '"os":{"family":"unix","os":"linux","arch":"unknown","version_hint":"linux"},';
    print '"identity":{"username":"' . $user . '","uid":null,"gid":null,"groups":[],';
    print '"is_elevated":false,"elevation_source":"perl","token_context":"","hostname":"' . $host . '"},';
    print '"plugins_run":[],"coverage":[],"assessments":[],"attack_paths":[],"triage_decisions":[],';
    print '"capability_delta":["linux.sudo","linux.suid","linux.cron","linux.systemd","linux.kernel","linux.credentials"],';
    print '"mode":"enumerate-only","profile":"script","authorized_use_ack":true,"version":"0.1.0",';
    print '"run_id":"perl-fallback","started_at_unix":0}' . "\n";
    exit 0;
}

print "=== StealthyPrivesc Linux Perl enum ===\n";
print "LEGAL: Authorized use only.\n\n";

print "[*] identity\n";
my $uid = (read_file('/proc/self/status') // '') =~ /^Uid:\s+(\d+)/m ? $1 : 'unknown';
print "uid=$uid\nuser=$user\nhostname=$host\n\n";

print "[*] sudoers readable fragments (no sudo -l by default)\n";
for my $path ('/etc/sudoers', glob('/etc/sudoers.d/*')) {
    next unless defined $path && -r $path;
    open my $fh, '<', $path or next;
    while (my $line = <$fh>) {
        if ($line =~ /NOPASSWD|ALL=\(ALL/) {
            print "$path: $line";
        }
    }
    close $fh;
}
print "\n";

print "[*] interesting SUID (shallow)\n";
for my $dir (qw(/usr/bin /usr/sbin /bin /sbin)) {
    next unless -d $dir;
    opendir my $dh, $dir or next;
    while (my $name = readdir $dh) {
        next if $name eq '.' || $name eq '..';
        my $path = "$dir/$name";
        next unless -f $path;
        my $mode = (stat $path)[2];
        next unless defined $mode && ($mode & 04000);
        print "$path\n";
    }
    closedir $dh;
}
print "\n";

print "[*] container sockets\n";
for my $sock (
    '/var/run/docker.sock', '/run/docker.sock',
    '/var/run/podman/podman.sock', '/run/podman/podman.sock',
    '/var/run/containerd/containerd.sock',
    '/var/lib/lxd/unix.socket', '/var/snap/lxd/common/lxd/unix.socket'
) {
    next unless -S $sock;
    print "$sock\n";
    print "FINDING: container socket writable: $sock\n" if -w $sock;
}
print "\n";

print "[*] writable cron/systemd hints\n";
for my $p (qw(/etc/crontab /etc/cron.d /etc/systemd/system)) {
    next unless -e $p;
    print "FINDING: writable $p\n" if -w $p;
}
print "\n";

print "[*] endpoint controls (AppArmor / SELinux / noexec)\n";
if (-d '/sys/module/apparmor' || -d '/sys/kernel/security/apparmor') {
    my $cur = read_file('/proc/self/attr/current');
    $cur = read_file('/proc/self/attr/apparmor/current') unless defined $cur;
    $cur = defined $cur ? $cur : 'unreadable';
    chomp $cur;
    print "AppArmor current=$cur\n";
    print "FINDING: AppArmor enforce profile active for this process\n" if $cur =~ /\(enforce\)/;
} else {
    print "AppArmor module not evident\n";
}
if (-r '/sys/fs/selinux/enforce') {
    my $en = read_file('/sys/fs/selinux/enforce') // '';
    chomp $en;
    print "SELinux enforce=$en\n";
}
if (-r '/proc/self/mountinfo') {
    my $mounts = read_file('/proc/self/mountinfo') // '';
    for my $mp ('/tmp', '/var/tmp', '/dev/shm', $ENV{HOME} // '/nonexistent') {
        next unless length $mp;
        for my $line (split /\n/, $mounts) {
            my @f = split ' ', $line;
            next unless @f >= 6 && $f[4] eq $mp;
            print "FINDING: noexec mount on drop path $mp\n" if $line =~ /\bnoexec\b/;
            last;
        }
    }
}
print "NOTE: if custom ELF is blocked, prefer enum.py / enum.sh / enum-posix.sh / enum.pl.\n\n";

print "[*] shadow readability\n";
if (-r '/etc/shadow') {
    print "FINDING: /etc/shadow readable\n";
} else {
    print "/etc/shadow not readable (expected)\n";
}

print "\nDone. Review findings manually — this script never auto-exploits.\n";
