/*
 * Generic Linux 4.19 server content.
 *
 * Deliberately distro-neutral: no /etc/debian_version, no apt/dpkg state,
 * no Ubuntu/Debian strings. Everything a scanner or an attacker pokes at
 * (accounts, sshd config, web root, a bit of shell history and an auth
 * log) exists and is internally consistent with the persona.
 */
#include "mp_linuxfs.h"

#define DIR   MP_LFS_DIR, NULL
#define F(t)  MP_LFS_FILE, t

static const mp_lfs_node_t s_nodes[] = {
    { "/",            DIR, 0755, "root", "root" },
    { "/bin",         DIR, 0755, "root", "root" },
    { "/boot",        DIR, 0755, "root", "root" },
    { "/dev",         DIR, 0755, "root", "root" },
    { "/etc",         DIR, 0755, "root", "root" },
    { "/etc/ssh",     DIR, 0755, "root", "root" },
    { "/home",        DIR, 0755, "root", "root" },
    { "/home/admin",  DIR, 0750, "admin","admin" },
    { "/lib",         DIR, 0755, "root", "root" },
    { "/lib64",       DIR, 0755, "root", "root" },
    { "/media",       DIR, 0755, "root", "root" },
    { "/mnt",         DIR, 0755, "root", "root" },
    { "/opt",         DIR, 0755, "root", "root" },
    { "/proc",        DIR, 0555, "root", "root" },
    { "/root",        DIR, 0700, "root", "root" },
    { "/run",         DIR, 0755, "root", "root" },
    { "/sbin",        DIR, 0755, "root", "root" },
    { "/srv",         DIR, 0755, "root", "root" },
    { "/sys",         DIR, 0555, "root", "root" },
    { "/tmp",         DIR, 1777, "root", "root" },
    { "/usr",         DIR, 0755, "root", "root" },
    { "/usr/bin",     DIR, 0755, "root", "root" },
    { "/usr/lib",     DIR, 0755, "root", "root" },
    { "/usr/local",   DIR, 0755, "root", "root" },
    { "/usr/sbin",    DIR, 0755, "root", "root" },
    { "/var",         DIR, 0755, "root", "root" },
    { "/var/log",     DIR, 0755, "root", "root" },
    { "/var/www",     DIR, 0755, "root", "root" },
    { "/var/www/html",DIR, 0755, "root", "root" },

    /* ---- /etc ---- */
    { "/etc/hostname", F("linux\n"), 0644, "root", "root" },
    { "/etc/hosts", F(
        "127.0.0.1\tlocalhost\n"
        "127.0.1.1\tlinux\n"
        "\n"
        "# The following lines are desirable for IPv6 capable hosts\n"
        "::1     localhost ip6-localhost ip6-loopback\n"
        "ff02::1 ip6-allnodes\n"
        "ff02::2 ip6-allrouters\n"), 0644, "root", "root" },
    { "/etc/issue", F("Linux 4.19 \\n \\l\n\n"), 0644, "root", "root" },
    { "/etc/os-release", F(
        "NAME=\"Linux\"\n"
        "VERSION=\"4.19\"\n"
        "ID=linux\n"
        "PRETTY_NAME=\"Linux 4.19\"\n"
        "VERSION_ID=\"4.19\"\n"
        "HOME_URL=\"https://www.kernel.org/\"\n"), 0644, "root", "root" },
    { "/etc/passwd", F(
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
        "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
        "sync:x:4:65534:sync:/bin:/bin/sync\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        "sshd:x:105:65534::/run/sshd:/usr/sbin/nologin\n"
        "admin:x:1000:1000:admin:/home/admin:/bin/bash\n"), 0644, "root", "root" },
    { "/etc/group", F(
        "root:x:0:\n"
        "daemon:x:1:\n"
        "bin:x:2:\n"
        "sys:x:3:\n"
        "sudo:x:27:admin\n"
        "www-data:x:33:\n"
        "admin:x:1000:\n"), 0644, "root", "root" },
    { "/etc/shadow", F(
        "root:$6$RoundAndRound$e0J3x9Q0mA0k1J0:19000:0:99999:7:::\n"
        "daemon:*:18800:0:99999:7:::\n"
        "bin:*:18800:0:99999:7:::\n"
        "www-data:*:18800:0:99999:7:::\n"
        "sshd:*:18800:0:99999:7:::\n"
        "admin:$6$AnotherSalt$Kd93mZ1qP8sL2vN:19100:0:99999:7:::\n"), 0640, "root", "shadow" },
    { "/etc/fstab", F(
        "# <file system> <mount point>   <type>  <options>       <dump>  <pass>\n"
        "/dev/sda1       /               ext4    errors=remount-ro 0       1\n"
        "/dev/sda2       none            swap    sw              0       0\n"
        "tmpfs           /run            tmpfs   defaults,noatime 0       0\n"), 0644, "root", "root" },
    { "/etc/ssh/sshd_config", F(
        "Port 22\n"
        "Protocol 2\n"
        "HostKey /etc/ssh/ssh_host_rsa_key\n"
        "LoginGraceTime 2m\n"
        "PermitRootLogin yes\n"
        "StrictModes yes\n"
        "MaxAuthTries 6\n"
        "PasswordAuthentication yes\n"
        "PermitEmptyPasswords no\n"
        "ChallengeResponseAuthentication no\n"
        "UsePAM yes\n"
        "X11Forwarding yes\n"
        "PrintMotd no\n"
        "AcceptEnv LANG LC_*\n"
        "Subsystem sftp /usr/lib/openssh/sftp-server\n"), 0644, "root", "root" },

    /* ---- web root ---- */
    { "/var/www/html/index.html", F(
        "<!DOCTYPE html>\n<html>\n<head>\n"
        "<title>Welcome</title>\n</head>\n<body>\n"
        "<h1>It works!</h1>\n"
        "<p>This is the default web page for this server.</p>\n"
        "</body>\n</html>\n"), 0644, "root", "root" },

    /* ---- /proc (static; dynamic values are generated by the shell) ---- */
    { "/proc/version", F(
        "Linux version 4.19.0 (gcc version 8.3.0 (GCC)) #1 SMP x86_64 GNU/Linux\n"),
      0444, "root", "root" },
    { "/proc/cpuinfo", F(
        "processor\t: 0\n"
        "vendor_id\t: GenuineIntel\n"
        "cpu family\t: 6\n"
        "model\t\t: 85\n"
        "model name\t: Intel(R) Xeon(R) Gold 6152 CPU @ 2.10GHz\n"
        "stepping\t: 4\n"
        "microcode\t: 0x2000065\n"
        "cpu MHz\t\t: 2095.078\n"
        "cache size\t: 30976 KB\n"
        "physical id\t: 0\n"
        "siblings\t: 2\n"
        "core id\t\t: 0\n"
        "cpu cores\t: 2\n"
        "flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov "
        "pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb rdtscp lm "
        "constant_tsc rep_good nopl xtopology cpuid pni pclmulqdq ssse3 fma cx16 "
        "pcid sse4_1 sse4_2 movbe popcnt aes xsave avx f16c rdrand hypervisor "
        "lahf_lm abm 3dnowprefetch\n"
        "\n"), 0444, "root", "root" },
    { "/proc/meminfo", F(
        "MemTotal:        2013276 kB\n"
        "MemFree:         1478032 kB\n"
        "MemAvailable:    1623588 kB\n"
        "Buffers:           42316 kB\n"
        "Cached:           361240 kB\n"
        "SwapCached:            0 kB\n"
        "SwapTotal:       1048572 kB\n"
        "SwapFree:        1048572 kB\n"), 0444, "root", "root" },
    { "/proc/mounts", F(
        "/dev/sda1 / ext4 rw,relatime,errors=remount-ro 0 0\n"
        "tmpfs /run tmpfs rw,nosuid,noexec,relatime,size=197024k,mode=755 0 0\n"
        "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"
        "sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\n"), 0444, "root", "root" },

    /* ---- things attackers hunt for ---- */
    { "/root/.bash_history", F(
        "ls -la\n"
        "cd /var/www/html\n"
        "vi index.html\n"
        "systemctl restart apache2\n"
        "tail -f /var/log/auth.log\n"
        "mysql -u root -p\n"
        "exit\n"), 0600, "root", "root" },
    { "/var/log/auth.log", F(
        "Oct  1 03:14:22 linux sshd[1093]: Failed password for root from 203.0.113.9 port 51422 ssh2\n"
        "Oct  1 03:14:25 linux sshd[1093]: Failed password for root from 203.0.113.9 port 51424 ssh2\n"
        "Oct  1 03:14:29 linux sshd[1093]: Failed password for invalid user admin from 203.0.113.9 port 51430 ssh2\n"
        "Oct  1 03:14:31 linux sshd[1093]: Connection closed by authenticating user root 203.0.113.9 port 51430 [preauth]\n"
        "Oct  1 09:00:01 linux CRON[2201]: pam_unix(cron:session): session opened for user root\n"),
      0640, "root", "adm" },
};

const mp_lfs_t mp_lfs_linux419 = {
    .hostname = "linux",
    .nodes = s_nodes,
    .n = sizeof(s_nodes) / sizeof(s_nodes[0]),
};
