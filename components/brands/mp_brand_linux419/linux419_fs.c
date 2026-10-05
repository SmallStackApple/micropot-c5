/*
 * Generic Linux 4.19 server file tree (mpfs).
 *
 * Content is distro-neutral on purpose: no apt/dpkg, no distro banners,
 * just a plain x86_64 Linux 4.19 host. File bodies use '\n' line endings;
 * renderers convert to CRLF.
 */
#include "mp_linuxfs.h"
#include "mp_linuxsh.h"

/* /etc/passwd: root + the usual system accounts + one human admin. */
static const char s_passwd[] =
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
    "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
    "sync:x:4:65534:sync:/bin:/bin/sync\n"
    "games:x:5:60:games:/usr/games:/usr/sbin/nologin\n"
    "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n"
    "lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\n"
    "mail:x:8:8:mail:/var/mail:/usr/sbin/nologin\n"
    "news:x:9:9:news:/var/spool/news:/usr/sbin/nologin\n"
    "proxy:x:13:13:proxy:/bin:/usr/sbin/nologin\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
    "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n"
    "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
    "sshd:x:105:65534::/run/sshd:/usr/sbin/nologin\n"
    "admin:x:1000:1000:admin,,,:/home/admin:/bin/bash\n";

static const char s_group[] =
    "root:x:0:\n"
    "daemon:x:1:\n"
    "sudo:x:27:admin\n"
    "www-data:x:33:\n"
    "sshd:x:105:\n"
    "admin:x:1000:\n";

/* sha512crypt-looking placeholders; the point is that the file exists,
 * is root-readable, and looks worth cracking. */
static const char s_shadow[] =
    "root:$6$Xk9f2mQp$dQw4w9WgXcQz7YvN2kL8sJhF3mR5tP6xA1zB9cV7nM2kQ8wE4rT6yU1iO3pA5sD7fG9hJ2kL4zX6cV8bN0m:18345:0:99999:7:::\n"
    "daemon:*:18345:0:99999:7:::\n"
    "bin:*:18345:0:99999:7:::\n"
    "www-data:*:18345:0:99999:7:::\n"
    "sshd:*:18345:0:99999:7:::\n"
    "admin:$6$mZ3vN8xL$kL8sJhF3mR5tP6xA1zB9cV7nM2kQ8wE4rT6yU1iO3pA5sD7fG9hJ2kL4zX6cV8bN0mQ3wE5rT8yU2iO6p:18345:0:99999:7:::\n";

static const char s_hostname[] = "linux\n";

static const char s_hosts[] =
    "127.0.0.1\tlocalhost\n"
    "127.0.1.1\tlinux\n"
    "\n"
    "::1\tlocalhost ip6-localhost ip6-loopback\n"
    "ff02::1\tip6-allnodes\n"
    "ff02::2\tip6-allrouters\n";

static const char s_issue[] = "Linux 4.19 \\n \\l\n";

static const char s_os_release[] =
    "PRETTY_NAME=\"Linux 4.19\"\n"
    "NAME=\"Linux\"\n"
    "VERSION_ID=\"4.19\"\n"
    "VERSION=\"4.19\"\n"
    "ID=linux\n"
    "HOME_URL=\"https://www.kernel.org/\"\n";

static const char s_resolv[] =
    "nameserver 192.168.1.1\n";

static const char s_fstab[] =
    "# /etc/fstab: static file system information.\n"
    "# <file system> <mount point> <type> <options> <dump> <pass>\n"
    "/dev/sda1       /               ext4   errors=remount-ro 0 1\n"
    "tmpfs           /run            tmpfs  nosuid,noexec      0 0\n";

static const char s_proc_version[] =
    "Linux version 4.19.0 (gcc version 8.3.0 (GCC)) #1 SMP x86_64 GNU/Linux\n";

static const char s_proc_cpuinfo[] =
    "processor\t: 0\n"
    "vendor_id\t: GenuineIntel\n"
    "cpu family\t: 6\n"
    "model\t\t: 85\n"
    "model name\t: Intel(R) Xeon(R) Gold 6152 CPU @ 2.10GHz\n"
    "stepping\t: 4\n"
    "cpu MHz\t\t: 2095.078\n"
    "cache size\t: 30976 KB\n"
    "cpu cores\t: 2\n"
    "flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx\n"
    "\n"
    "processor\t: 1\n"
    "vendor_id\t: GenuineIntel\n"
    "cpu family\t: 6\n"
    "model\t\t: 85\n"
    "model name\t: Intel(R) Xeon(R) Gold 6152 CPU @ 2.10GHz\n"
    "stepping\t: 4\n"
    "cpu MHz\t\t: 2095.078\n"
    "cache size\t: 30976 KB\n"
    "cpu cores\t: 2\n"
    "flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx\n";

static const char s_proc_meminfo[] =
    "MemTotal:        2013276 kB\n"
    "MemFree:         1478032 kB\n"
    "MemAvailable:    1623588 kB\n"
    "Buffers:           42316 kB\n"
    "Cached:           361240 kB\n"
    "SwapCached:            0 kB\n"
    "Active:           312544 kB\n"
    "Inactive:         208832 kB\n"
    "SwapTotal:       1048572 kB\n"
    "SwapFree:        1048572 kB\n"
    "Dirty:               124 kB\n"
    "Writeback:             0 kB\n"
    "Mapped:            68412 kB\n"
    "Slab:              48220 kB\n"
    "CommitLimit:     2055208 kB\n"
    "Committed_AS:     412336 kB\n";

static const char s_proc_mounts[] =
    "sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\n"
    "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"
    "udev /dev devtmpfs rw,nosuid,relatime,size=992236k,nr_inodes=248059,mode=755 0 0\n"
    "/dev/sda1 / ext4 rw,relatime,errors=remount-ro,data=ordered 0 0\n"
    "tmpfs /run tmpfs rw,nosuid,noexec,relatime,size=201328k,mode=755 0 0\n";

static const char s_sshd_config[] =
    "# Package generated configuration file\n"
    "Port 22\n"
    "Protocol 2\n"
    "HostKey /etc/ssh/ssh_host_rsa_key\n"
    "HostKey /etc/ssh/ssh_host_ecdsa_key\n"
    "HostKey /etc/ssh/ssh_host_ed25519_key\n"
    "PermitRootLogin yes\n"
    "PasswordAuthentication yes\n"
    "ChallengeResponseAuthentication no\n"
    "UsePAM yes\n"
    "X11Forwarding yes\n"
    "PrintMotd no\n"
    "AcceptEnv LANG LC_*\n"
    "Subsystem sftp /usr/lib/openssh/sftp-server\n";

static const char s_auth_log[] =
    "Oct  3 21:14:02 linux sshd[1421]: Failed password for root from 185.220.101.4 port 51092 ssh2\n"
    "Oct  3 21:14:05 linux sshd[1421]: Failed password for root from 185.220.101.4 port 51092 ssh2\n"
    "Oct  3 21:14:08 linux sshd[1421]: Failed password for root from 185.220.101.4 port 51092 ssh2\n"
    "Oct  3 21:14:08 linux sshd[1421]: Connection closed by 185.220.101.4 port 51092 [preauth]\n"
    "Oct  4 02:31:44 linux sshd[1509]: Accepted password for admin from 192.168.1.66 port 53410 ssh2\n"
    "Oct  4 02:31:44 linux sshd[1509]: pam_unix(sshd:session): session opened for user admin by (uid=0)\n"
    "Oct  4 02:34:10 linux sudo:    admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash\n"
    "Oct  4 02:34:10 linux sudo: pam_unix(sudo:session): session opened for user root by admin(uid=0)\n"
    "Oct  4 06:55:19 linux sshd[1664]: Failed password for invalid user oracle from 45.148.10.88 port 60112 ssh2\n";

static const char s_syslog[] =
    "Oct  1 09:00:04 linux kernel: [    0.000000] Linux version 4.19.0 (gcc version 8.3.0 (GCC)) #1 SMP x86_64 GNU/Linux\n"
    "Oct  1 09:00:04 linux kernel: [    0.000000] Command line: BOOT_IMAGE=/boot/vmlinuz-4.19.0 root=/dev/sda1 ro quiet\n"
    "Oct  1 09:00:05 linux kernel: [    1.204331] EXT4-fs (sda1): mounted filesystem with ordered data mode\n"
    "Oct  1 09:00:07 linux systemd[1]: Started OpenBSD Secure Shell server.\n"
    "Oct  1 09:00:08 linux apache2[655]: AH00163: Apache/2.4.38 configured -- resuming normal operations\n";

static const char s_bash_history[] =
    "cd /var/log\n"
    "tail -f auth.log\n"
    "systemctl status apache2\n"
    "vim /etc/ssh/sshd_config\n"
    "systemctl restart sshd\n"
    "cd /var/www/html\n"
    "ls -la\n"
    "passwd admin\n"
    "top\n"
    "exit\n";

static const char s_www_index[] =
    "<html><body><h1>It works!</h1></body></html>\n";

/* Keep it unbranded: Debian's stock motd paragraph (the "programs included
 * ... free software ... doc/<pkg>/copyright" wording) is instantly
 * recognizable even with the distro name scrubbed. A custom or minimal
 * Linux install ships an empty or one-line motd. */
static const char s_motd[] =
    "Linux linux 4.19.0 #1 SMP x86_64 GNU/Linux\n";

#define D(path)      { path, MPFS_DIR, NULL, "drwxr-xr-x", "root", "root", 4096, "Oct  1 09:00" }
#define F(path, ...) { path, MPFS_FILE, __VA_ARGS__ }

const mpfs_node_t mp_linux419_fs[] = {
    D("/"),
    D("/bin"),
    D("/boot"),
    D("/dev"),
    D("/etc"),
    D("/etc/ssh"),
    D("/home"),
    D("/home/admin"),
    D("/lib"),
    D("/lib64"),
    D("/media"),
    D("/mnt"),
    D("/opt"),
    D("/proc"),
    D("/root"),
    D("/run"),
    D("/sbin"),
    D("/srv"),
    D("/sys"),
    D("/tmp"),
    D("/usr"),
    D("/var"),
    D("/var/log"),
    D("/var/www"),
    D("/var/www/html"),

    F("/etc/passwd", s_passwd, "-rw-r--r--", "root", "root", 0, "Oct  1 09:00"),
    F("/etc/group", s_group, "-rw-r--r--", "root", "root", 0, "Oct  1 09:00"),
    F("/etc/shadow", s_shadow, "-rw-------", "root", "root", 0, "Oct  3 21:12"),
    F("/etc/hostname", s_hostname, "-rw-r--r--", "root", "root", 0, "Oct  1 09:00"),
    F("/etc/hosts", s_hosts, "-rw-r--r--", "root", "root", 0, "Oct  1 09:00"),
    F("/etc/issue", s_issue, "-rw-r--r--", "root", "root", 0, "Oct  1 09:00"),
    F("/etc/os-release", s_os_release, "-rw-r--r--", "root", "root", 0, "Oct  1 09:00"),
    F("/etc/resolv.conf", s_resolv, "-rw-r--r--", "root", "root", 0, "Oct  1 09:00"),
    F("/etc/fstab", s_fstab, "-rw-r--r--", "root", "root", 0, "Oct  1 09:00"),
    F("/etc/motd", s_motd, "-rw-r--r--", "root", "root", 0, "Oct  1 09:00"),
    F("/etc/ssh/sshd_config", s_sshd_config, "-rw-r--r--", "root", "root", 0, "Oct  3 21:12"),
    F("/proc/version", s_proc_version, "-r--r--r--", "root", "root", 0, "Oct  4 09:42"),
    F("/proc/cpuinfo", s_proc_cpuinfo, "-r--r--r--", "root", "root", 0, "Oct  4 09:42"),
    F("/proc/meminfo", s_proc_meminfo, "-r--r--r--", "root", "root", 0, "Oct  4 09:42"),
    F("/proc/mounts", s_proc_mounts, "-r--r--r--", "root", "root", 0, "Oct  4 09:42"),
    F("/var/log/auth.log", s_auth_log, "-rw-r-----", "root", "adm", 0, "Oct  4 06:55"),
    F("/var/log/syslog", s_syslog, "-rw-r-----", "root", "adm", 0, "Oct  1 09:00"),
    F("/root/.bash_history", s_bash_history, "-rw-------", "root", "root", 0, "Oct  3 21:10"),
    F("/var/www/html/index.html", s_www_index, "-rw-r--r--", "www-data", "www-data", 0, "Oct  1 09:00"),
};

const size_t mp_linux419_fs_n = sizeof(mp_linux419_fs) / sizeof(mp_linux419_fs[0]);

/* ------------------------------------------ canned shell data (non-structural)
 * Structural commands (ls/cd/cat/pwd/...) and network commands are answered
 * by mp_linuxsh; these are the static outputs. Line endings are '\n', the
 * renderer converts to CRLF. */

static const mp_cmd_t s_extra_cmds[] = {
    { "ps",
      "  PID TTY          TIME CMD\n"
      "  998 pts/0    00:00:00 bash\n"
      " 1124 pts/0    00:00:00 ps\n" },
    { "ps aux",
      "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
      "root         1  0.0  0.1 168400 11200 ?        Ss   Oct01   0:01 /sbin/init\n"
      "root       412  0.0  0.1  72304  6200 ?        Ss   Oct01   0:00 /lib/systemd/systemd-journald\n"
      "root       520  0.0  0.0  38456  4100 ?        Ss   Oct01   0:00 /usr/sbin/sshd -D\n"
      "root       530  0.0  0.0  21544  2380 ?        Ss   Oct01   0:00 /usr/sbin/vsftpd\n"
      "root       541  0.0  0.0  14208  2136 ?        Ss   Oct01   0:00 /usr/sbin/inetd\n"
      "root       655  0.0  0.0  12400  2800 ?        Ss   Oct01   0:00 /usr/sbin/apache2 -k start\n"
      "www-data   656  0.0  0.0 1243800 7600 ?        S    Oct01   0:00 /usr/sbin/apache2 -k start\n"
      "root       998  0.0  0.0   8300  1900 pts/0    Ss   09:41   0:00 -bash\n" },
    { "ps -ef",
      "UID        PID  PPID  C STIME TTY          TIME CMD\n"
      "root         1     0  0 Oct01 ?        00:00:01 /sbin/init\n"
      "root       412     1  0 Oct01 ?        00:00:00 /lib/systemd/systemd-journald\n"
      "root       520     1  0 Oct01 ?        00:00:00 /usr/sbin/sshd -D\n"
      "root       530     1  0 Oct01 ?        00:00:00 /usr/sbin/vsftpd\n"
      "root       541     1  0 Oct01 ?        00:00:00 /usr/sbin/inetd\n"
      "root       655     1  0 Oct01 ?        00:00:00 /usr/sbin/apache2 -k start\n"
      "www-data   656   655  0 Oct01 ?        00:00:00 /usr/sbin/apache2 -k start\n" },
    { "df -h",
      "Filesystem      Size  Used Avail Use% Mounted on\n"
      "udev            969M     0  969M   0% /dev\n"
      "/dev/sda1        49G  6.2G   40G  14% /\n"
      "tmpfs           197M  1.1M  196M   1% /run\n" },
    { "df",
      "Filesystem     1K-blocks    Used Available Use% Mounted on\n"
      "udev              992236       0    992236   0% /dev\n"
      "/dev/sda1       50871296 6496256  41775104  14% /\n"
      "tmpfs             201328    1120    200208   1% /run\n" },
    { "free",
      "              total        used        free      shared  buff/cache   available\n"
      "Mem:        2013276      534688     1478032        9420      361240     1623588\n"
      "Swap:       1048572           0     1048572\n" },
    { "free -m",
      "              total        used        free      shared  buff/cache   available\n"
      "Mem:           1966         522        1443           9         352        1585\n"
      "Swap:          1023           0        1023\n" },
    { "uptime",
      " 09:42:11 up 2 days, 22:41,  1 user,  load average: 0.00, 0.01, 0.05\n" },
    { "w",
      " 09:42:11 up 2 days, 22:41,  1 user,  load average: 0.00, 0.01, 0.05\n"
      "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
      "root     pts/0    192.168.1.66     09:41    0.00s  0.02s  0.00s -bash\n" },
    { "ss -tlnp",
      "State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process\n"
      "LISTEN 0      128          0.0.0.0:21         0.0.0.0:*     users:((\"vsftpd\",pid=530,fd=3))\n"
      "LISTEN 0      128          0.0.0.0:22         0.0.0.0:*     users:((\"sshd\",pid=520,fd=3))\n"
      "LISTEN 0      128          0.0.0.0:23         0.0.0.0:*     users:((\"inetd\",pid=541,fd=4))\n"
      "LISTEN 0      128          0.0.0.0:80         0.0.0.0:*     users:((\"apache2\",pid=655,fd=4))\n" },
    { "netstat -tlnp",
      "Active Internet connections (only servers)\n"
      "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\n"
      "tcp        0      0 0.0.0.0:21              0.0.0.0:*               LISTEN      530/vsftpd\n"
      "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      520/sshd\n"
      "tcp        0      0 0.0.0.0:23              0.0.0.0:*               LISTEN      541/inetd\n"
      "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      655/apache2\n" },
    { "env",
      "SHELL=/bin/bash\n"
      "USER=root\n"
      "HOME=/root\n"
      "PWD=/root\n"
      "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
      "TERM=xterm\n"
      "LANG=C.UTF-8\n"
      "SHLVL=1\n" },
    { "history",
      "    1  cd /var/log\n"
      "    2  tail -f auth.log\n"
      "    3  systemctl status apache2\n"
      "    4  vim /etc/ssh/sshd_config\n"
      "    5  systemctl restart sshd\n"
      "    6  passwd admin\n"
      "    7  top\n"
      "    8  exit\n" },
    { "last",
      "admin    pts/0        192.168.1.66     Sat Oct  4 02:31 - 02:47  (00:16)\n"
      "root     pts/1        192.168.1.66     Fri Oct  3 20:12 - 21:05  (00:53)\n"
      "reboot   system boot  4.19.0         Wed Oct  1 09:00 - 09:42 (2+00:41)\n"
      "\n"
      "wtmp begins Wed Oct  1 09:00:04 2026\n" },
    { "lsblk",
      "NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT\n"
      "sda      8:0    0   50G  0 disk\n"
      "|-sda1   8:1    0   49G  0 part /\n"
      "`-sda2   8:2    0    1G  0 part [SWAP]\n" },
    { "lscpu",
      "Architecture:        x86_64\n"
      "CPU op-mode(s):      32-bit, 64-bit\n"
      "CPU(s):              2\n"
      "Thread(s) per core:  1\n"
      "Core(s) per socket:  2\n"
      "Model name:          Intel(R) Xeon(R) Gold 6152 CPU @ 2.10GHz\n"
      "CPU MHz:             2095.078\n"
      "L1d cache:           32K\n"
      "L2 cache:            1024K\n"
      "L3 cache:            30976K\n" },
    { "mount",
      "sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)\n"
      "proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)\n"
      "udev on /dev type devtmpfs (rw,nosuid,relatime,size=992236k,nr_inodes=248059,mode=755)\n"
      "/dev/sda1 on / type ext4 (rw,relatime,errors=remount-ro,data=ordered)\n"
      "tmpfs on /run type tmpfs (rw,nosuid,noexec,relatime,size=201328k,mode=755)\n" },
    { "dmesg",
      "[    0.000000] Linux version 4.19.0 (gcc version 8.3.0 (GCC)) #1 SMP x86_64 GNU/Linux\n"
      "[    0.000000] Command line: BOOT_IMAGE=/boot/vmlinuz-4.19.0 root=/dev/sda1 ro quiet\n"
      "[    0.412208] x86/fpu: Supporting XSAVE feature 0x001: 'x87 floating point registers'\n"
      "[    1.204331] EXT4-fs (sda1): mounted filesystem with ordered data mode. Opts: (null)\n"
      "[    2.884120] IPv6: ADDRCONF(NETDEV_UP): eth0: link is not ready\n"
      "[    3.012455] e1000: eth0 NIC Link is Up 1000 Mbps Full Duplex, Flow Control: RX\n" },
    { "top",
      "top - 09:42:11 up 2 days, 22:41,  1 user,  load average: 0.00, 0.01, 0.05\n"
      "Tasks:  89 total,   1 running,  88 sleeping,   0 stopped,   0 zombie\n"
      "%Cpu(s):  0.2 us,  0.1 sy,  0.0 ni, 99.7 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st\n"
      "MiB Mem :   1966.1 total,   1443.4 free,    522.2 used,    352.7 buff/cache\n"
      "\n"
      "  PID USER      PR  NI    VIRT    RES    SHR S  %CPU %MEM     TIME+ COMMAND\n"
      "    1 root      20   0  168400  11200   8300 S   0.0  0.6   0:01.12 systemd\n"
      "  520 root      20   0   38456   4100   3400 S   0.0  0.2   0:00.31 sshd\n"
      "  655 root      20   0   12400   2800   2100 S   0.0  0.1   0:00.18 apache2\n" },
};


const mp_linuxsh_config_t mp_linux419_shell_cfg = {
    .hostname = "linux",
    .kernel_release = "4.19.0",
    .kernel_version = "#1 SMP",
    .machine = "x86_64",
    .fs = mp_linux419_fs,
    .fs_n = sizeof(mp_linux419_fs) / sizeof(mp_linux419_fs[0]),
    .extra_cmds = s_extra_cmds,
    .n_extra = sizeof(s_extra_cmds) / sizeof(s_extra_cmds[0]),
};
