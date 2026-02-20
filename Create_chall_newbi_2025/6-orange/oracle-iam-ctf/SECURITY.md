# Security Hardening - CVE-2025-61757 CTF Challenge

## Non-Root User Configuration

### Docker User Setup

```dockerfile
# Create non-root user
RUN useradd -m -u 1000 -s /bin/bash oim

# Run as non-root
USER oim
```

**Why This Matters:**
- ✅ Container escapes are limited
- ✅ Host system protection
- ✅ CTF best practice
- ✅ Realistic security posture

### Verification

```bash
# After RCE, check user
$ whoami
oim

$ id
uid=1000(oim) gid=1000(oim) groups=1000(oim)

# NOT root anymore!
```

## Flag Protection

### File Permissions

```dockerfile
RUN echo "FLAG{...}" > /flag.txt && \
    chown oim:oim /flag.txt && \
    chmod 400 /flag.txt
```

**Permission Breakdown:**
- `400` = `-r--------` (read-only for owner)
- Owner: `oim` user only
- Cannot be modified or deleted by oim user
- Only readable by the app user

### Test Flag Access

```bash
# Can read
$ cat /flag.txt
FLAG{CVE_2025_61757_0r4cl3_1d3nt1ty_pwn3d}

# Cannot write
$ echo "hacked" > /flag.txt
bash: /flag.txt: Permission denied

# Cannot delete
$ rm /flag.txt
rm: cannot remove '/flag.txt': Permission denied

# Cannot change permissions
$ chmod 777 /flag.txt
chmod: changing permissions of '/flag.txt': Operation not permitted
```

## Docker Security Options

### Capabilities

```yaml
cap_drop:
  - ALL              # Drop all Linux capabilities
cap_add:
  - NET_BIND_SERVICE # Only allow binding to ports
```

**Dropped Capabilities:**
- `CAP_SYS_ADMIN` - No system administration
- `CAP_SYS_PTRACE` - No process tracing
- `CAP_NET_RAW` - No raw sockets
- `CAP_SYS_MODULE` - No kernel module loading
- And 40+ other dangerous capabilities

### Security Options

```yaml
security_opt:
  - no-new-privileges:true
```

**Effect:**
- Prevents privilege escalation
- No setuid binaries can gain privileges
- No sudo/su elevation possible

### User Enforcement

```yaml
user: "1000:1000"
```

**Guarantee:**
- Forces container to run as UID 1000
- Even if Dockerfile is modified
- Double protection layer

## What Attackers CANNOT Do

After successful RCE exploitation:

❌ **Cannot escalate to root**
```bash
$ sudo su
sudo: command not found

$ su root
su: must be run from a terminal
```

❌ **Cannot modify flag**
```bash
$ echo "fake" > /flag.txt
Permission denied
```

❌ **Cannot access host system**
```bash
$ ls /host
ls: cannot access '/host': No such file or directory
```

❌ **Cannot install packages**
```bash
$ apt-get install vim
E: Could not open lock file - open (13: Permission denied)
```

❌ **Cannot escape container**
```bash
$ docker ps
bash: docker: command not found
```

## What Attackers CAN Do (Intended)

✅ **Read the flag** (goal of challenge)
```bash
$ cat /flag.txt
FLAG{CVE_2025_61757_0r4cl3_1d3nt1ty_pwn3d}
```

✅ **Execute basic commands**
```bash
$ whoami
oim

$ pwd
/app

$ ls -la
total 24
drwxr-xr-x 1 oim oim 4096 Nov 25 12:00 .
drwxr-xr-x 1 root root 4096 Nov 25 12:00 ..
-rw-r--r-- 1 oim oim 8432 Nov 25 12:00 app.py
```

✅ **Read environment variables**
```bash
$ env | grep FLAG
FLAG=FLAG{CVE_2025_61757_0r4cl3_1d3nt1ty_pwn3d}
```

## Security Comparison

### Before (Insecure)
```dockerfile
# Running as root
CMD ["python", "app.py"]
```

```bash
# After RCE
$ whoami
root

$ rm -rf /
# Could destroy entire container
```

### After (Secure)
```dockerfile
USER oim
CMD ["python", "app.py"]
```

```bash
# After RCE
$ whoami
oim

$ rm -rf /
rm: cannot remove '/bin': Permission denied
```

## CTF Best Practices

### 1. Principle of Least Privilege
- Container runs with minimum required permissions
- User can only do what's needed for the challenge

### 2. Defense in Depth
- Multiple security layers:
  1. Non-root user (Dockerfile)
  2. Dropped capabilities (docker-compose)
  3. No new privileges flag
  4. User enforcement

### 3. Realistic Simulation
- Real-world servers don't run as root
- Teaches proper exploitation techniques
- Mirrors actual security controls

### 4. Safe for Hosting
- Container escape is extremely difficult
- Host system is protected
- Can be safely deployed on shared infrastructure

## Testing Security

### Build and Test
```bash
# Rebuild with security
docker-compose down
docker-compose build --no-cache
docker-compose up -d

# Exploit
python3 exploit.py http://localhost:14000 --shell

# Verify non-root
$ id
uid=1000(oim) gid=1000(oim) groups=1000(oim)

# Try privilege escalation (should fail)
$ sudo su
sudo: command not found

# Verify flag is readable
$ cat /flag.txt
FLAG{CVE_2025_61757_0r4cl3_1d3nt1ty_pwn3d}

# Verify flag cannot be modified
$ echo "pwned" > /flag.txt
bash: /flag.txt: Permission denied
```

## Additional Hardening (Optional)

### Read-Only Root Filesystem
```yaml
read_only: true
tmpfs:
  - /tmp
  - /app/__pycache__
```

### Resource Limits
```yaml
deploy:
  resources:
    limits:
      cpus: '0.5'
      memory: 512M
```

### Network Isolation
```yaml
networks:
  ctf-network:
    driver: bridge
    internal: true  # No internet access
```

## References

- **Docker Security Best Practices**: https://docs.docker.com/engine/security/
- **Linux Capabilities**: https://man7.org/linux/man-pages/man7/capabilities.7.html
- **CTF Challenge Design**: OWASP Testing Guide
- **Principle of Least Privilege**: NIST SP 800-53

## Conclusion

Security hardening ensures:
1. ✅ Challenge is safe to host
2. ✅ Realistic security posture
3. ✅ Educational value (shows real-world controls)
4. ✅ CTF organizer protection
5. ✅ Fair challenge (no unintended privilege escalation)

Players must exploit the **intended vulnerability** (CVE-2025-61757) without relying on container misconfigurations.
