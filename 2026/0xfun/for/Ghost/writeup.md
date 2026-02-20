# Ghost - Forensics

## Challenge

> The interception of a transmission has occurred, with only a network capture remaining. Recover the flag before the trail goes cold.

We are given a single file: `wallpaper.png`.

## Solution

### Step 1: Hidden Data After PNG IEND

Inspecting the file reveals extra data appended after the PNG `IEND` chunk. The magic bytes `7z\xbc\xaf'\x1c` indicate a **7z archive**:

```python
data = open('wallpaper.png', 'rb').read()
iend = data.find(b'IEND')
archive = data[iend+8:]
open('hidden.7z', 'wb').write(archive)
```

### Step 2: Read the Password From the Image

The archive is password-protected. Opening the PNG reveals leet-speak text in the top-left corner:

```
1n73rc3p7_c0nf1rm3d
```

This translates to `intercept_confirmed` — the password.

### Step 3: Extract the Archive

```python
import py7zr

with py7zr.SevenZipFile('hidden.7z', 'r', password='1n73rc3p7_c0nf1rm3d') as z:
    z.extractall()
```

This extracts `fishwithwater/nothing.txt` containing the flag.

## Flag

```
0xfun{l4y3r_pr0t3c710n_k3y}
```

> "layer protection key"
