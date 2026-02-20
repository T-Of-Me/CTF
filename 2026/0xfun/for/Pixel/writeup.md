# Pixel - Forensics

## Challenge

> Our design intern "repaired" a broken image and handed us the result, claiming the important part is still in there.
>
> All we know is the original came from a compressed archive, and something about the recovery feels suspicious.

We are given a single file: `pixel.fun`.

## Solution

### Step 1: Identify the File

The file looks like a PNG but the first byte is `88` instead of `89` — a corrupted PNG header:

```
00000000: 8850 4e47 0d0a 1a0a ...  (should be 89 50 4e 47)
```

### Step 2: Find Hidden Data After IEND

After the PNG `IEND` chunk at `0x9b37a`, there are **1188 bytes** of trailing data. The first 6 bytes of this trailing data are `89 50 4E 47 0D 0A` — another PNG signature. But the rest of the structure (especially the UTF-16LE filename `real_flag.png` near the end) reveals this is actually a **7z archive** with its signature overwritten.

```python
data = open('pixel.fun', 'rb').read()
iend_pos = data.find(b'IEND')
trailing = data[iend_pos + 8:]
# First 6 bytes: 89 50 4E 47 0D 0A (fake PNG sig)
# Real 7z sig:   37 7A BC AF 27 1C
```

### Step 3: Restore 7z Header and Extract

Replace the fake PNG signature with the real 7z magic bytes and extract the archive:

```python
import py7zr, io

data = open('pixel.fun', 'rb').read()
iend_pos = data.find(b'IEND')
trailing = data[iend_pos + 8:]

fixed_7z = b'\x37\x7a\xbc\xaf\x27\x1c' + trailing[6:]

with py7zr.SevenZipFile(io.BytesIO(fixed_7z), mode='r') as archive:
    archive.extractall()
```

This extracts `real_flag.png` — a WebP image containing a QR code with the flag printed at the bottom.

## Flag

```
0xfun{FuN_PN9_f1le_7z}
```

> "Fun PNG file 7z"
