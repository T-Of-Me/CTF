# Tesla - Forensics

## Challenge

We are given a Flipper Zero `.sub` file named `Tesla.sub`.

## Solution

### Step 1: Decode Binary to ASCII

The `RAW_Data` field contains space-separated 8-bit binary values. Converting each group to ASCII reveals an **obfuscated Windows batch script**:

```batch
@cls
@set "Ilc=pesbMUQl73oWnqD9rAvFRKZaf0hO5@dBN4uSzCtGjE YxITwXiVm1Jcgy26LkH8P"
%Ilc:~29,1%%Ilc:~1,1%%Ilc:~54,1%...
```

### Step 2: Deobfuscate the Batch Script

The script uses a **character substitution table** with the CMD syntax `%var:~N,1%` to extract one character at a time by index from the table:

```
Index: 0  1  2  3  4  5  6  7  8  9  10 11 12 ...
Char:  p  e  s  b  M  U  Q  l  7  3  o  W  n  ...
```

Resolving all substitutions reveals:

```batch
@echo off
powershell -NoProfile -Command "[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('i could be something to this'))"
:: 5958051a1b170013520746265a0e51435b36165752470b7f03591d1b364b501608616e ::
:: ive been encrypted many in ways ::
pause
```

### Step 3: XOR Decryption

The comments contain:
- A **hex-encoded ciphertext**: `5958051a1b170013520746265a0e51435b36165752470b7f03591d1b364b501608616e`
- A hint: `"i could be something to this"` — this is the **XOR key**
- Another hint: `"ive been encrypted many in ways"`

XORing the ciphertext with the repeating key `"i could be something to this"`:

```python
hex_str = '5958051a1b170013520746265a0e51435b36165752470b7f03591d1b364b501608616e'
data = bytes.fromhex(hex_str)
key = 'i could be something to this'

flag = ''
for i, b in enumerate(data):
    flag += chr(b ^ ord(key[i % len(key)]))
print(flag)
```

## Flag

```
0xfun{d30bfU5c473_x0r3d_w1th_k3y}
```

> "deobfuscate xored with key"
