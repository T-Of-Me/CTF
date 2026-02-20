# Emoji's - 0xfun CTF 2026 (Misc)

## Flag
`0xfun{3moji_s3cr3t_emb3d_1n_t1tle}`

## Challenge
A folder named `Emoji's` containing a file `emoji.txt` with a sequence of emojis. The flag is hidden somewhere in the challenge files.

## Solution

### 1. Notice suspicious folder name
The folder name `Emoji's` appears normal, but inspecting its byte content reveals **34 invisible Unicode characters** embedded between the `o` and `j`:

```
E m o [34 hidden chars] j i ' s
```

### 2. Identify the hidden characters
Using UTF-32 hex dump of the folder name, the hidden codepoints are in the **Supplementary Private Use Area-B** (U+E0100+):

```
U+E0120, U+E0168, U+E0156, U+E0165, U+E015E, U+E016B, ...
```

These resemble **Unicode Tag Characters** (normally U+E0020-U+E007E) but shifted up by `0x100`.

### 3. Decode with offset
Extracting the low byte of each codepoint gives ASCII-like values, but shifted by `-0x10` from the real message. Adding `0x10` back to each byte reveals the flag:

```python
tag_low_bytes = [0x20, 0x68, 0x56, 0x65, 0x5E, 0x6B, 0x23, 0x5D,
                 0x5F, 0x5A, 0x59, 0x4F, 0x63, 0x23, 0x53, 0x62,
                 0x23, 0x64, 0x4F, 0x55, 0x5D, 0x52, 0x23, 0x54,
                 0x4F, 0x21, 0x5E, 0x4F, 0x64, 0x21, 0x64, 0x5C,
                 0x55, 0x6D]

flag = ''.join(chr(b + 0x10) for b in tag_low_bytes)
# '0xfun{3moji_s3cr3t_emb3d_1n_t1tle}'
```

## Key Takeaways
- **Unicode Tag Characters** (U+E0001-U+E007F) are zero-width invisible characters originally designed for language tagging, commonly abused for steganography
- The challenge added an extra `0x100` offset to the codepoints as a twist, so a naive tag-character decoder wouldn't work directly
- The flag was hidden in the **folder name** itself - "embedded in title"
