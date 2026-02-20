# DTMF - Forensics

## Flag
`0xfun{Mu1t1_t4p_plu5_dtmf}`

## Overview
A WAV file containing DTMF (Dual-Tone Multi-Frequency) signals encoding a multi-layered message. The challenge involves decoding audio signals, then peeling through encoding layers, and finally finding a hidden Vigenere key in the file's metadata.

## Solution

### Step 1: Analyze the WAV file
The file `message.wav` is a mono 8kHz WAV, 50.4 seconds long, containing 288 DTMF tone bursts. Each tone is 100ms with either a 40ms gap (within a byte) or a 240ms gap (between bytes).

### Step 2: DTMF decoding
Each tone corresponds to either key `0` (frequencies 941 Hz + 1336 Hz) or key `1` (frequencies 697 Hz + 1209 Hz). Decoding all 288 tones yields a binary string:

```
01001101 01001000 01001010 01110100 01011010 00110010 ...
```

### Step 3: Binary to ASCII
Converting the 288 bits (36 bytes) to ASCII:

```
MHJtZ2p7VHUxbTFfYjRoX2lzYzVfdm50cn0=
```

### Step 4: Base64 decode
```
MHJtZ2p7VHUxbTFfYjRoX2lzYzVfdm50cn0=  -->  0rmgj{Tu1m1_b4h_isc5_vntr}
```

This looks like a flag but with scrambled letters. The prefix `0rmgj` should be `0xfun`.

### Step 5: Find the hidden key
Inspecting the WAV file's RIFF chunks reveals a `LIST/INFO` metadata chunk containing a comment:

```
ICMT: uhmwhatisthis
```

This is the Vigenere cipher key.

### Step 6: Vigenere decrypt
Applying Vigenere decryption with key `uhmwhatisthis` (only shifting alphabetic characters, preserving digits and symbols):

```
Cipher: 0rmgj{Tu1m1_b4h_isc5_vntr}
Key:    uhmwhatisthis (cycling over letters only)
Plain:  0xfun{Mu1t1_t4p_plu5_dtmf}
```

## Script
```python
import wave, numpy as np, base64, struct

# --- DTMF Decode ---
w = wave.open('message.wav', 'r')
rate = w.getframerate()
data = np.frombuffer(w.readframes(w.getnframes()), dtype=np.int16)
w.close()

DTMF = {
    (697, 1209): '1', (697, 1336): '2', (697, 1477): '3',
    (770, 1209): '4', (770, 1336): '5', (770, 1477): '6',
    (852, 1209): '7', (852, 1336): '8', (852, 1477): '9',
    (941, 1209): '*', (941, 1336): '0', (941, 1477): '#',
}
LOW = [697, 770, 852, 941]
HIGH = [1209, 1336, 1477]

# Segment detection
win = int(rate * 0.01)
segments = []
in_tone = False
for i in range(0, len(data) - win, win):
    amp = np.max(np.abs(data[i:i+win]))
    if amp > 500 and not in_tone:
        tone_start = i / rate
        in_tone = True
    elif amp <= 500 and in_tone:
        segments.append((tone_start, i / rate))
        in_tone = False

# Decode each tone
bits = ''
for s, e in segments:
    mid = int((s + e) / 2 * rate)
    chunk = data[mid-200:mid+200].astype(float)
    fft = np.fft.rfft(chunk)
    freqs = np.fft.rfftfreq(len(chunk), 1.0/rate)
    mags = np.abs(fft)
    bl = max(LOW, key=lambda f: mags[np.argmin(np.abs(freqs - f))])
    bh = max(HIGH, key=lambda f: mags[np.argmin(np.abs(freqs - f))])
    bits += DTMF.get((bl, bh), '?')

# --- Binary -> ASCII -> Base64 ---
ascii_text = ''.join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8))
cipher = base64.b64decode(ascii_text).decode()

# --- Extract key from WAV metadata ---
with open('message.wav', 'rb') as f:
    raw = f.read()
idx = raw.find(b'ICMT')
key_len = struct.unpack('<I', raw[idx+4:idx+8])[0]
key = raw[idx+8:idx+8+key_len].rstrip(b'\x00').decode()

# --- Vigenere decrypt ---
result, ki = [], 0
for c in cipher:
    if c.isalpha():
        base = ord('A') if c.isupper() else ord('a')
        k = ord(key[ki % len(key)].lower()) - ord('a')
        result.append(chr((ord(c) - base - k) % 26 + base))
        ki += 1
    else:
        result.append(c)

print(''.join(result))  # 0xfun{Mu1t1_t4p_plu5_dtmf}
```
