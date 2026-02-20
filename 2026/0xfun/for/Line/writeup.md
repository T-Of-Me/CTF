# Line - Forensics

## Challenge

> You're aboard a deep-space relay station when an incoming capture hits your buffer: a mono audio recording labeled "0xfun".
>
> The analysts insist it's alien. But the encoding style feels... familiar. Like something humanity would send when it wanted to be understood without sharing a language.
>
> Dig into the signal, recover what it's really carrying, and extract the flag.

We are given two files: `record.wav` (mono 16-bit PCM, 48kHz, ~11.6s) and `cover.png`.

## Solution

### Step 1: Analyze the Cover Image

The cover image shows a vinyl record titled **"THE NOT-RANDOM RECORD"** with track listing:

- **SIDE A:** 01. STATIC, 02. SIGNAL, 03. CALIBRATION
- **SIDE B:** 01. NOISE, 02. ORDER

The description hints at the **Voyager Golden Record** — humanity's famous attempt to communicate with extraterrestrials by encoding images as audio signals.

### Step 2: Understand the Encoding

The Voyager Golden Record encoded images directly into audio: each sample's amplitude represents a pixel brightness value, and the image is reconstructed by wrapping the samples into rows of a fixed width (scan line length).

The key is finding the correct **line width**. The audio contains tones with a fundamental frequency of ~125 Hz. At 48kHz sample rate, one period = `48000 / 125 = 384` samples.

### Step 3: Render the Image

Normalize the raw 16-bit samples to 0-255 grayscale and reshape with width **384**:

```python
import numpy as np
import wave
import struct
from PIL import Image

w = wave.open('record.wav', 'rb')
frames = w.readframes(w.getnframes())
samples = np.array(struct.unpack('<' + 'h' * w.getnframes(), frames), dtype=np.float64)
w.close()

width = 384
h = len(samples) // width
usable = h * width

norm = ((samples[:usable] - samples.min()) / (samples.max() - samples.min()) * 255).astype(np.uint8)
img = Image.fromarray(norm.reshape(h, width))
img.save('decoded.png')
```

This produces a **1449x384** grayscale image revealing the 5 track sections described on the cover — including visible text with the flag: **"golden record is not random"**.

## Flag

```
0xfun{g0ld3n_r3c0rd_1s_n0t_r4nd0m}
```

> "Golden record is not random"
