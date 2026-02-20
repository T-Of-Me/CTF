# Drums - Forensics

## Challenge

> A kid taps out 1337 drums, thinking it's nothing more than a noisy rhythm. Observers notice the pattern matches a strange signal they've been monitoring for weeks. What began as play suddenly becomes the key to a mystery none of them expected.

We are given a single file: `Melodie.wav`.

## Solution

### Step 1: Identify the Signal

Opening `Melodie.wav` and viewing its spectrogram reveals frequencies concentrated in the 1200-2300 Hz band — the characteristic range of an **SSTV (Slow Scan Television)** signal.

```
Duration: 111.34s | Sample rate: 44100 Hz | 16-bit mono
```

### Step 2: Decode the SSTV Image (Red Herring)

Using the `sstv` Python library to decode the audio:

```bash
python3 -m sstv -d Melodie.wav -o output.png
```

The decoder detects **Scottie 1** mode (VIS code 60) and produces a 320x256 image of a cartoon character with a speech bubble saying:

> **"SEEMS LIKE A DEADEND"**

This is a red herring to distract from the real flag.

### Step 3: LSB Steganography in the WAV

The hint "1337 drums" and the trolling SSTV image suggest there's a second layer of encoding. The SSTV signal acts as a **cover** for data hidden in the **least significant bits** of the audio samples.

Using `stego_lsb` to extract 2-LSB data from the WAV file:

```python
from stego_lsb.WavSteg import recover_data

recover_data('Melodie.wav', 'recovered.bin', num_lsb=2, bytes_to_recover=10000)
```

The extracted data immediately reveals the flag at offset 0.

## Flag

```
0xfun{8f2b5c9d4f6a1eab3e0c4df52b79d8c1}
```
