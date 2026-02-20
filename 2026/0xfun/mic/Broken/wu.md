# Broken - 0xfun CTF 2026 (Misc)

## Flag
`0xfun{br0k3n_qr_r3c0v3rd}`

## Challenge
Given an image `secret_id.png` - a damaged ID card containing two broken QR codes:
- **Top-right QR**: top-right corner torn off (missing finder pattern)
- **Bottom-right QR**: skull overlaid on center area

## Solution

### 1. Analyze the image
The ID card has two QR codes. The top-right QR is more promising since only one finder pattern is missing while most data modules are intact.

### 2. Locate finder patterns
Using pixel analysis on the grayscale image, I found two intact finder patterns of the top QR:
- **Top-left finder**: center at `(1280, 119)` with the classic `B(10) W(9) B(28) W(9) B(10)` signature (ratio 1:1:3:1:1)
- **Bottom-left finder**: center at `(1280, 289)` with the same signature

### 3. Determine QR parameters
- Distance between finder centers: `289 - 119 = 170px`
- For a standard QR, finder centers are separated by `(N - 7)` modules where N = QR size
- Module size: `66 / 7 = 9.44px`
- QR size: `170 / 9.44 + 7 = 25` modules -> **QR Version 2 (25x25)**

### 4. Extract module grid
Sampled the center of each module from the grayscale image:
- Pixel value `< 100` -> black module
- Pixel value `> 180` -> white module
- Otherwise -> unknown (damaged by torn paper)

Result: **54 unknown modules** out of 625 total (~8.6%), all in the top-right corner.

### 5. Reconstruct missing structure
Manually filled in known QR structural elements:
- **Top-right finder pattern** (7x7)
- **Separators** around all three finder patterns
- **Timing patterns** (row 6 and column 6)
- **Alignment pattern** at position (18, 18) for Version 2
- **Dark module** at (17, 8)

After reconstruction, only **4 unknown data modules** remained.

### 6. Decode
QR error correction handled the remaining unknowns. OpenCV's `QRCodeDetector` decoded the reconstructed QR successfully.

```python
import cv2
detector = cv2.QRCodeDetector()
data, _, _ = detector.detectAndDecode(reconstructed_qr)
# '0xfun{br0k3n_qr_r3c0v3rd}'
```
