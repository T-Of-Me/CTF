# Meow Transmission — BITSCTF 2026

**Category:** Steganography / Crypto
**Points:** 50
**Solves:** 160
**Flag:** `BITSCTF{4rn0ld5_c4t_m4ps_4r3_p3r10d1c}`

---

## Đề bài

> Our surveillance team intercepted a seemingly innocent cat photo being transmitted between two suspected agents. The metadata contains some strange ramblings about cats and dancing...
> We believe there's hidden information in this image, but standard tools haven't revealed anything useful. Can you uncover their secret?

File: `transmission.png` — ảnh grayscale 128×128

---

## Phân tích

### Bước 1: Đọc metadata PNG

```bash
python3 -c "
from PIL import Image
img = Image.open('transmission.png')
for k, v in img.info.items():
    print(f'{k}: {v}')
"
```

Metadata `Comment` chứa hint rõ ràng:

```
Meow! I'm a cat who loves to transform.
My journey involves 3 leaps through chaos.
At each leap, I choose my style: [1, 2, 1]
I spin [47, 37, 29] times at each stop.
Each dance has its own rhythm: [96, 64, 96] spins to complete.
The sequence of my adventure: [1, 2, 3]
My world is 128x128 pixels wide.

Perhaps a certain Russian mathematician knows my secret?

Author: Mr. Arnold Cat
```

→ **Arnold Cat Map** (Vladimir Arnold) được áp dụng 3 lần với các tham số khác nhau.

### Bước 2: Phát hiện LSB Steganography

Kiểm tra phân phối pixel values:

```python
import numpy as np
from PIL import Image

img = np.array(Image.open('transmission.png'))
unique = np.unique(img)
print(unique)
# [ 32  40  47  48  55  56  63  64  71  72 ... 231 232]
# Tất cả đều là bội số của 8, hoặc (bội số của 8 - 1)

lsb3 = img & 0x07
print(np.unique(lsb3))  # [0 7]
# Lower 3 bits CHỈ có giá trị 0 hoặc 7
```

**Key insight:** 341/16384 pixels có `lower_3_bits = 7` (binary `111`), còn lại là `0`.
→ Flag được giấu trong **LSB** của các pixel, scramble bởi Arnold Cat Map.

### Bước 3: Tìm hiểu Arnold Cat Map

**Generalized Arnold Cat Map (row-major convention):**

```
new_row = (row + a × col) % N
new_col = (b × row + (a×b + 1) × col) % N
```

**Các tham số từ metadata:**

| Step | Style | a | b | Spins | Period |
|------|-------|---|---|-------|--------|
| 1    | 1     | 1 | 1 | 47    | 96     |
| 2    | 2     | 2 | 1 | 37    | 64     |
| 3    | 1     | 1 | 1 | 29    | 96     |

Verify periods:
- `style=1` (a=1, b=1), N=128 → period = **96** ✓
- `style=2` (a=2, b=1), N=128 → period = **64** ✓

### Bước 4: Decode Arnold Cat Map

Để đảo ngược: áp dụng forward map thêm `(period - spins)` lần, theo thứ tự **ngược lại**:

- Undo step 3: style=1, `96 - 29 = 67` lần
- Undo step 2: style=2, `64 - 37 = 27` lần
- Undo step 1: style=1, `96 - 47 = 49` lần

```python
import numpy as np
from PIL import Image

img = np.array(Image.open('transmission.png'))
N = 128

# Trích xuất binary LSB image
binary = (img & 1).astype(np.uint8)

def arnold_B(img, a, b, n_iters, N):
    """Arnold Cat Map - row-major convention"""
    r = img.copy()
    row, col = np.mgrid[0:N, 0:N]
    new_row = (row + a * col) % N
    new_col = (b * row + (a*b + 1) * col) % N
    for _ in range(n_iters):
        nr = np.zeros_like(r)
        nr[new_row, new_col] = r[row, col]
        r = nr
    return r

result = arnold_B(binary, 1, 1, 96-29, N)   # undo step 3: 67 iters
result = arnold_B(result, 2, 1, 64-37, N)   # undo step 2: 27 iters
result = arnold_B(result, 1, 1, 96-47, N)   # undo step 1: 49 iters

# Lưu kết quả (nhân 255 để hiển thị)
from PIL import Image
Image.fromarray(result * 255).resize((512, 512), Image.NEAREST).save('flag.png')
```

### Bước 5: Đọc flag

Sau khi decode, 341 pixels trắng tạo thành **pixel-art text** hiển thị rõ ràng:

```
BITSCTF{4rn0ld5_c4t_m4ps_4r3_p3r10d1c}
```

![Flag decoded](flag_8x.png)

---

## Giải mã leet speak

`4rn0ld5_c4t_m4ps_4r3_p3r10d1c`
→ **Arnold's cat maps are periodic**

Đây là tính chất nổi tiếng của Arnold Cat Map: với bất kỳ kích thước ảnh N×N nào, ảnh sẽ trở về trạng thái ban đầu sau một số hữu hạn lần áp dụng (chu kỳ). Điều này được xác nhận bởi chính metadata:
- Style 1 (a=1, b=1) với N=128 có **period = 96**
- Style 2 (a=2, b=1) với N=128 có **period = 64**

---

## Script giải hoàn chỉnh

```python
import numpy as np
from PIL import Image

def arnold_B(img, a, b, n_iters, N):
    r = img.copy()
    row, col = np.mgrid[0:N, 0:N]
    new_row = (row + a * col) % N
    new_col = (b * row + (a*b + 1) * col) % N
    for _ in range(n_iters):
        nr = np.zeros_like(r)
        nr[new_row, new_col] = r[row, col]
        r = nr
    return r

img = np.array(Image.open('transmission.png'))
N = 128

# Trích LSB
binary = (img & 1).astype(np.uint8)

# Decode ngược 3 bước Arnold Cat Map
result = arnold_B(binary, 1, 1, 96-29, N)  # undo step 3
result = arnold_B(result, 2, 1, 64-37, N)  # undo step 2
result = arnold_B(result, 1, 1, 96-47, N)  # undo step 1

# Hiển thị
Image.fromarray(result * 255).resize((512, 512), Image.NEAREST).save('flag.png')
print("Flag: BITSCTF{4rn0ld5_c4t_m4ps_4r3_p3r10d1c}")
```

---

## Flag

```
BITSCTF{4rn0ld5_c4t_m4ps_4r3_p3r10d1c}
```
