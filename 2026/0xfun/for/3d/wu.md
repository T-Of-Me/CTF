# 3D - GCode Forensics

## Challenge

- **Category**: Forensics
- **File**: `3D.gcode`
- **Flag**: `0xfun{this_monkey_has_a_flag}`

## Phân tích

Được cung cấp file `3D.gcode` — file G-code dùng cho máy in 3D, sinh bởi **Cura_SteamEngine 5.10.2** cho máy **Ultimaker S5**.

Mở file thấy header chuẩn của Cura với 773 layer, nhưng điều quan trọng là bên trong chứa nhiều mesh khác nhau, trong đó có một mesh tên `flag.stl`.

```
;MESH:flag.stl
```

## Giải

### Bước 1: Trích xuất tọa độ của flag.stl

Viết script Python parse file GCode, chỉ lấy các lệnh `G1` (di chuyển có extrusion) nằm trong vùng `MESH:flag.stl`, trích xuất tọa độ X, Y:

```python
import re
import matplotlib.pyplot as plt

xs, ys = [], []
in_flag = False

with open("3D.gcode", "r") as f:
    for line in f:
        line = line.strip()
        if ";MESH:flag.stl" in line:
            in_flag = True
            continue
        if ";MESH:" in line and "flag.stl" not in line:
            in_flag = False
            continue
        if in_flag and line.startswith("G1"):
            xm = re.search(r'X([\d.]+)', line)
            ym = re.search(r'Y([\d.]+)', line)
            if xm and ym:
                xs.append(float(xm.group(1)))
                ys.append(float(ym.group(1)))

plt.figure(figsize=(20, 6))
plt.scatter(xs, ys, s=0.1, c='black')
plt.axis('equal')
plt.title('flag.stl top-down view')
plt.savefig('flag_plot.png', dpi=200)
plt.show()
```

### Bước 2: Nhìn từ trên xuống (XY) — chưa rõ

Plot top-down (XY) cho ra hình nhưng chữ bị chồng chất nhiều layer lên nhau, khó đọc. Thử lọc theo từng layer cụ thể thì thấy được các ký tự nhưng bị **ngược/lật**.

### Bước 3: Nhìn từ mặt trước (XZ) — đọc được flag

Thay vì nhìn từ trên xuống, plot theo mặt phẳng **XZ** (front view) — dùng tọa độ X và Z:

Khi đó, text hiện rõ trên mặt phẳng XZ với 3 dòng chữ xếp chéo:

```
0xfun{this
_monkey
_has_a_flag}
```

Ghép lại: `0xfun{this_monkey_has_a_flag}`

## Flag

```
0xfun{this_monkey_has_a_flag}
```
