# Nothing Expected - Excalidraw Forensics

## Challenge

- **Category**: Forensics
- **File**: `file.png`, `scene.excalidraw`
- **Flag**: `0xfun{th3_sw0rd_0f_k1ng_4rthur}`

## Phân tích

Được cung cấp file `file.png` — hình một nhân vật bí ẩn đội mũ, đeo kính đen với dòng chữ *"nothing to see here, move along"*, gợi ý rằng flag được giấu ở nơi khác.

Kèm theo là file `scene.excalidraw` — định dạng JSON của công cụ vẽ [Excalidraw](https://excalidraw.com).

## Giải

### Bước 1: Kiểm tra file Excalidraw

Mở file `scene.excalidraw` bằng text editor, thấy đây là file JSON chứa metadata của một bản vẽ Excalidraw. Bên trong có một element kiểu `text` với nội dung:

```json
"text": "shh, this is a secret!!"
```

Đây là gợi ý rằng bản vẽ chứa nội dung bí mật.

### Bước 2: Mở bằng Excalidraw

Import file `scene.excalidraw` vào [excalidraw.com](https://excalidraw.com). Bản vẽ hiển thị flag được viết tay trực tiếp trên canvas cùng với dòng chữ đỏ *"shh, this is a secret!!"* và một mũi tên.

Nội dung vẽ tay chính là flag:

```
0xfun{th3_sw0rd_0f_k1ng_4rthur}
```

Kết quả cũng được xác nhận qua file `hidden_drawing.png` — ảnh render của bản vẽ Excalidraw, hiển thị rõ flag.

## Flag

```
0xfun{th3_sw0rd_0f_k1ng_4rthur}
```
