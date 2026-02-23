import os

def decode_zero_width_safely(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"[-] Không tìm thấy file {file_path}")
        return

    # Danh sách các ký tự Zero-width có trong chuỗi của bạn
    zw_chars = ['\u200b', '\u200c', '\u200d', '\u200e', '\u202c', '\u202d', '\u2062', '\u2063', '\ufeff']
    extracted = "".join([c for c in content if c in zw_chars])

    # Tách các khối dựa trên delimiter (\u200b\u200b\u200b)
    chunks = extracted.split('\u200b\u200b\u200b')
    print(f"[*] Đã tách được {len(chunks)} khối dữ liệu (bỏ qua các khối rỗng).")

    # ⚠️ TÙY CHỈNH MAPPING: 
    # Dưới đây là bảng ánh xạ nhị phân giả định. Nếu kết quả vẫn ra rác, 
    # bạn cần hoán đổi các giá trị '0', '1' hoặc thay đổi độ dài bit tùy theo tool giấu tin.
    mapping = {
        '\u200c': '000',
        '\u200d': '001',
        '\u202c': '010',
        '\u202d': '011',
        '\u2062': '100',
        '\u2063': '101',
        '\ufeff': '110',
        '\u200e': '111',
        '\u200b': '' # Bỏ qua các \u200b còn sót lại
    }

    raw_bytes = bytearray()

    for chunk in chunks:
        if not chunk: continue
        
        # Chuyển đổi khối Unicode thành chuỗi nhị phân
        binary_str = "".join([mapping.get(c, "") for c in chunk])
        
        # Ép nhị phân thành số nguyên (byte)
        if binary_str:
            try:
                byte_val = int(binary_str, 2)
                if byte_val < 256:
                    raw_bytes.append(byte_val)
            except ValueError:
                pass

    if not raw_bytes:
        print("[-] Không có dữ liệu byte nào được tạo ra. Hãy kiểm tra lại bảng mapping!")
        return

    # 1. In ra Hex Dump (Tuyệt đối an toàn cho Terminal)
    print("\n[*] Hex Dump của dữ liệu giải mã:")
    hex_output = raw_bytes.hex()
    formatted_hex = " ".join([hex_output[i:i+2] for i in range(0, len(hex_output), 2)])
    print(formatted_hex)

    # 2. In ra ASCII (Lọc các ký tự không hiển thị được)
    print("\n[*] Chuỗi ASCII an toàn:")
    safe_ascii = "".join([chr(b) if 32 <= b <= 126 else '.' for b in raw_bytes])
    print(safe_ascii)

    # 3. Lưu ra file nhị phân
    output_filename = "decoded_payload.bin"
    with open(output_filename, "wb") as f:
        f.write(raw_bytes)
    print(f"\n[+] Đã lưu raw bytes ra file: {output_filename}")
    print(f"[!] Gợi ý tiếp theo: Chạy lệnh 'file {output_filename}' trên Kali/Ubuntu để xem đây là định dạng gì.")

if __name__ == "__main__":
    decode_zero_width_safely('input.txt')