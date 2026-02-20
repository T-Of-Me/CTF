import requests

PUBLIC_URL = "https://caf9f866c38a.ngrok-free.app"

session = requests.Session()
session.headers.update({
    'ngrok-skip-browser-warning': 'true',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
})

print("[1] Testing homepage...")
r = session.get(PUBLIC_URL)
print(f"    Status: {r.status_code}")
print(f"    Text: {r.text[:150]}")

print("\n[2] Testing /_next/image with simple URL...")
test = f"{PUBLIC_URL}/_next/image?w=640&q=75&url=https%3A%2F%2Fpicsum.photos%2F200"
r = session.get(test)
print(f"    Status: {r.status_code}")
if r.status_code != 200:
    print(f"    Text: {r.text[:150]}")
else:
    print(f"    Got image: {len(r.content)} bytes")

print("\n[3] Testing with rebinding server...")
test2 = f"{PUBLIC_URL}/_next/image?w=640&q=75&url=http%3A%2F%2F7f000001.c0a80001.rbndr.us%3A5000%2F"
r = session.get(test2)
print(f"    Status: {r.status_code}")
print(f"    Length: {len(r.content)} bytes")