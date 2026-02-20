import requests
from bs4 import BeautifulSoup

BASE = "http://challs.watctf.org:3080"

# session giữ cookie (connect.sid)
s = requests.Session()

# các đáp án đúng theo bundle
answers = [
    "Perimeter Institute for Theoretical Physics",  # Q1
    "University of Waterloo",                      # Q2
    "BlackBerry (RIM)"                             # Q3
]

# 1. Load trang quiz (để có session)
resp = s.get(BASE)
print("[*] Start:", resp.status_code, s.cookies.get_dict())

# 2. Nếu quiz là client-side React thì có thể không có endpoint /api,
#    nhưng thường backend có 1 route nhận answer. Nếu không thì ta chỉ cần session.
#    -> Thử vào /admin luôn
resp = s.get(BASE + "/admin", allow_redirects=False)
print("[*] Admin first try:", resp.status_code, resp.headers.get("location"))

# Nếu vẫn redirect thì có thể cần simulate việc "xong quiz".
# Giả sử có endpoint /api/answer (bạn chỉnh lại đúng URL nhé)
for idx, ans in enumerate(answers):
    data = {"q": idx, "answer": ans}
    r = s.post(BASE + "/api/answer", json=data)
    print(f"Answer {idx+1}:", r.status_code, r.text[:100])

# 3. Sau khi trả lời hết, vào lại /admin
resp = s.get(BASE + "/admin")
print("[*] Admin final:", resp.status_code)
print(resp.text[:1000])  # in thử 1000 ký tự đầu
