import requests

words = ['flag', 'truth', 'answer', 'key', 'solution', 'password']
url = "https://the-trial.chall.lac.tf/"

for word in words:
    data = {'answer': f'I want the {word}.'}
    r = requests.post(url, data=data)
    if '{' in r.text or 'correct' in r.text.lower():
        print(f"Found: {word}")
        print(r.text)