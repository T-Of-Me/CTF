```bash
docker build -t pdf.exe . && docker run -d --name pdf.exe-container -p 3000:3000 pdf.exe
```