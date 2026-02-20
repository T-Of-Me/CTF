from flask import Flask, request, render_template_string
import os

app = Flask(__name__)

HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>Network Ping Tool</title>
    <style>
        body { font-family: Arial; max-width: 600px; margin: 50px auto; padding: 20px; }
        input { width: 100%; padding: 10px; margin: 10px 0; }
        button { padding: 10px 20px; background: #007bff; color: white; border: none; cursor: pointer; }
        .result { background: #f5f5f5; padding: 15px; margin-top: 20px; white-space: pre-wrap; }
    </style>
</head>
<body>
    <h1>🌐 Network Ping Tool</h1>
    <form method="POST">
        <input type="text" name="host" placeholder="Enter IP or hostname" required>
        <button type="submit">Ping</button>
    </form>
    {% if result %}
    <div class="result">{{ result }}</div>
    {% endif %}
</body>
</html>
'''

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        host = request.form.get('host', '')
        # Vulnerable command injection
        cmd = f"ping -c 4 {host}"
        result = os.popen(cmd).read()
    return render_template_string(HTML, result=result)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)