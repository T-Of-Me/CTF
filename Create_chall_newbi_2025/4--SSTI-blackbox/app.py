from flask import Flask, request, render_template_string, render_template
import os

app = Flask(__name__)

# Blacklist để filter một số payload nguy hiểm
BLACKLIST = ['config', 'self', 'request', 'class', 'mro', 'subclasses', 'globals', 'builtins', 'import']

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/greet', methods=['POST'])
def greet():
    name = request.form.get('name', '')
    
    # Kiểm tra blacklist
    for word in BLACKLIST:
        if word.lower() in name.lower():
            return "Hacking detected! 🚨", 403
    
    # Lỗ hổng SSTI: render_template_string với input của user
    template = f"<h1>Hello {name}!</h1><p>Welcome to our website.</p>"
    return render_template_string(template)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)