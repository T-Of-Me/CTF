from flask import Flask, request, render_template, jsonify
import requests

app = Flask(__name__)

with open('flag.txt', 'r') as f:
    FLAG = f.read().strip()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/submit', methods=['POST'])
def submit():
    target_url = request.form.get('url')

    if not target_url:
        return jsonify({"error": "No URL provided"}), 400

    try:
        response = requests.get(target_url)
        
        if "CODE_TOAN_BUG{" in response.text:
            return jsonify({"flag": FLAG}), 200
        else:
            return jsonify({"response": "Flag not found in response."}), 200
    except requests.RequestException as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='10.0.1.1', port=4015)

