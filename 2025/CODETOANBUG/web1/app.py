from flask import Flask, request, render_template, abort
import base64
import pickle

app = Flask(__name__)

# Replace with your actual flag
FLAG = "CODE_TOAN_BUG{fake_flag}"

class Exploit:
    def __reduce__(self):
        return (print, ("Flag: " + FLAG,))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/submit', methods=['POST'])
def submit():
    convert_data = request.form.get('data')
    host = request.host

    if host in ["labs.codetoanbug.com", "103.173.155.151:4100"]:
        abort(403)

    try:
        obj = pickle.loads(base64.b64decode(convert_data))
        
        if isinstance(obj, Exploit):
            return f"<p>Flag: {FLAG}</p>"
        else:
            return "<p>Invalid data.</p>"
    except Exception as e:
        return f"<p>Convert failed: {str(e)}</p>"

if __name__ == '__main__':
    app.run(host='10.0.1.1', port=4100)

