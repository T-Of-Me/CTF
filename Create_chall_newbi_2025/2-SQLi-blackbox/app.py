from flask import Flask, render_template, request, redirect, url_for
import sqlite3

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('DROP TABLE IF EXISTS users')
    c.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)')
    c.execute("INSERT INTO users (username, password) VALUES ('admin', 'super_secret_password_123')")
    c.execute("INSERT INTO users (username, password) VALUES ('user', 'user123')")
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    
    try:
        c.execute(query)
        result = c.fetchone()
        conn.close()
        
        if result:
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error='Hỏi HN để biết mật khẩu')
    except Exception as e:
        conn.close()
        return render_template('login.html', error='Đừng cố gằng nữa baybe')

@app.route('/dashboard')
def dashboard():
    flag = "MSEC{no_flag}"
    return render_template('dashboard.html', flag=flag)

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=False)

    