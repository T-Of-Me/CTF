from flask import Flask, request, jsonify, render_template, session, redirect, url_for
import re
import os
import subprocess
from functools import wraps

app = Flask(__name__)
app.secret_key = os.urandom(32)

FLAG = os.getenv('FLAG', 'FLAG{CVE_2025_61757_0r4cl3_1d3nt1ty_pwn3d}')

users_db = {
    'admin': {
        'password': 'Oracle@2025!Admin',
        'role': 'SystemAdministrator',
        'first_name': 'System',
        'last_name': 'Administrator',
        'email': 'admin@oim.local',
        'usr_key': '1'
    }
}

def security_filter():
    """
    Vulnerable SecurityFilter - CVE-2025-61757
    
    Real vulnerable code from Oracle:
    if (queryString.equalsIgnoreCase("WSDL") || WADL_PATTERN.matcher(requestURI).find()) {
        chain.doFilter(...)
    }
    """
    query_string = request.query_string.decode('utf-8').upper()
    
    # Bypass 1: ?WSDL query parameter
    if 'WSDL' in query_string:
        return True
    
    # Bypass 2: Matrix parameter with .wadl (e.g., /path;.wadl)
    full_path = request.full_path.rstrip('?')
    if re.search(r'\.wadl', full_path, re.IGNORECASE):
        return True
    
    if re.search(r'\.wadl', request.url, re.IGNORECASE):
        return True
    
    # Public endpoints
    public = ['/static/', '/login', '/identity/rest/v1/info', '/']
    return any(request.path.startswith(p) for p in public)

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if security_filter():
            return f(*args, **kwargs)
        if 'authenticated' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/')
def index():
    return redirect(url_for('dashboard' if 'authenticated' in session else 'login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username in users_db and users_db[username]['password'] == password:
            session.update({'authenticated': True, 'username': username, 'role': users_db[username]['role']})
            return redirect(url_for('dashboard'))
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'authenticated' not in session:
        return redirect(url_for('login'))
    user_data = users_db.get(session.get('username'), {})
    show_flag = user_data.get('role') == 'SystemAdministrator'
    return render_template('dashboard.html', user=user_data, username=session.get('username'), flag=FLAG if show_flag else None)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/identity/rest/v1/info')
def info():
    return jsonify({'product': 'Oracle Identity Manager', 'version': '12.2.1.4.0', 'component': 'REST WebServices', 'status': 'running'})

@app.route('/iam/governance/applicationmanagement/api/v1/applications/templates')
@app.route('/iam/governance/applicationmanagement/api/v1/applications/templates<path:s>')
@require_auth
def templates(s=None):
    return jsonify({'templates': [{'id': '1', 'name': 'Active Directory'}]})

@app.route('/iam/governance/applicationmanagement/api/v1/applications/groovyscriptstatus', methods=['POST'])
@app.route('/iam/governance/applicationmanagement/api/v1/applications/groovyscriptstatus<path:s>', methods=['POST'])
@require_auth
def groovy_compile(s=None):
    """
    Groovy compilation endpoint with @ASTTest execution
    
    Real exploit: @ASTTest annotation executes code during compilation
    """
    try:
        data = request.get_json()
        script = data.get('groovyScript', '')
        
        # Pattern 1: Real Groovy @ASTTest with Runtime.exec()
        ast_pattern = r'@ASTTest\s*\([^)]*value\s*=\s*\{([^}]+)\}'
        match = re.search(ast_pattern, script, re.DOTALL)
        
        if match:
            ast_code = match.group(1)
            exec_match = re.search(r'Runtime\.getRuntime\(\)\.exec\(["\']([^"\']+)["\']\)', ast_code)
            if exec_match:
                cmd = exec_match.group(1)
                result = subprocess.check_output(cmd, shell=True, timeout=5, text=True, stderr=subprocess.STDOUT)
                return jsonify({'status': 'compiled', 'output': f'Compilation successful\n{result}'})
        
        # Pattern 2: Simple command (CTF mode)
        if 'script' in data:
            result = subprocess.check_output(data['script'], shell=True, timeout=5, text=True, stderr=subprocess.STDOUT)
            return jsonify({'status': 'compiled', 'output': result})
        
        return jsonify({'status': 'compiled', 'message': 'Script compiled (no execution)'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=14000, debug=False)
