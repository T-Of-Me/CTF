import os
import time
from urllib.request import urlopen
from flask import Flask, request, send_from_directory, jsonify, abort
from werkzeug.utils import secure_filename
import pdfkit

# ---

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SHARED_DIR = os.path.join(BASE_DIR, 'reports')
os.makedirs(SHARED_DIR, exist_ok=True)

# ---

def get_system_report(content_disposition="attachment; filename=\"report.txt\""):
    """
    Generates the text rep2ort containing system info.
    """
    report = f"{content_disposition}\n\n"
    report += os.popen("uname -a && echo && uptime && echo && whoami").read()
    return report

def fetch_pdf_report(data_uri, filename):
    """
    Parses the data URI and constructs the report content.
    Returns the report string on success, or None on failure.
    """
    try:
        response = urlopen(data_uri)
        info = response.info()
        
        raw_body = response.read()

        cd_header = info.get("Content-Disposition")
        
        if cd_header:
            final_cd = f'{cd_header}; id="{raw_body}"; filename="{filename}"'
        else:
            final_cd = f'attachment; filename="{filename}"'

        return get_system_report(final_cd)

    except Exception:
        return None

# ---

@app.route('/generate', methods=['GET'])
def generate_pdf():
    data_uri = request.args.get('data')
    if not data_uri:
        return jsonify({"error": "Missing 'data' parameter"}), 400
    
    if not data_uri.startswith("data:plain/text"):
        return jsonify({"error": "Invalid data format"}), 400

    timestamp = int(time.time())
    filename = f"report_{timestamp}.pdf"
    
    content = fetch_pdf_report(data_uri, filename)
    if content is None:
        return jsonify({"error": "Failed to fetch report content"}), 500
    
    output_path = os.path.join(SHARED_DIR, filename)
    try:
        pdfkit.from_string(content, output_path)
        return jsonify({"message": "PDF generated", "filename": filename})
    except Exception:
        return jsonify({"error": "Failed to generate PDF"}), 500

# ---

@app.route('/pdfs', methods=['GET'])
def list_pdfs():
    files = [f for f in os.listdir(SHARED_DIR) if f.endswith('.pdf')]
    return jsonify({"files": files})

# ---

@app.route('/pdfs/<filename>', methods=['GET'])
def download_pdf(filename):
    safe_filename = secure_filename(filename)
    
    if safe_filename != filename:
        return abort(400, description="Invalid filename")
        
    file_path = os.path.join(SHARED_DIR, safe_filename)
    if not os.path.exists(file_path):
        return abort(404, description="File not found")

    return send_from_directory(SHARED_DIR, safe_filename, as_attachment=True)

# ---

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)