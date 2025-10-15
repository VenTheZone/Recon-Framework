from flask import Flask, request, jsonify, send_from_directory, Response
from flask_sqlalchemy import SQLAlchemy
import threading
from bypass import run_full_scan
from crawler import start_crawl
from reporting import generate_html_report, generate_pdf_report
from scanners.xss_scanner import run_xss_scanner
from scanners.surface_scanner import run_surface_scanner
from scanners.port_scanner import run_port_scanner
import os
from huggingface_hub import InferenceClient
import multiprocessing
import json
import uuid

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scans.db'
db = SQLAlchemy(app)

CRAWL_OUTPUT_DIR = os.path.join(os.getcwd(), 'crawl_results')
CHAT_HISTORY = {}

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(200), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False)
    result = db.Column(db.Text, nullable=False)

class Crawl(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(200), nullable=False)
    result = db.Column(db.Text, nullable=False)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    api_key = db.Column(db.String(200), nullable=True)
    model_id = db.Column(db.String(200), nullable=True, default="Qwen/Qwen3-Coder-480B-A35B-Instruct")
    session_id = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))


@app.route('/')
def hello_world():
    return 'Hello, World!'

def run_full_scan_and_save(url, wordlist, output_file, scan_id):
    run_full_scan(url, wordlist, output_file)
    with app.app_context():
        scan = Scan.query.get(scan_id)
        with open(output_file, 'r') as f:
            scan.result = f.read()
        db.session.commit()

def run_xss_scanner_and_save(url, scan_id):
    is_vulnerable = run_xss_scanner(url)
    with app.app_context():
        scan = Scan.query.get(scan_id)
        scan.result = "Vulnerable" if is_vulnerable else "Not Vulnerable"
        db.session.commit()

def run_surface_scanner_and_save(domain, scan_id):
    results = run_surface_scanner(domain)
    with app.app_context():
        scan = Scan.query.get(scan_id)
        scan.result = json.dumps(results)
        db.session.commit()

def run_port_scanner_and_save(target, scan_id):
    results = run_port_scanner(target)
    with app.app_context():
        scan = Scan.query.get(scan_id)
        scan.result = json.dumps(results)
        db.session.commit()

@app.route('/scan/bypass', methods=['POST'])
def scan_route():
    data = request.get_json()
    url = data.get('url')
    wordlist = data.get('wordlist', '/usr/share/seclists/Discovery/Web-Content/common.txt')

    if not url:
        return jsonify({'error': 'URL is required'}), 400

    new_scan = Scan(url=url, scan_type='bypass', result="Scanning...")
    db.session.add(new_scan)
    db.session.commit()

    output_file = f"{new_scan.id}_scan.txt"

    scan_thread = threading.Thread(target=run_full_scan_and_save, args=(url, wordlist, output_file, new_scan.id))
    scan_thread.start()

    return jsonify({'message': 'Scan started', 'scan_id': new_scan.id})

@app.route('/scan/xss', methods=['POST'])
def xss_scan_route():
    data = request.get_json()
    url = data.get('url')

    if not url:
        return jsonify({'error': 'URL is required'}), 400

    new_scan = Scan(url=url, scan_type='xss', result="Scanning...")
    db.session.add(new_scan)
    db.session.commit()

    scan_thread = threading.Thread(target=run_xss_scanner_and_save, args=(url, new_scan.id))
    scan_thread.start()

    return jsonify({'message': 'XSS scan started', 'scan_id': new_scan.id})

@app.route('/scan/surface', methods=['POST'])
def surface_scan_route():
    data = request.get_json()
    domain = data.get('domain')

    if not domain:
        return jsonify({'error': 'Domain is required'}), 400

    new_scan = Scan(url=domain, scan_type='surface', result="Scanning...")
    db.session.add(new_scan)
    db.session.commit()

    scan_thread = threading.Thread(target=run_surface_scanner_and_save, args=(domain, new_scan.id))
    scan_thread.start()

    return jsonify({'message': 'Attack surface scan started', 'scan_id': new_scan.id})

@app.route('/scan/port', methods=['POST'])
def port_scan_route():
    data = request.get_json()
    target = data.get('target')

    if not target:
        return jsonify({'error': 'Target is required'}), 400

    new_scan = Scan(url=target, scan_type='port', result="Scanning...")
    db.session.add(new_scan)
    db.session.commit()

    scan_thread = threading.Thread(target=run_port_scanner_and_save, args=(target, new_scan.id))
    scan_thread.start()

    return jsonify({'message': 'Port scan started', 'scan_id': new_scan.id})


@app.route('/api/scans', methods=['GET'])
def get_scans():
    scans = Scan.query.all()
    return jsonify([{'id': scan.id, 'url': scan.url, 'scan_type': scan.scan_type, 'result': scan.result} for scan in scans])

@app.route('/api/crawls', methods=['GET'])
def get_crawls():
    crawls = Crawl.query.all()
    return jsonify([{'id': crawl.id, 'url': crawl.url, 'result': crawl.result} for crawl in crawls])


@app.route('/api/assistant', methods=['POST'])
def assistant():
    data = request.get_json()
    session_id = data.get('session_id')
    scan_context = data.get('scan_context')
    user_question = data.get('user_question')

    user = User.query.first()
    api_key = user.api_key if user else None
    model_id = user.model_id if user else "Qwen/Qwen3-Coder-480B-A35B-Instruct"

    if not all([session_id, user_question, api_key]):
        return jsonify({'error': 'Missing session_id, user question or API key not set'}), 400

    if session_id not in CHAT_HISTORY:
        CHAT_HISTORY[session_id] = []

    history = CHAT_HISTORY[session_id]

    full_prompt = "Conversation History:\n"
    for turn in history:
        full_prompt += f"{turn['sender']}: {turn['text']}\n"
    full_prompt += f"\nYou are R-T-F_Assistant, an expert penetration tester. Analyze the following context for potential misconfigurations or vulnerabilities. Provide a concise analysis and answer the user's question.\n\nContext:\n{scan_context}\n\nUser Question:\n{user_question}\n\nAssistant:"

    try:
        client = InferenceClient(model_id, token=api_key)
        response = client.text_generation(full_prompt, max_new_tokens=500)

        history.append({'sender': 'user', 'text': user_question})
        history.append({'sender': 'ai', 'text': response})
        CHAT_HISTORY[session_id] = history

        return jsonify({'response': response})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def start_crawl_and_save(start_url, allowed_domain, output_file, crawl_id):
    start_crawl(start_url, allowed_domain, output_file)
    with app.app_context():
        with open(output_file, 'r') as f:
            crawl = Crawl.query.get(crawl_id)
            crawl.result = f.read()
            db.session.commit()


@app.route('/crawl', methods=['POST'])
def crawl():
    data = request.get_json()
    url = data.get('url')
    allowed_domain = data.get('allowed_domain')

    if not url or not allowed_domain:
        return jsonify({'error': 'URL and allowed_domain are required'}), 400

    new_crawl = Crawl(url=url, result="Crawling...")
    db.session.add(new_crawl)
    db.session.commit()

    output_file = os.path.join(CRAWL_OUTPUT_DIR, f"{new_crawl.id}_crawl.json")

    crawl_process = multiprocessing.Process(target=start_crawl_and_save, args=(url, allowed_domain, output_file, new_crawl.id))
    crawl_process.start()

    return jsonify({'message': 'Crawl started', 'crawl_id': new_crawl.id})

@app.route('/results/<filename>', methods=['GET'])
def get_results(filename):
    return send_from_directory(CRAWL_OUTPUT_DIR, filename)

@app.route('/api/settings', methods=['POST'])
def save_settings():
    data = request.get_json()
    api_key = data.get('api_key')
    model_id = data.get('model_id')
    user = User.query.first()
    if not user:
        user = User()
        db.session.add(user)
    user.api_key = api_key
    user.model_id = model_id
    db.session.commit()
    return jsonify({'message': 'Settings saved'})

@app.route('/api/settings', methods=['GET'])
def get_settings():
    user = User.query.first()
    api_key = user.api_key if user else ''
    model_id = user.model_id if user else "Qwen/Qwen3-Coder-480B-A35B-Instruct"
    return jsonify({'api_key': api_key, 'model_id': model_id})

@app.route('/report/<int:scan_id>/<string:format>')
def download_report(scan_id, format):
    scan = Scan.query.get_or_404(scan_id)
    if format == 'html':
        html = generate_html_report(scan)
        return Response(html, mimetype='text/html')
    elif format == 'pdf':
        pdf = generate_pdf_report(scan)
        return Response(pdf, mimetype='application/pdf')
    else:
        return jsonify({'error': 'Invalid format'}), 400

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
