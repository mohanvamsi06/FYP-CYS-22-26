from flask import Flask, render_template, jsonify, send_from_directory
import os, json
from collections import defaultdict, Counter
import subprocess
import time


app = Flask(__name__)
JSON_PATH = os.environ.get('RESULT_JSON_PATH', '/var/tmp/results/results.json')
RESULTS_PATH = "/var/tmp/results/results.json"
JOB_NAME = "cis-k8s-audit"
JOB_YAML = "job.yaml"
NAMESPACE = "default"

def run_cmd(cmd):
    return subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False
    )

def load_raw():
    try:
        with open(JSON_PATH, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
            for k in ('findings', 'results', 'checks'):
                if k in data and isinstance(data[k], list):
                    return data[k]
            for v in data.values() if isinstance(data, dict) else []:
                if isinstance(v, list):
                    return v
            return []
    except Exception as e:
        return {"error": f"Could not load JSON: {e}"}

def normalize_status(s):
    if not s: return 'UNKNOWN'
    s_up = str(s).strip().upper()
    if s_up in ('PASS', 'PASSED', 'SUCCESS'):
        return 'PASS'
    if s_up in ('FAIL', 'FAILED', 'ERROR'):
        return 'FAIL'
    if s_up in ('WARN', 'WARNING'):
        return 'WARN'
    return 'UNKNOWN'

def build_processed(raw_list):
    totals = {'total': 0, 'by_status': Counter()}
    per_file = defaultdict(lambda: Counter())
    top_failed = []
    checks_by_id = {}

    for item in raw_list:
        if not isinstance(item, dict):
            continue
        totals['total'] += 1
        status = normalize_status(item.get('status'))
        totals['by_status'][status] += 1

        src = item.get('_source_file') or item.get('source') or 'unknown'
        per_file[src][status] += 1

        canonical = {
            'check_id': item.get('check_id'),
            'description': item.get('description'),
            'status': status,
            'reason': item.get('reason'),
            'remediation': item.get('remediation'),
            '_source_file': src,
        }
        if 'line_results' in item and isinstance(item['line_results'], list):
            canonical['line_results'] = item['line_results'][:8]

        if status == 'FAIL':
            top_failed.append(canonical)

        cid = item.get('check_id')
        if cid:
            checks_by_id[cid] = canonical

    # robust sort: coerce check_id to string so comparisons are consistent
    top_failed.sort(key=lambda x: (0 if 'line_results' in x else 1, str(x.get('check_id') or '')))

    top_failed = top_failed[:20]

    per_file_out = {}
    for src, counter in per_file.items():
        per_file_out[src] = dict(counter)

    processed = {
        'summary': {
            'total_checks': totals['total'],
            'counts': dict(totals['by_status']),
        },
        'per_file': per_file_out,
        'top_failed': top_failed,
        'counts_by_status': dict(totals['by_status']),
        'meta': {'source_path': JSON_PATH}
    }
    return processed

@app.route("/api/scan/start", methods=["POST"])
def start_scan():
    # 1. Delete old results
    try:
        if os.path.exists(RESULTS_PATH):
            os.remove(RESULTS_PATH)
    except Exception as e:
        return jsonify({"error": f"Failed to delete results: {e}"}), 500

    # 2. Delete existing job if present
    run_cmd([
        "kubectl", "delete", "job", JOB_NAME,
        "-n", NAMESPACE, "--ignore-not-found=true"
    ])

    # 3. Apply job.yaml
    res = run_cmd(["kubectl", "apply", "-f", JOB_YAML])
    if res.returncode != 0:
        return jsonify({"error": res.stderr}), 500

    return jsonify({"status": "started"})

@app.route("/api/scan/status")
def scan_status():
    res = run_cmd([
        "kubectl", "get", "job", JOB_NAME,
        "-n", NAMESPACE,
        "-o", "json"
    ])

    if res.returncode != 0:
        return jsonify({"status": "not_found"})

    try:
        job = json.loads(res.stdout)
        status = job.get("status", {})

        if status.get("failed", 0) > 0:
            return jsonify({"status": "failed"})

        if status.get("succeeded", 0) > 0:
            return jsonify({"status": "completed"})

        return jsonify({"status": "running"})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)})

@app.route('/')
def index():
    return render_template('base.html')

@app.route('/compliance')
def compliance():
    return render_template('compliance.html')

@app.route('/api/data')
def api_raw():
    data = load_raw()
    return jsonify(data)

@app.route('/api/processed')
def api_processed():
    raw = load_raw()
    if isinstance(raw, dict) and raw.get('error'):
        return jsonify({'error': raw.get('error')}), 500
    processed = build_processed(raw)
    return jsonify(processed)

@app.route('/result.json')
def serve_result():
    if os.path.exists(JSON_PATH):
        return send_from_directory(os.path.dirname(os.path.abspath(JSON_PATH)) or '.', os.path.basename(JSON_PATH))
    return ("Not found", 404)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
