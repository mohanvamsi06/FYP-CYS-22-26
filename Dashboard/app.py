from flask import Flask, render_template, jsonify, send_from_directory
import os, json
from collections import defaultdict, Counter
import subprocess
import time


app = Flask(__name__)
JSON_PATH = os.environ.get('RESULT_JSON_PATH', '/output/results.json')
RESULTS_PATH = "/output/results.json"
RUNTIME_LOGS_PATH = "/output/runtime_alerts.json"
JOB_NAME = "cis-k8s-audit"
NAMESPACE = "default"

# Configurable filter for runtime alerts
# Add binaries to exclude from alerts (noise from monitoring tools)
EXCLUDED_BINARIES = os.environ.get('EXCLUDED_BINARIES', 
    'kubectl,jq,grep,bash,sh,chmod,touch,echo,cat,head,tail,sed,awk,curl,wget'
).split(',')

# Event types to include (empty = include all)
# Options: 'process_exec', 'process_tracepoint', 'process_kprobe', 'process_exit'
INCLUDED_EVENT_TYPES = os.environ.get('INCLUDED_EVENT_TYPES', 
    'process_tracepoint'
).split(',') if os.environ.get('INCLUDED_EVENT_TYPES') else []

# Subsystems to include (empty = include all)
# For tracepoints: 'syscalls', 'raw_syscalls', etc.
INCLUDED_SUBSYSTEMS = os.environ.get('INCLUDED_SUBSYSTEMS', 
    'syscalls'
).split(',') if os.environ.get('INCLUDED_SUBSYSTEMS') else []

# Compliance job YAML template
COMPLIANCE_JOB_YAML = """
apiVersion: batch/v1
kind: Job
metadata:
  name: cis-k8s-audit
spec:
  template:
    spec:
      nodeSelector:
        node-role.kubernetes.io/control-plane: ""
      tolerations:
      - key: "node-role.kubernetes.io/control-plane"
        operator: "Exists"
        effect: "NoSchedule"
      - operator: "Exists"
      hostPID: true
      hostNetwork: true
      serviceAccountName: audit-runner
      restartPolicy: Never
      containers:
        - name: check
          image: mohanvamsi06/fyp:master_node 
          imagePullPolicy: Always
          volumeMounts:
            - name: kubernetes
              mountPath: /etc/kubernetes
              readOnly: true
            - name: cni
              mountPath: /etc/cni/net.d
              readOnly: true
            - name: etcd
              mountPath: /var/lib/etcd
              readOnly: true
            - name: output
              mountPath: /output
      volumes:
        - name: kubernetes
          hostPath:
            path: /etc/kubernetes
        - name: cni
          hostPath:
            path: /etc/cni/net.d
        - name: etcd
          hostPath:
            path: /var/lib/etcd
        - name: output
          hostPath:
            path: /var/tmp/results
            type: DirectoryOrCreate
"""

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

    # 3. Apply job YAML via stdin
    proc = subprocess.run(
        ["kubectl", "apply", "-f", "-"],
        input=COMPLIANCE_JOB_YAML,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False
    )
    
    if proc.returncode != 0:
        return jsonify({"error": proc.stderr}), 500

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

@app.route('/runtime')
def runtime():
    return render_template('runtime.html')

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

def should_include_alert(alert):
    """
    Determine if an alert should be included based on filters.
    Returns True if alert should be shown, False otherwise.
    """
    # Check event type
    event_type = None
    if 'process_tracepoint' in alert:
        event_type = 'process_tracepoint'
        process_data = alert['process_tracepoint'].get('process', {})
        subsys = alert['process_tracepoint'].get('subsys', '')
    elif 'process_exec' in alert:
        event_type = 'process_exec'
        process_data = alert['process_exec'].get('process', {})
        subsys = None
    elif 'process_kprobe' in alert:
        event_type = 'process_kprobe'
        process_data = alert['process_kprobe'].get('process', {})
        subsys = None
    elif 'process_exit' in alert:
        event_type = 'process_exit'
        process_data = alert['process_exit'].get('process', {})
        subsys = None
    else:
        return False
    
    # Filter by event type if specified
    if INCLUDED_EVENT_TYPES and event_type not in INCLUDED_EVENT_TYPES:
        return False
    
    # Filter by subsystem if specified (for tracepoints)
    if INCLUDED_SUBSYSTEMS and subsys and subsys not in INCLUDED_SUBSYSTEMS:
        return False
    
    # Get binary name
    binary = process_data.get('binary', '')
    
    # Exclude noise from monitoring tools
    if any(excluded in binary for excluded in EXCLUDED_BINARIES):
        return False
    
    return True

@app.route('/api/runtime/alerts')
def runtime_alerts():
    """Fetch runtime security alerts from Tetragon logs"""
    try:
        if not os.path.exists(RUNTIME_LOGS_PATH):
            return jsonify({'alerts': [], 'total': 0, 'error': 'No runtime logs found'})
        
        with open(RUNTIME_LOGS_PATH, 'r', encoding='utf-8') as f:
            alerts = []
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    alert = json.loads(line)
                    
                    # Apply filters
                    if should_include_alert(alert):
                        alerts.append(alert)
                        
                except json.JSONDecodeError:
                    continue
            
            # Sort by timestamp (most recent first)
            alerts.sort(key=lambda x: x.get('time', ''), reverse=True)
            
            # Limit to last 1000 alerts
            alerts = alerts[:1000]
            
            return jsonify({
                'alerts': alerts,
                'total': len(alerts),
                'timestamp': time.time()
            })
    except Exception as e:
        return jsonify({'error': str(e), 'alerts': [], 'total': 0}), 500

@app.route('/api/runtime/stats')
def runtime_stats():
    """Get statistics about runtime alerts"""
    try:
        if not os.path.exists(RUNTIME_LOGS_PATH):
            return jsonify({'error': 'No runtime logs found'})
        
        with open(RUNTIME_LOGS_PATH, 'r', encoding='utf-8') as f:
            alerts = []
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    alert = json.loads(line)
                    
                    # Apply filters
                    if should_include_alert(alert):
                        alerts.append(alert)
                        
                except json.JSONDecodeError:
                    continue
        
        # Calculate statistics
        total = len(alerts)
        by_type = Counter()
        by_process = Counter()
        by_severity = Counter()
        
        for alert in alerts:
            # Extract event info based on type
            if 'process_tracepoint' in alert:
                event_type = alert['process_tracepoint'].get('event', 'unknown')
                process_name = alert['process_tracepoint'].get('process', {}).get('binary', 'unknown')
            elif 'process_exec' in alert:
                event_type = 'execve'
                process_name = alert['process_exec'].get('process', {}).get('binary', 'unknown')
            elif 'process_kprobe' in alert:
                event_type = alert['process_kprobe'].get('function_name', 'kprobe')
                process_name = alert['process_kprobe'].get('process', {}).get('binary', 'unknown')
            else:
                event_type = 'unknown'
                process_name = 'unknown'
            
            by_type[event_type] += 1
            by_process[process_name] += 1
            
            # Determine severity based on event type
            event_lower = event_type.lower()
            if any(x in event_lower for x in ['setuid', 'capset', 'sigkill', 'unshare', 'mount']):
                by_severity['critical'] += 1
            elif any(x in event_lower for x in ['clone', 'accept', 'connect', 'bind']):
                by_severity['high'] += 1
            elif any(x in event_lower for x in ['execve', 'ptrace', 'chmod', 'chown']):
                by_severity['medium'] += 1
            else:
                by_severity['low'] += 1
        
        return jsonify({
            'total': total,
            'by_type': dict(by_type.most_common(10)),
            'by_process': dict(by_process.most_common(10)),
            'by_severity': dict(by_severity),
            'timestamp': time.time()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
