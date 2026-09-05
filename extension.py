# app.py
import dotenv
dotenv.load_dotenv()

import os
import sys
import time

VENV_PATH = os.getenv('VENV_PATH')
if VENV_PATH and VENV_PATH not in sys.path:
    sys.path.insert(0, VENV_PATH)

PROJECT_ROOT = os.getenv('PROJECT_ROOT')
if PROJECT_ROOT and PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

from prometheus_client import Counter, generate_latest, CONTENT_TYPE_LATEST, Histogram
from flask import Flask, render_template, request, jsonify, Response
import redis
from SURF_AI_model.model_setting import DomainClassifier

app = Flask(__name__)

# 서버 시작 시 모델 로드
print("⏳ Loading AI Model...")
classifier = DomainClassifier()

# Redis 연결 설정
r = redis.Redis(
    host=os.getenv('REDIS_HOST', '127.0.0.1'),
    port=int(os.getenv('REDIS_PORT', '6379')),
    db=int(os.getenv('REDIS_DB', '0')),
    decode_responses=True
)

# for prometheus
REQUEST_COUNT = Counter(
    'surf_requests_total',
    'Total HTTP requests'
)
PRECISION_BUCKETS = (.0005, .001, .002, .005, .01, .025, .05, .075, .1, .25, .5, 1.0, 2.5, 5.0, float("inf"))

HTTP_LATENCY = Histogram(
    'surf_http_server_duration_seconds',
    'Time taken to serve block page',
    ['stage'],
    buckets=PRECISION_BUCKETS
)

FALSE_POSITIVE_COUNTER = Counter(
    'surf_false_positive_reports_total', 
    'Total number of false positive reports',
    ['domain']
)

def get_predict_name(domain):
    if not domain:
        return None
    domain = domain.lower().strip().rstrip('.')
    if domain.startswith("www."):
        domain = domain[4:]
    return domain or None

@app.route('/check')
def check_block():
    domain = request.args.get('domain')
    client_ip = request.remote_addr.replace('::ffff:', '')

    if not domain:
        return jsonify({"error": "No domain"}), 400

    predict_name = get_predict_name(domain)
    
    stored_score = r.get(f"block_mark:{client_ip}:{predict_name}")

    if stored_score:
        return jsonify({
            "result": "surf_blocked",
            "prob": float(stored_score),
            "domain": predict_name
        })
    
    return jsonify({"result": "not_found"})

@app.route('/allow', methods=['POST'])
def allow_domain():
    data = request.get_json(silent=True) or {}
    predict_name = get_predict_name(data.get('domain'))
    if not predict_name:
        return jsonify({"status": "error", "message": "No domain"}), 400

    mode = data.get('mode')
    client_ip = request.remote_addr.replace('::ffff:', '')

    if mode == 'temp':
        r.setex(f"allow:{client_ip}:{predict_name}", 1800, "1")
        return jsonify({"status": "success", "message": f"[{predict_name}] 30분간 임시 허용되었습니다." })
    else:
        r.set(f"whitelist:{client_ip}:{predict_name}", "1")
        return jsonify({"status": "success", "message": f"[{predict_name}] 영구 허용되었습니다."})

@app.route('/report-false-positive', methods=['POST'])
def report_false_positive():
    data = request.get_json(silent=True) or {}
    domain = get_predict_name(data.get('domain'))
    
    if not domain:
        return jsonify({"result": "error", "message": "No domain provided"}), 400

    FALSE_POSITIVE_COUNTER.labels(domain=domain).inc()
    
    return jsonify({"result": "success", "message": "Report received"})

@app.route('/healthz')
def healthz():
    """프로세스 감시용. Redis 연결까지 확인한다."""
    try:
        r.ping()
        return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({"status": "degraded", "redis": str(e)}), 503


@app.route('/metrics')
def metrics():
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

@app.before_request
def before_request():
    REQUEST_COUNT.inc()


if __name__ == '__main__':
    # debug=True 로 열어두면 Werkzeug 디버거가 원격 코드 실행 통로가 된다.
    # 외부에 노출되는 배포에는 개발 서버 대신 gunicorn 을 쓴다.
    server_port = int(os.getenv('SERVER_PORT', '5000'))
    print(f"🚀 Server starting on Dual-Stack (IPv4/IPv6) port {server_port}...", flush=True)
    app.run(host='::', port=server_port, debug=False, use_reloader=False)