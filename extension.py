# app.py

import os
import sys
import time

# 1. 가상환경 경로 설정
VENV_PATH = '/opt/miniforge/envs/lower/lib/python3.9/site-packages'
sys.path.insert(0, VENV_PATH)

from prometheus_client import Counter, generate_latest, CONTENT_TYPE_LATEST, Histogram
from flask import Flask, render_template, request, jsonify, Response
import redis
from SURF_AI_model.model_setting import DomainClassifier

app = Flask(__name__)

# 서버 시작 시 모델 로드
print("⏳ Loading AI Model...")
classifier = DomainClassifier()

# Redis 연결 설정
r = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)

# for prometheus
REQUEST_COUNT = Counter(
    'surf_requests_total',
    'Total HTTP requests'
)

# Prometheus 히스토그램을 위한 버킷 정의 (초 단위)
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
    domain = domain.lower()
    if domain.startswith("www."):
        return domain[4:]
    return domain

@app.route('/check')
def check_block():
    domain = request.args.get('domain')
    client_ip = request.remote_addr.replace('::ffff:', '')

    if not domain:
        return jsonify({"error": "No domain"}), 400

    predict_name = get_predict_name(domain)
    
    # Redis에서 저장된 점수를 가져옴
    stored_score = r.get(f"block_mark:{client_ip}:{predict_name}")

    if stored_score:
        # stored_score는 "85.5" 같은 문자열이므로 float으로 변환
        return jsonify({
            "result": "surf_blocked",
            "prob": float(stored_score),
            "domain": predict_name
        })
    
    return jsonify({"result": "not_found"})

@app.route('/allow', methods=['POST'])
def allow_domain():
    data = request.json
    predict_name = get_predict_name(data.get('domain'))
    mode = data.get('mode')
    client_ip = request.remote_addr.replace('::ffff:', '')

    if mode == 'temp':
        # 30분 임시 허용
        r.setex(f"allow:{client_ip}:{predict_name}", 1800, "1")
        return jsonify({"status": "success", "message": f"[{predict_name}] 30분간 임시 허용되었습니다." })
    else:
        # 영구 허용
        r.set(f"whitelist:{client_ip}:{predict_name}", "1")
        return jsonify({"status": "success", "message": f"[{predict_name}] 영구 허용되었습니다."})

@app.route('/report-false-positive', methods=['POST'])
def report_false_positive():
    data = request.json
    domain = data.get('domain')
    domain = get_predict_name(domain)
    
    if not domain:
        return jsonify({"result": "error", "message": "No domain provided"}), 400

    # 메트릭 증가 (해당 도메인의 카운트 +1)
    FALSE_POSITIVE_COUNTER.labels(domain=domain).inc()
    
    return jsonify({"result": "success", "message": "Report received"})

@app.route('/metrics')
def metrics():
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

@app.before_request
def before_request():
    REQUEST_COUNT.inc()


if __name__ == '__main__':
    try:
        # 포트 80은 반드시 sudo 권한이 필요합니다!
        print("🚀 Server starting on Dual-Stack (IPv4/IPv6) port 80...")
        app.run(host='::', port=80, debug=True, use_reloader=True, reloader_type='stat') # 디버그 모드를 켜서 에러를 확인하세요
    except Exception as e:
        print(f"Critical Error: {e}")