# extension.py
#
# SURF 확장 프로그램이 붙는 HTTP API.
#
# 엔드포인트는 두 갈래다.
#   /predict  단독 모드. 확장이 이동 직전에 도메인을 보내면 즉석 추론해서 답한다.
#   /check    DNS 연동 모드. NXDOMAIN 이 우리 모델 때문인지 Redis 기록으로 확인한다.
#
# 클라이언트 식별은 IP 가 아니라 토큰으로 한다. Cloudflare 터널이나 DoH 를 거치면
# remote_addr 이 전부 127.0.0.1 로 뭉개져서 허용 상태를 기기별로 구분할 수 없다.

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

from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
from flask import Flask, request, jsonify, Response
from flask_cors import CORS
import redis
import torch

from SURF_AI_model.model_setting import DomainClassifier

# ---------------------------------------------------------------- 설정

# CPU 추론이라 스레드 과할당이 오히려 느리다. 워커 수와 곱해져 코어를 넘지 않게 잡는다.
torch.set_num_threads(int(os.getenv('TORCH_THREADS', '2')))

PREDICT_CACHE_TTL = int(os.getenv('PREDICT_CACHE_TTL', '21600'))   # 6시간
BLOCK_MARK_TTL = int(os.getenv('BLOCK_MARK_TTL', '300'))
TEMP_ALLOW_TTL = int(os.getenv('TEMP_ALLOW_TTL', '1800'))          # 30분
RATE_LIMIT_PER_MIN = int(os.getenv('RATE_LIMIT_PER_MIN', '600'))

# 웹 데모 페이지가 다른 오리진에서 호출한다. 확장은 host_permissions 로 통과하므로
# CORS 와 무관하지만, 브라우저에서 직접 부르는 경로를 위해 열어둔다.
ALLOWED_ORIGINS = [o.strip() for o in os.getenv('CORS_ORIGINS', '*').split(',') if o.strip()]

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": ALLOWED_ORIGINS}},
     allow_headers=["Content-Type", "X-SURF-Client"])

print("⏳ Loading AI Model...", flush=True)
classifier = DomainClassifier()

r = redis.Redis(
    host=os.getenv('REDIS_HOST', '127.0.0.1'),
    port=int(os.getenv('REDIS_PORT', '6379')),
    db=int(os.getenv('REDIS_DB', '0')),
    decode_responses=True
)

# ---------------------------------------------------------------- 메트릭

PRECISION_BUCKETS = (.0005, .001, .002, .005, .01, .025, .05, .075, .1,
                     .25, .5, 1.0, 2.5, 5.0, float("inf"))

REQUEST_COUNT = Counter('surf_requests_total', 'Total HTTP requests')

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

# 확장 단독 모드 지표. DNS 경로 지표(surf_dns_*)와 이름을 나눠서
# 대시보드에서 두 경로를 따로 볼 수 있게 한다.
EXT_PREDICT_TOTAL = Counter(
    'surf_ext_predict_total',
    'Extension standalone predictions',
    ['result', 'cached']
)

EXT_PREDICT_LATENCY = Histogram(
    'surf_ext_predict_duration_seconds',
    'Extension standalone prediction latency',
    ['result'],
    buckets=PRECISION_BUCKETS
)

EXT_AI_LATENCY = Histogram(
    'surf_ext_ai_inference_duration_seconds',
    'Pure model inference latency on the HTTP path',
    ['result'],
    buckets=PRECISION_BUCKETS
)

ALLOW_ACTIONS = Counter(
    'surf_allow_actions_total',
    'User allow decisions from the block page',
    ['mode']
)

# ---------------------------------------------------------------- 헬퍼

def get_predict_name(domain):
    if not domain:
        return None
    domain = domain.lower().strip().rstrip('.')
    if domain.startswith("www."):
        domain = domain[4:]
    return domain or None


# 프록시를 거친 요청은 전부 이 주소로 보인다. 식별자로 쓰면 한 사람의 허용이
# 모든 사용자에게 적용되므로 후보에서 뺀다.
LOOPBACK = {'127.0.0.1', '::1', 'localhost'}


def client_ids():
    """이 요청을 낸 기기를 가리킬 수 있는 식별자를 우선순위대로 모은다.

    같은 기기라도 경로에 따라 다른 이름으로 기록된다.

      DoH 를 쓰면   DoH 프록시가 토큰을 넘겨 Unbound 가 토큰으로 기록한다.
      53 에 직접 붙으면  Unbound 가 클라이언트 IP 로 기록한다.

    확장은 어느 쪽이든 토큰 헤더를 보내므로, 토큰만 보면 직접 붙은 경우의 기록을
    찾지 못한다. 두 후보를 모두 들고 다녀야 양쪽이 맞물린다.
    """
    ids = []

    token = request.headers.get('X-SURF-Client') or request.args.get('c')
    if token:
        ids.append(token.strip()[:64])

    ip = (request.remote_addr or '').replace('::ffff:', '')
    if ip and ip not in LOOPBACK and ip not in ids:
        ids.append(ip)

    return ids or ['unknown']


def client_id():
    """기록을 남길 때 쓰는 대표 식별자."""
    return client_ids()[0]


def rate_limited(cid):
    """공개 엔드포인트라 남용을 막는다. 분 단위 고정 창이면 충분하다."""
    if RATE_LIMIT_PER_MIN <= 0:
        return False
    key = f"rl:{cid}:{int(time.time() // 60)}"
    try:
        count = r.incr(key)
        if count == 1:
            r.expire(key, 120)
        return count > RATE_LIMIT_PER_MIN
    except Exception:
        return False


def run_model(domain):
    """모델 추론. (blocked, score) 를 돌려준다.

    score 는 DNS 모듈과 같은 척도다. 악성 확률 50~100% 구간을 0~100 으로 편 값이라
    차단 페이지 게이지가 두 경로에서 동일하게 보인다.
    """
    pred, probs = classifier.predict(domain)
    raw_percent = probs[0][1].item() * 100
    score = round(max(0.0, (raw_percent - 50) * 2), 2)
    return pred == 1, score

# ---------------------------------------------------------------- 라우트

@app.route('/predict')
def predict():
    """단독 모드용 즉석 추론. 확장이 이동 직전에 호출한다."""
    started = time.time()
    domain = get_predict_name(request.args.get('domain'))
    if not domain:
        return jsonify({"error": "No domain"}), 400

    cids = client_ids()
    cid = cids[0]
    if rate_limited(cid):
        return jsonify({"error": "rate limited"}), 429

    # 사용자가 이미 허용해둔 도메인은 모델을 돌리지 않는다.
    try:
        if any(r.exists(f"whitelist:{c}:{domain}") or r.exists(f"allow:{c}:{domain}")
               for c in cids):
            EXT_PREDICT_TOTAL.labels(result='allowed', cached='allowlist').inc()
            return jsonify({"blocked": False, "prob": 0.0, "domain": domain,
                            "reason": "user_allowed"})
    except Exception as e:
        print(f"⚠️ Redis allow 조회 실패: {e}", flush=True)

    # 판정 캐시. 파일럿 기간 동안 같은 도메인을 반복 추론하지 않게 한다.
    cache_key = f"pred:{domain}"
    cached = None
    try:
        cached = r.get(cache_key)
    except Exception as e:
        print(f"⚠️ Redis 캐시 조회 실패: {e}", flush=True)

    if cached is not None:
        score = float(cached)
        blocked = score > 0
        EXT_PREDICT_TOTAL.labels(result='blocked' if blocked else 'allowed',
                                 cached='hit').inc()
    else:
        ai_started = time.time()
        blocked, score = run_model(domain)
        ai_elapsed = time.time() - ai_started

        label = 'blocked' if blocked else 'allowed'
        EXT_AI_LATENCY.labels(result=label).observe(ai_elapsed)
        EXT_PREDICT_TOTAL.labels(result=label, cached='miss').inc()

        try:
            r.setex(cache_key, PREDICT_CACHE_TTL, str(score if blocked else 0.0))
        except Exception as e:
            print(f"⚠️ Redis 캐시 저장 실패: {e}", flush=True)

    if blocked:
        # DNS 경로와 같은 자리에 기록을 남긴다. 차단 페이지가 어느 경로로 열리든
        # /check 로 동일한 근거를 조회할 수 있다.
        try:
            r.setex(f"block_mark:{cid}:{domain}", BLOCK_MARK_TTL, str(score))
        except Exception as e:
            print(f"⚠️ Redis block_mark 저장 실패: {e}", flush=True)

    EXT_PREDICT_LATENCY.labels(result='blocked' if blocked else 'allowed') \
                       .observe(time.time() - started)

    return jsonify({"blocked": blocked, "prob": score, "domain": domain})


@app.route('/check')
def check_block():
    """DNS 연동 모드용. NXDOMAIN 이 우리 모델 때문인지 확인한다."""
    domain = get_predict_name(request.args.get('domain'))
    if not domain:
        return jsonify({"error": "No domain"}), 400

    # DNS 가 어느 이름으로 기록했든 찾아낸다. DoH 면 토큰, 53 직결이면 IP 다.
    for cid in client_ids():
        stored_score = r.get(f"block_mark:{cid}:{domain}")
        if stored_score:
            return jsonify({
                "result": "surf_blocked",
                "prob": float(stored_score),
                "domain": domain
            })

    return jsonify({"result": "not_found"})


@app.route('/allow', methods=['POST'])
def allow_domain():
    data = request.get_json(silent=True) or {}
    domain = get_predict_name(data.get('domain'))
    if not domain:
        return jsonify({"status": "error", "message": "No domain"}), 400

    mode = data.get('mode')
    cids = client_ids()

    # 후보 전체에 남긴다. Unbound 가 IP 로 보는 경로와 토큰으로 보는 경로가 갈리는데,
    # 한쪽에만 기록하면 허용을 눌러도 DNS 가 계속 막는다.
    for cid in cids:
        if mode == 'temp':
            r.setex(f"allow:{cid}:{domain}", TEMP_ALLOW_TTL, "1")
        else:
            r.set(f"whitelist:{cid}:{domain}", "1")
        r.delete(f"block_mark:{cid}:{domain}")

    message = (f"[{domain}] 30분간 임시 허용되었습니다." if mode == 'temp'
               else f"[{domain}] 영구 허용되었습니다.")

    # 판정 캐시를 지워야 허용 직후 재조회에서 다시 막지 않는다.
    r.delete(f"pred:{domain}")

    ALLOW_ACTIONS.labels(mode=('temp' if mode == 'temp' else 'perm')).inc()
    return jsonify({"status": "success", "message": message})


@app.route('/report-false-positive', methods=['POST'])
def report_false_positive():
    data = request.get_json(silent=True) or {}
    domain = get_predict_name(data.get('domain'))

    if not domain:
        return jsonify({"result": "error", "message": "No domain provided"}), 400

    FALSE_POSITIVE_COUNTER.labels(domain=domain).inc()

    # 신고 내역을 남겨 운영 중에 화이트리스트 반영 대상을 뽑을 수 있게 한다.
    try:
        r.zincrby("fp_reports", 1, domain)
    except Exception as e:
        print(f"⚠️ 오탐 기록 실패: {e}", flush=True)

    return jsonify({"result": "success", "message": "Report received"})


@app.route('/healthz')
def healthz():
    """터널·프로세스 감시용. Redis 까지 확인한다."""
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
    # 개발용 실행 경로다. 외부에 노출하는 배포는 gunicorn 을 쓴다.
    #   gunicorn -c gunicorn.conf.py extension:app
    # Flask 개발 서버를 debug 로 열어두면 Werkzeug 디버거가 원격 코드 실행 통로가 된다.
    port = int(os.getenv('SERVER_PORT', '5000'))
    print(f"🚀 개발 서버 시작 (port {port}). 배포에는 gunicorn 을 쓰세요.", flush=True)
    app.run(host='::', port=port, debug=False, use_reloader=False)
