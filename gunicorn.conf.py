# gunicorn.conf.py
#
#   gunicorn -c gunicorn.conf.py extension:app
#
# 워커를 1개로 둔 이유가 두 가지 있다.
#
#  1) 지표 정확도. prometheus_client 는 프로세스마다 따로 집계하므로 워커가 여럿이면
#     /metrics 응답이 그때그때 다른 워커의 숫자를 보여준다. 대시보드가 발표 자료라서
#     이 오차를 감당할 수 없다. 워커를 늘리려면 PROMETHEUS_MULTIPROC_DIR 를 잡고
#     multiprocess collector 로 바꿔야 한다.
#
#  2) 메모리. 모델은 import 시점에 로드되므로 워커 수만큼 사본이 생긴다.
#     서버가 노트북이라 여유가 없다.
#
# 동시성은 스레드로 확보한다. torch 는 연산 중 GIL 을 놓기 때문에 CPU 추론에서도
# 스레드가 효과가 있다. 여기에 확장의 내장 허용 목록과 Redis 판정 캐시가 얹히면
# 파일럿 규모에서는 이걸로 충분하다.

import os

bind = f"[::]:{os.getenv('SERVER_PORT', '5000')}"
workers = int(os.getenv('GUNICORN_WORKERS', '1'))
threads = int(os.getenv('GUNICORN_THREADS', '8'))
worker_class = 'gthread'

# 모델 로드가 오래 걸린다. 기동 중에 워커가 죽지 않게 넉넉히 둔다.
timeout = 120
graceful_timeout = 30
keepalive = 5

preload_app = True

accesslog = '-'
errorlog = '-'
loglevel = os.getenv('GUNICORN_LOGLEVEL', 'info')
