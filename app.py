from flask import Flask, render_template, request
from SURF_AI_model.model_setting import DomainClassifier

app = Flask(__name__)

# 서버 시작 시 모델 로드
print("⏳ Loading AI Model...")
classifier = DomainClassifier()

@app.route('/')
def block_page():
    # 1. 접속한 도메인 확인
    domain = request.args.get('domain', default=request.host.split(':')[0])
    prob = request.args.get('prob', default=99.9, type=float)
    
    # 2. 실시간 추론
    pred, probs = classifier.predict(domain)
    malicious_prob = round(probs[0][1].item() * 100, 2)
    
    # 3. HTML로 데이터 전달
    return render_template('index.html', domain=domain, prob=malicious_prob)

if __name__ == '__main__':
    # 관리자 권한으로 실행 (80포트)
    app.run(host='127.0.0.1', port=80) 