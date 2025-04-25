# 중고거래 플랫폼

안전하고 편리한 중고거래 서비스를 제공하는 웹 애플리케이션입니다.

## 주요 기능

- 사용자 인증 (회원가입/로그인)
- 상품 등록 및 관리
- 실시간 채팅
- 안전한 거래 시스템
- 신고 기능
- 관리자 기능

## 기술 스택

- Python 3.8+
- Flask
- SQLite3
- Socket.IO
- Bootstrap 5
- HTML/CSS/JavaScript

## 환경 설정

1. Python 설치
   - [Python 공식 웹사이트](https://www.python.org/downloads/)에서 Python 3.8 이상 버전을 다운로드하여 설치

2. 가상환경 생성 및 활성화
   ```bash
   # 가상환경 생성
   python -m venv venv

   # 가상환경 활성화
   # Windows
   venv\Scripts\activate
   # macOS/Linux
   source venv/bin/activate
   ```

3. 필요한 패키지 설치
   ```bash
   pip install -r requirements.txt
   ```

## 프로젝트 설정

1. requirements.txt 생성
   ```bash
   pip freeze > requirements.txt
   ```

2. 데이터베이스 초기화
   - 애플리케이션 최초 실행 시 자동으로 데이터베이스가 생성됩니다.

3. 환경 변수 설정
   - `config.py` 파일에서 필요한 설정을 변경할 수 있습니다.
   - 실제 운영 환경에서는 중요한 설정값을 환경 변수로 관리하는 것을 권장합니다.

## 실행 방법

1. 개발 서버 실행
   ```bash
   python app.py
   ```

2. 웹 브라우저에서 접속
   - 기본적으로 `https://localhost:443`으로 접속할 수 있습니다.

## 보안 설정

1. SSL 인증서 설정
   - `app.py`의 `ssl_context` 설정에서 인증서 경로를 지정해야 합니다.
   ```python
   ssl_context = (
       'path/to/cert.pem',  # SSL 인증서 경로
       'path/to/key.pem'    # SSL 키 경로
   )
   ```

2. 비밀키 설정
   - `app.py`의 `SECRET_KEY`를 환경 변수로 설정하는 것을 권장합니다.
   ```python
   app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')
   ```

## 디렉토리 구조

```
secure-coding/
├── app.py              # 메인 애플리케이션 파일
├── config.py           # 설정 파일
├── requirements.txt    # 의존성 패키지 목록
├── market.db          # SQLite 데이터베이스
└── templates/         # HTML 템플릿 파일들
    ├── base.html
    ├── index.html
    ├── login.html
    ├── register.html
    └── ...
```

## 의존성 패키지

```
Flask==2.0.1
Flask-SocketIO==5.1.1
Flask-WTF==0.15.1
bcrypt==3.2.0
Flask-Limiter==2.4.0
python-socketio==5.4.0
```

## 주의사항

1. 실제 운영 환경에서는 반드시 다음 사항을 확인하세요:
   - 강력한 비밀키 사용
   - SSL/TLS 인증서 설정
   - 환경 변수를 통한 중요 설정 관리
   - 적절한 로깅 설정

2. 개발 모드에서는 디버그 모드를 활성화할 수 있지만, 운영 환경에서는 반드시 비활성화해야 합니다.

## 라이선스

이 프로젝트는 MIT 라이선스를 따릅니다.
