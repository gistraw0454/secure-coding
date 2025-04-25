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

## 환경 구축 가이드

### 1. 기본 요구사항

- Python 3.8 이상
- pip (Python 패키지 관리자)
- Git

### 2. Python 설치
1. [Python 공식 웹사이트](https://www.python.org/downloads/)에서 Python 3.8 이상 버전을 다운로드
2. 설치 시 "Add Python to PATH" 옵션 체크
3. 설치 완료 후 버전 확인:
   ```bash
   python --version
   ```

### 3. 프로젝트 클론 및 설정

1. 프로젝트 클론:
   ```bash
   git clone [repository_url]
   cd secure-coding
   ```

2. 가상환경 생성 및 활성화:
   ```bash
   # Windows
   python -m venv venv
   venv\Scripts\activate

   # macOS/Linux
   python3 -m venv venv
   source venv/bin/activate
   ```

3. 필요한 패키지 설치:
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

### 4. 데이터베이스 설정

데이터베이스는 애플리케이션 최초 실행 시 자동으로 생성됩니다.

### 5. 환경 변수 설정

1. 개발 환경 설정 (Windows):
   ```bash
   # CMD
   set FLASK_ENV=development
   set FLASK_DEBUG=1
   set SECRET_KEY=your-secret-key-here

   # PowerShell
   $env:FLASK_ENV = "development"
   $env:FLASK_DEBUG = "1"
   $env:SECRET_KEY = "your-secret-key-here"
   ```

2. 개발 환경 설정 (macOS/Linux):
   ```bash
   export FLASK_ENV=development
   export FLASK_DEBUG=1
   export SECRET_KEY=your-secret-key-here
   ```

### 6. SSL 인증서 설정 (선택사항)

개발 환경에서 HTTPS를 사용하려면:

1. 자체 서명 인증서 생성:
   ```bash
   # Windows (OpenSSL 필요)
   openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365

   # macOS/Linux
   openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
   ```

2. 생성된 인증서 파일을 프로젝트 루트 디렉토리에 복사

### 7. 애플리케이션 실행

1. 개발 서버 실행:
   ```bash
   # 기본 실행
   python app.py

   # 특정 포트로 실행
   python app.py --port 5000
   ```

2. 웹 브라우저에서 접속:
   - HTTPS 사용 시: `https://localhost:443`
   - HTTP 사용 시: `http://localhost:5000`

### 8. 문제 해결

1. 포트 충돌 시:
   ```bash
   # Windows
   netstat -ano | findstr :443
   taskkill /PID [프로세스ID] /F

   # macOS/Linux
   lsof -i :443
   kill -9 [프로세스ID]
   ```

2. 패키지 설치 오류 시:
   ```bash
   pip install --upgrade pip setuptools wheel
   pip install -r requirements.txt
   ```

3. 데이터베이스 초기화:
   ```bash
   # 기존 데이터베이스 삭제
   rm market.db
   # 새로 실행하면 자동으로 생성됨
   ```

## 개발 모드 vs 운영 모드

### 개발 모드
```bash
# Windows
set FLASK_ENV=development
set FLASK_DEBUG=1

# macOS/Linux
export FLASK_ENV=development
export FLASK_DEBUG=1
```

### 운영 모드
```bash
# Windows
set FLASK_ENV=production
set FLASK_DEBUG=0

# macOS/Linux
export FLASK_ENV=production
export FLASK_DEBUG=0
```

## 주의사항

1. 실제 운영 환경에서는 반드시 다음 사항을 확인하세요:
   - 강력한 비밀키 사용
   - SSL/TLS 인증서 설정
   - 환경 변수를 통한 중요 설정 관리
   - 디버그 모드 비활성화
   - 적절한 로깅 설정

2. 보안 설정:
   - 모든 비밀키와 인증서는 안전하게 관리
   - 환경 변수 사용
   - 정기적인 업데이트 수행

## 라이선스

이 프로젝트는 MIT 라이선스를 따릅니다.
