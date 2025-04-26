# 보안 중고거래 플랫폼

안전한 중고거래를 위한 웹 플랫폼입니다. 사용자 인증, 상품 관리, 실시간 채팅, 안전 거래 기능을 제공합니다.

## 시스템 요구사항

- Python 3.8 이상
- SQLite3
- 웹 브라우저 (Chrome, Firefox, Safari 등)

## 설치 방법

1. 저장소 클론
```bash
git clone [repository-url]
cd secure-coding
```

2. 가상환경 생성 및 활성화
```bash
python -m venv venv
# Windows
venv\Scripts\activate
# Linux/Mac
source venv/bin/activate
```

3. 필요한 패키지 설치
```bash
pip install -r requirements.txt
```

## 서버 실행 방법

1. 데이터베이스 초기화
```bash
python init_db.py
```

2. 서버 실행
```bash
python app.py
```

서버는 기본적으로 http://localhost:5000 에서 실행됩니다.

## 주요 기능

### 사용자 관리
- 회원가입/로그인
- 프로필 관리
- 지갑 기능 (기본 10,000원 지급)
- 사용자 신고 기능

### 상품 관리
- 상품 등록/수정/삭제
- 카테고리별 상품 조회
- 상품 검색
- 상품 신고 기능

### 채팅 기능
- 1:1 채팅
- 전체 채팅
- 실시간 메시지 전송

### 거래 시스템
- 안전 거래 기능
- 거래 내역 조회
- 지갑 잔액 관리
- 송금 기능

### 관리자 기능
- 사용자 관리 (활성화/정지)
- 상품 관리 (활성화/비활성화)
- 신고 내역 관리
- 시스템 모니터링

## 보안 기능

### 사용자 인증
- 비밀번호 해시화 (werkzeug.security)
- 세션 관리
- CSRF 보호
- 로그인 시도 제한

### 입력 검증
- XSS 방지
- SQL 인젝션 방지
- 입력값 살균 처리

### 접근 제어
- 권한 기반 접근 제어
- 관리자 전용 기능 보호
- API 엔드포인트 보호

### 데이터 보안
- 데이터베이스 보안 설정
- 민감 정보 보호
- 에러 처리 및 로깅

## API 엔드포인트

### 사용자 관련
- POST /register : 회원가입
- POST /login : 로그인
- GET /logout : 로그아웃
- GET /profile : 프로필 조회
- POST /profile : 프로필 수정

### 상품 관련
- GET /products : 상품 목록 조회
- POST /product/new : 상품 등록
- GET /product/<id> : 상품 상세 조회
- POST /product/<id>/edit : 상품 수정
- POST /report_product/<id> : 상품 신고

### 채팅 관련
- GET /chat/rooms : 채팅방 목록
- GET /chat/room/<id> : 채팅방 입장
- POST /chat/create/<product_id> : 채팅방 생성
- WebSocket /chat : 실시간 채팅

### 거래 관련
- GET /wallet : 지갑 조회
- POST /transfer : 송금
- GET /transactions : 거래 내역 조회

### 관리자 관련
- GET /admin : 관리자 대시보드
- POST /admin/user/<id>/status : 사용자 상태 변경
- POST /admin/product/<id>/status : 상품 상태 변경

## 데이터베이스 스키마

### user 테이블
- id (TEXT, PK)
- username (TEXT, UNIQUE)
- password (TEXT)
- status (TEXT)
- role (TEXT)
- warning_count (INTEGER)
- created_at (TIMESTAMP)

### product 테이블
- id (TEXT, PK)
- title (TEXT)
- description (TEXT)
- price (TEXT)
- seller_id (TEXT, FK)
- status (TEXT)
- category (TEXT)
- report_count (INTEGER)
- created_at (TIMESTAMP)

### wallet 테이블
- user_id (TEXT, PK, FK)
- balance (INTEGER)
- updated_at (TIMESTAMP)

### money_transaction 테이블
- id (TEXT, PK)
- sender_id (TEXT, FK)
- receiver_id (TEXT, FK)
- amount (INTEGER)
- description (TEXT)
- created_at (TIMESTAMP)

### chat_room 테이블
- id (TEXT, PK)
- product_id (TEXT, FK)
- buyer_id (TEXT, FK)
- seller_id (TEXT, FK)
- status (TEXT)
- created_at (TIMESTAMP)

### report 테이블
- id (TEXT, PK)
- reporter_id (TEXT, FK)
- target_id (TEXT)
- target_type (TEXT)
- reason (TEXT)
- status (TEXT)
- created_at (TIMESTAMP)

## 라이선스

이 프로젝트는 MIT 라이선스를 따릅니다.
