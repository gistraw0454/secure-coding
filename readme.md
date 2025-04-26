# 안전한 중고거래 플랫폼

안전하고 신뢰할 수 있는 중고거래 경험을 제공하는 웹 플랫폼입니다.

## 주요 기능

### 🔒 보안 기능
- 사용자 인증 및 권한 관리
- CSRF 보호
- XSS 방지
- SQL Injection 방지
- 입력값 검증 및 살균
- 세션 관리
- 비밀번호 해시화 (bcrypt)
- 로그인 시도 제한

### 👥 사용자 기능
- 회원가입/로그인
- 프로필 관리
  - 개인정보 수정
  - 비밀번호 변경
- 상품 관리
  - 상품 등록/수정/삭제
  - 상품 상태 관리
- 지갑 기능
  - 잔액 확인
  - 송금
  - 거래 내역 조회

### 💬 채팅 기능
- 1:1 채팅
- 전체 채팅
- 실시간 메시지 전송
- 채팅방 관리

### 👮 관리자 기능
- 사용자 관리
  - 계정 활성화/비활성화
  - 경고 시스템
- 상품 관리
  - 상품 상태 관리
  - 부적절한 상품 관리
- 신고 시스템
  - 사용자 신고 처리
  - 상품 신고 처리

## API 명세

### 프로필 관련 (/profile)
- GET /profile
  - 프로필 페이지 조회
  - 사용자 정보, 등록 상품 목록 표시
  - 로그인 필요

- POST /profile/update
  - 프로필 정보 수정 (자기소개)
  - 로그인 필요

- POST /profile/password
  - 비밀번호 변경
  - 현재 비밀번호 확인 후 변경
  - 로그인 필요

### 상품 관련 (/product)
- GET /products
  - 상품 목록 조회
  - 필터: 카테고리, 가격, 검색어
  - 정렬: 최신순, 가격순

- POST /product/new
  - 상품 등록
  - 제목, 설명, 가격, 카테고리 입력
  - 로그인 필요

- GET /product/<id>
  - 상품 상세 조회

- POST /product/<id>/edit
  - 상품 정보 수정
  - 판매자만 가능

- POST /product/<id>/toggle
  - 상품 상태 변경
  - 판매자만 가능

### 채팅 관련 (/chat)
- GET /chat/rooms
  - 채팅방 목록 조회
  - 로그인 필요

- GET /chat/room/<id>
  - 채팅방 조회
  - 참여자만 접근 가능

- POST /chat/create/<product_id>
  - 채팅방 생성
  - 자신의 상품에는 생성 불가

- WebSocket /chat
  - 실시간 채팅
  - join/leave/message 이벤트

### 거래 관련 (/wallet)
- GET /wallet
  - 지갑 조회
  - 잔액 및 거래 내역
  - 로그인 필요

- POST /transfer
  - 송금 기능
  - 분당 10회 제한
  - 로그인 필요

### 관리자 기능 (/admin)
- GET /admin
  - 관리자 대시보드
  - 사용자/상품/신고 관리
  - 관리자 권한 필요

- POST /admin/user/<id>/status
  - 사용자 상태 관리
  - 자기 자신은 정지 불가
  - 관리자 권한 필요

- POST /admin/product/<id>/status
  - 상품 상태 관리
  - 정지된 사용자의 상품은 활성화 불가
  - 관리자 권한 필요

### 신고 기능
- POST /report_user/<id>
  - 사용자 신고
  - 24시간 내 동일 대상 신고 불가
  - 24시간 내 최대 5회

- POST /report_product/<id>
  - 상품 신고
  - 자신의 상품 신고 불가
  - 24시간 내 동일 상품 신고 불가

## 시작하기

### 시스템 요구사항
- Python 3.8 이상
- SQLite3
- Git

### 설치 방법
1. 저장소 클론
   ```bash
   git clone [repository-url]
   cd secure-coding
   ```

2. 가상환경 생성 및 활성화
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   venv\Scripts\activate     # Windows
   ```

3. 패키지 설치
   ```bash
   pip install -r requirements.txt
   ```

### 실행 방법
1. 데이터베이스 초기화
   ```bash
   python init_db.py
   ```

2. 서버 실행
   ```bash
   python app.py
   ```

3. 웹 브라우저에서 접속
   ```
   http://localhost:5000
   ```

## 데이터베이스 구조

### User 테이블
- id (TEXT): 사용자 고유 ID
- username (TEXT): 사용자명
- password (TEXT): 해시화된 비밀번호
- bio (TEXT): 자기소개
- status (TEXT): 계정 상태
- role (TEXT): 권한
- created_at (TIMESTAMP): 가입일
- warning_count (INTEGER): 경고 횟수

### Product 테이블
- id (TEXT): 상품 고유 ID
- title (TEXT): 상품명
- description (TEXT): 상품 설명
- price (TEXT): 가격
- seller_id (TEXT): 판매자 ID
- status (TEXT): 상품 상태
- category (TEXT): 카테고리
- created_at (TIMESTAMP): 등록일
- report_count (INTEGER): 신고 횟수

### Wallet 테이블
- user_id (TEXT): 사용자 ID
- balance (INTEGER): 잔액
- updated_at (TIMESTAMP): 최종 수정일

### Transaction 테이블
- id (TEXT): 거래 고유 ID
- sender_id (TEXT): 송금자 ID
- receiver_id (TEXT): 수신자 ID
- amount (INTEGER): 금액
- description (TEXT): 거래 설명
- created_at (TIMESTAMP): 거래일

### Chat 테이블
- id (TEXT): 채팅방 ID
- product_id (TEXT): 상품 ID
- buyer_id (TEXT): 구매자 ID
- seller_id (TEXT): 판매자 ID
- status (TEXT): 채팅방 상태
- created_at (TIMESTAMP): 생성일

## 라이선스
이 프로젝트는 MIT 라이선스를 따릅니다.
