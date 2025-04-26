import sqlite3
import uuid
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, jsonify
from flask_socketio import SocketIO, send, join_room, leave_room, emit
import re
import html
import bcrypt
from flask_wtf.csrf import CSRFProtect
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import time
import os
from werkzeug.security import generate_password_hash

app = Flask(__name__)
app.config.from_object('config.Config')
app.config['SECRET_KEY'] = 'your-secret-key-here'  # 실제 운영 환경에서는 환경 변수로 관리
app.config['SESSION_COOKIE_SECURE'] = True  # HTTPS에서만 쿠키 전송
app.config['SESSION_COOKIE_HTTPONLY'] = True  # JavaScript에서 쿠키 접근 불가
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF 방지
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # 세션 만료 시간 설정
DATABASE = 'market.db'
socketio = SocketIO(app)
csrf = CSRFProtect(app)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# 읽기 전용 작업에 대한 데코레이터
def readonly_operation(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        g._database = get_readonly_db()
        try:
            return f(*args, **kwargs)
        finally:
            g._database = None
    return decorated_function

# 데이터베이스 연결 관리: 요청마다 연결 생성 후 사용, 종료 시 close
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # 결과를 dict처럼 사용하기 위함
        
        # 기본 보안 설정
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA secure_delete=ON")
    return db

def get_readonly_db():
    db = getattr(g, '_readonly_database', None)
    if db is None:
        db = g._readonly_database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA query_only=ON")
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()
    
    readonly_db = getattr(g, '_readonly_database', None)
    if readonly_db is not None:
        readonly_db.close()

# 테이블 생성 (최초 실행 시에만)
def init_db():
    with app.app_context():
        # 데이터베이스 생성
        db = sqlite3.connect(DATABASE)
        cursor = db.cursor()
        
        # 데이터베이스 권한 설정
        cursor.execute("PRAGMA journal_mode=WAL")  # Write-Ahead Logging 모드 활성화
        cursor.execute("PRAGMA foreign_keys=ON")   # 외래 키 제약 조건 활성화
        cursor.execute("PRAGMA secure_delete=ON")  # 안전한 삭제 모드 활성화
        
        # role 컬럼 추가 (없는 경우에만)
        try:
            cursor.execute("ALTER TABLE user ADD COLUMN role TEXT DEFAULT 'user'")
            print('role 컬럼이 추가되었습니다.')
        except sqlite3.OperationalError:
            print('role 컬럼이 이미 존재합니다.')
        
        # admin 계정 업그레이드
        cursor.execute("UPDATE user SET role = 'admin' WHERE username = 'admin'")
        if cursor.rowcount > 0:
            print('admin 계정이 관리자 권한으로 업그레이드되었습니다.')
            db.commit()
        
        # 읽기 전용 트랜잭션 설정
        def get_readonly_db():
            db = sqlite3.connect(DATABASE)
            db.execute("PRAGMA query_only=ON")  # 읽기 전용 모드
            return db
        
        # 사용자 테이블 수정
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT,
                status TEXT DEFAULT 'active',
                role TEXT DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                warning_count INTEGER DEFAULT 0
            )
        """)
        # 상품 테이블 수정
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL,
                status TEXT DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                category TEXT,
                report_count INTEGER DEFAULT 0,
                FOREIGN KEY (seller_id) REFERENCES user (id)
            )
        """)
        # 신고 테이블 수정
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                target_type TEXT NOT NULL,
                reason TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (reporter_id) REFERENCES user (id)
            )
        """)
        # 채팅방 테이블 추가
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chat_room (
                id TEXT PRIMARY KEY,
                product_id TEXT NOT NULL,
                buyer_id TEXT NOT NULL,
                seller_id TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'active',
                FOREIGN KEY (product_id) REFERENCES product (id),
                FOREIGN KEY (buyer_id) REFERENCES user (id),
                FOREIGN KEY (seller_id) REFERENCES user (id)
            )
        """)
        # 채팅 메시지 테이블 추가
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chat_message (
                id TEXT PRIMARY KEY,
                room_id TEXT NOT NULL,
                sender_id TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (room_id) REFERENCES chat_room (id),
                FOREIGN KEY (sender_id) REFERENCES user (id)
            )
        """)
        # 전체 채팅 메시지 테이블 추가
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS global_chat_message (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sender_id) REFERENCES user (id)
            )
        """)
        # 지갑 테이블 추가
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS wallet (
                user_id TEXT PRIMARY KEY,
                balance INTEGER DEFAULT 0,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES user (id)
            )
        """)
        # 거래 내역 테이블 추가
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS money_transaction (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                amount INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                description TEXT,
                FOREIGN KEY (sender_id) REFERENCES user (id),
                FOREIGN KEY (receiver_id) REFERENCES user (id)
            )
        """)
        # 로그인 시도 테이블 추가
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS login_attempts (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                success BOOLEAN NOT NULL
            )
        """)
        db.commit()
        return db

def validate_input(username, password):
    # XSS 방지를 위한 특수문자 이스케이프
    username = html.escape(username)
    
    # 아이디 검증: 알파벳, 숫자, 언더스코어만 허용 (4-20자)
    if not re.match(r'^[a-zA-Z0-9_]{4,20}$', username):
        return False, "아이디는 4-20자의 영문, 숫자, 언더스코어만 사용할 수 있습니다."
    
    # 비밀번호 검증: 최소 8자, 영문/숫자/특수문자 조합
    if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$', password):
        return False, "비밀번호는 8자 이상의 영문, 숫자, 특수문자 조합이어야 합니다."
    
    return True, None

# 기본 라우트
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# 회원가입
@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("3 per minute")
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # 입력값 검증
        is_valid, error_message = validate_input(username, password)
        if not is_valid:
            flash(error_message)
            return redirect(url_for('register'))
        
        db = get_db()
        cursor = db.cursor()
        
        # 중복 사용자 체크
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))
            
        # bcrypt를 사용한 비밀번호 해싱
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        
        user_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
            (user_id, username, hashed_password)
        )
        
        # 지갑 생성 (초기 잔액 10000원)
        cursor.execute(
            "INSERT INTO wallet (user_id, balance) VALUES (?, ?)",
            (user_id, 10000)
        )
        
        db.commit()
        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))
        
    return render_template('register.html')

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 세션 존재 여부 확인
        if 'user_id' not in session:
            flash('로그인이 필요합니다.')
            return redirect(url_for('login'))
        
        # 세션 만료 시간 확인
        if 'last_activity' in session:
            inactive_time = datetime.now() - datetime.fromisoformat(session['last_activity'])
            if inactive_time > timedelta(minutes=30):
                session.clear()
                flash('세션이 만료되었습니다. 다시 로그인해주세요.')
                return redirect(url_for('login'))
        
        # 마지막 활동 시간 업데이트
        session['last_activity'] = datetime.now().isoformat()
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('로그인이 필요합니다.')
            return redirect(url_for('login'))
            
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT role FROM user WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
        
        if not user or user['role'] != 'admin':
            flash('관리자 권한이 필요합니다.')
            return redirect(url_for('dashboard'))
            
        return f(*args, **kwargs)
    return decorated_function

# 로그인
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        ip_address = request.remote_addr
        
        # 로그인 시도 횟수 확인
        attempt_count = check_login_attempts(username, ip_address)
        if attempt_count >= 5:
            flash('너무 많은 로그인 시도가 있었습니다. 10분 후에 다시 시도해주세요.')
            return redirect(url_for('login'))
        
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        login_success = False
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            if user['status'] == 'suspended':
                flash('계정이 정지되었습니다. 관리자에게 문의하세요.')
            else:
                session['user_id'] = user['id']
                session['last_activity'] = datetime.now().isoformat()
                session.permanent = True
                
                # 마지막 로그인 시간 업데이트
                cursor.execute(
                    "UPDATE user SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
                    (user['id'],)
                )
                db.commit()
                
                login_success = True
                flash('로그인 성공!')
                
                # 성공한 로그인 기록
                add_login_attempt(username, ip_address, True)
                return redirect(url_for('dashboard'))
        
        # 실패한 로그인 기록
        add_login_attempt(username, ip_address, False)
        
        if not login_success:
            # 실패 시 지연 시간 추가 (시도 횟수에 따라 증가)
            time.sleep(min(attempt_count * 2, 10))
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))
            
    return render_template('login.html')

# 로그아웃
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

# 대시보드: 사용자 정보와 전체 상품 리스트 표시
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    # 현재 사용자 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    # 모든 상품 조회
    cursor.execute("SELECT * FROM product")
    all_products = cursor.fetchall()
    return render_template('dashboard.html', products=all_products, user=current_user)

def sanitize_input(text):
    if text is None:
        return None
    return html.escape(str(text))

@app.template_filter('safe_markdown')
def safe_markdown(text):
    if text is None:
        return ''
    # HTML 태그 이스케이프
    text = html.escape(str(text))
    # 줄바꿈만 허용
    text = text.replace('\n', '<br>')
    return text

# 프로필 페이지: bio 업데이트 가능
@app.route('/profile', methods=['GET'])
@login_required
def profile():
    db = get_db()
    cursor = db.cursor()
    
    # 사용자 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    
    # 사용자의 상품 목록 조회
    cursor.execute("""
        SELECT * FROM product 
        WHERE seller_id = ? 
        ORDER BY created_at DESC
    """, (session['user_id'],))
    products = cursor.fetchall()
    
    return render_template('profile.html', user=user, products=products)

@app.route('/profile/update', methods=['POST'])
@login_required
def update_profile():
    bio = sanitize_input(request.form.get('bio', '').strip())
    
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            "UPDATE user SET bio = ? WHERE id = ?",
            (bio, session['user_id'])
        )
        db.commit()
        flash('프로필이 업데이트되었습니다.', 'success')
    except Exception as e:
        db.rollback()
        app.logger.error(f'프로필 업데이트 중 오류 발생: {str(e)}')
        flash('프로필 업데이트 중 오류가 발생했습니다.', 'error')
    
    return redirect(url_for('profile'))

@app.route('/profile/password', methods=['POST'])
@login_required
def update_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    if not all([current_password, new_password, confirm_password]):
        flash('모든 필드를 입력해주세요.', 'error')
        return redirect(url_for('profile'))
    
    if new_password != confirm_password:
        flash('새 비밀번호가 일치하지 않습니다.', 'error')
        return redirect(url_for('profile'))
    
    # 비밀번호 복잡도 검증
    if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$', new_password):
        flash('비밀번호는 8자 이상의 영문, 숫자, 특수문자 조합이어야 합니다.', 'error')
        return redirect(url_for('profile'))
    
    try:
        db = get_db()
        cursor = db.cursor()
        
        # 현재 비밀번호 확인
        cursor.execute("SELECT password FROM user WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
        
        if not bcrypt.checkpw(current_password.encode('utf-8'), user['password']):
            flash('현재 비밀번호가 올바르지 않습니다.', 'error')
            return redirect(url_for('profile'))
        
        # 새 비밀번호 해시화 및 업데이트
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), salt)
        
        cursor.execute(
            "UPDATE user SET password = ? WHERE id = ?",
            (hashed_password, session['user_id'])
        )
        db.commit()
        flash('비밀번호가 변경되었습니다.', 'success')
        
    except Exception as e:
        db.rollback()
        app.logger.error(f'비밀번호 변경 중 오류 발생: {str(e)}')
        flash('비밀번호 변경 중 오류가 발생했습니다.', 'error')
    
    return redirect(url_for('profile'))

@app.route('/product/<product_id>/toggle', methods=['POST'])
@login_required
def toggle_product_status(product_id):
    try:
        db = get_db()
        cursor = db.cursor()
        
        # 상품 소유자 확인
        cursor.execute("""
            SELECT status, seller_id 
            FROM product 
            WHERE id = ?
        """, (product_id,))
        product = cursor.fetchone()
        
        if not product:
            flash('상품을 찾을 수 없습니다.', 'error')
            return redirect(url_for('profile'))
        
        if product['seller_id'] != session['user_id']:
            flash('권한이 없습니다.', 'error')
            return redirect(url_for('profile'))
        
        # 상태 토글
        new_status = 'inactive' if product['status'] == 'active' else 'active'
        cursor.execute(
            "UPDATE product SET status = ? WHERE id = ?",
            (new_status, product_id)
        )
        
        db.commit()
        status_str = '판매중지' if new_status == 'inactive' else '판매시작'
        flash(f'상품이 {status_str}되었습니다.', 'success')
        
    except Exception as e:
        db.rollback()
        app.logger.error(f'상품 상태 변경 중 오류 발생: {str(e)}')
        flash('상태 변경 중 오류가 발생했습니다.', 'error')
    
    return redirect(url_for('profile'))

# 상품 등록
@app.route('/product/new', methods=['GET', 'POST'])
@login_required
def new_product():
    if request.method == 'POST':
        title = sanitize_input(request.form.get('title', '').strip())
        description = sanitize_input(request.form.get('description', '').strip())
        price = request.form.get('price', '').strip()
        category = request.form.get('category', '').strip()

        # 입력값 검증
        if not all([title, description, price, category]):
            flash('모든 필드를 입력해주세요.')
            return redirect(url_for('new_product'))

        # 가격 유효성 검사
        try:
            price_value = int(price)
            if price_value < 0:
                flash('가격은 0 이상이어야 합니다.')
                return redirect(url_for('new_product'))
        except ValueError:
            flash('올바른 가격을 입력해주세요.')
            return redirect(url_for('new_product'))

        # XSS 방지를 위한 추가 검증
        if len(title) > 100 or len(description) > 1000:
            flash('제목 또는 설명이 너무 깁니다.')
            return redirect(url_for('new_product'))

        # 허용된 카테고리 검증
        allowed_categories = ['전자기기', '의류', '도서', '생활용품', '기타']
        if category not in allowed_categories:
            flash('올바른 카테고리를 선택해주세요.')
            return redirect(url_for('new_product'))

        try:
            db = get_db()
            cursor = db.cursor()
            product_id = str(uuid.uuid4())
            cursor.execute(
                "INSERT INTO product (id, title, description, price, seller_id, category) VALUES (?, ?, ?, ?, ?, ?)",
                (product_id, title, description, price, session['user_id'], category)
            )
            db.commit()
            flash('상품이 등록되었습니다.')
            return redirect(url_for('view_product', product_id=product_id))
        except sqlite3.Error as e:
            db.rollback()
            flash('상품 등록 중 오류가 발생했습니다. 다시 시도해주세요.')
            return redirect(url_for('new_product'))

    return render_template('product/new.html')

# 상품 목록 조회 (필터링 기능 추가)
@app.route('/products')
def list_products():
    category = request.args.get('category')
    min_price = request.args.get('min_price')
    max_price = request.args.get('max_price')
    search_query = request.args.get('query')
    
    db = get_db()
    cursor = db.cursor()
    
    query = """
        SELECT p.*, u.username as seller_name 
        FROM product p
        JOIN user u ON p.seller_id = u.id
        WHERE p.status = 'active'
    """
    params = []
    
    if category:
        query += " AND p.category = ?"
        params.append(category)
    
    if min_price:
        query += " AND CAST(REPLACE(p.price, ',', '') AS INTEGER) >= ?"
        params.append(min_price)
        
    if max_price:
        query += " AND CAST(REPLACE(p.price, ',', '') AS INTEGER) <= ?"
        params.append(max_price)
        
    if search_query:
        query += " AND (p.title LIKE ? OR p.description LIKE ?)"
        search_pattern = f"%{search_query}%"
        params.extend([search_pattern, search_pattern])
        
    query += " ORDER BY p.created_at DESC"
    
    cursor.execute(query, params)
    products = cursor.fetchall()
    
    # 카테고리 목록 조회
    cursor.execute("SELECT DISTINCT category FROM product WHERE category IS NOT NULL")
    categories = [row['category'] for row in cursor.fetchall()]
    
    return render_template('products.html', products=products, categories=categories)

# 상품 상세 조회
@app.route('/product/<product_id>')
@readonly_operation
def view_product(product_id):
    db = get_db()  # 이 db는 읽기 전용
    cursor = db.cursor()
    cursor.execute("""
        SELECT p.*, u.username as seller_name, u.status as seller_status
        FROM product p
        JOIN user u ON p.seller_id = u.id
        WHERE p.id = ?
    """, (product_id,))
    product = cursor.fetchone()
    
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
        
    if product['status'] != 'active':
        flash('비활성화된 상품입니다.')
        return redirect(url_for('dashboard'))
        
    # 판매자가 정지 상태인 경우
    if product['seller_status'] != 'active':
        flash('이 상품의 판매자가 현재 정지 상태입니다.')
        return redirect(url_for('dashboard'))
    
    return render_template('view_product.html', product=product)

# 신고하기
@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        target_id = request.form['target_id']
        reason = request.form['reason']
        db = get_db()
        cursor = db.cursor()
        report_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO report (id, reporter_id, target_id, reason) VALUES (?, ?, ?, ?)",
            (report_id, session['user_id'], target_id, reason)
        )
        db.commit()
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('report.html')

def check_report_limit(reporter_id, target_id):
    db = get_db()
    cursor = db.cursor()
    
    # 동일 대상에 대한 24시간 내 신고 횟수 확인
    cursor.execute("""
        SELECT COUNT(*) as report_count
        FROM report
        WHERE reporter_id = ?
        AND target_id = ?
        AND created_at > datetime('now', '-24 hours')
    """, (reporter_id, target_id))
    
    same_target_count = cursor.fetchone()['report_count']
    if same_target_count > 0:
        return False, "동일한 대상에 대해 24시간 내 한 번만 신고할 수 있습니다."
    
    # 사용자의 24시간 내 총 신고 횟수 확인
    cursor.execute("""
        SELECT COUNT(*) as total_count
        FROM report
        WHERE reporter_id = ?
        AND created_at > datetime('now', '-24 hours')
    """, (reporter_id,))
    
    total_count = cursor.fetchone()['total_count']
    if total_count >= 5:
        return False, "24시간 내 최대 5회까지만 신고할 수 있습니다."
    
    return True, None

# 사용자 신고
@app.route('/report_user/<user_id>', methods=['POST'])
@login_required
def report_user(user_id):
    reason = request.form.get('reason')
    if not reason:
        flash('신고 사유를 입력해주세요.')
        return redirect(url_for('view_user', user_id=user_id))
    
    # 자기 자신 신고 방지
    if user_id == session['user_id']:
        flash('자기 자신을 신고할 수 없습니다.')
        return redirect(url_for('view_user', user_id=user_id))
    
    # 신고 제한 확인
    can_report, message = check_report_limit(session['user_id'], user_id)
    if not can_report:
        flash(message)
        return redirect(url_for('view_user', user_id=user_id))
    
    db = get_db()
    cursor = db.cursor()
    
    # 신고 기록 추가
    report_id = str(uuid.uuid4())
    cursor.execute(
        "INSERT INTO report (id, reporter_id, target_id, target_type, reason, status) VALUES (?, ?, ?, ?, ?, ?)",
        (report_id, session['user_id'], user_id, 'user', reason, 'pending')
    )
    
    # 신고 횟수 증가 및 자동 정지 처리
    cursor.execute("UPDATE user SET warning_count = warning_count + 1 WHERE id = ?", (user_id,))
    cursor.execute("SELECT warning_count FROM user WHERE id = ?", (user_id,))
    warning_count = cursor.fetchone()['warning_count']
    
    if warning_count >= 3:
        cursor.execute("UPDATE user SET status = 'suspended' WHERE id = ?", (user_id,))
    
    db.commit()
    flash('신고가 접수되었습니다.')
    return redirect(url_for('view_user', user_id=user_id))

# 관리자용: 사용자 상태 관리
@app.route('/admin')
@login_required
def admin_dashboard():
    # 관리자 권한 확인
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT role FROM user WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    
    if not user or user['role'] != 'admin':
        flash('관리자 권한이 필요합니다.')
        return redirect(url_for('dashboard'))
    
    # 사용자 목록 조회
    cursor.execute("""
        SELECT u.*, w.balance
        FROM user u
        LEFT JOIN wallet w ON u.id = w.user_id
        ORDER BY u.created_at DESC
    """)
    users = cursor.fetchall()
    
    # 상품 목록 조회
    cursor.execute("""
        SELECT p.*, u.username as seller_name
        FROM product p
        JOIN user u ON p.seller_id = u.id
        ORDER BY p.created_at DESC
    """)
    products = cursor.fetchall()
    
    # 신고 목록 조회
    cursor.execute("""
        SELECT r.*, 
               ru.username as reporter_name,
               CASE 
                   WHEN r.target_type = 'user' THEN tu.username
                   WHEN r.target_type = 'product' THEN tp.title
               END as target_name
        FROM report r
        JOIN user ru ON r.reporter_id = ru.id
        LEFT JOIN user tu ON r.target_type = 'user' AND r.target_id = tu.id
        LEFT JOIN product tp ON r.target_type = 'product' AND r.target_id = tp.id
        ORDER BY r.created_at DESC
    """)
    reports = cursor.fetchall()
    
    return render_template('admin.html', users=users, products=products, reports=reports)

@app.route('/admin/user/<user_id>/status', methods=['POST'])
@login_required
@admin_required
def update_user_status(user_id):
    new_status = request.form.get('status')
    if new_status not in ['active', 'suspended']:
        flash('잘못된 상태값입니다.', 'error')
        return redirect(url_for('admin_dashboard'))
    
    try:
        db = get_db()
        cursor = db.cursor()
        
        # 관리자 자신을 정지시키는 것을 방지
        if user_id == session['user_id']:
            flash('자신의 계정은 정지할 수 없습니다.', 'error')
            return redirect(url_for('admin_dashboard'))
        
        # 상태 변경
        cursor.execute(
            "UPDATE user SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (new_status, user_id)
        )
        
        if cursor.rowcount == 0:
            flash('사용자를 찾을 수 없습니다.', 'error')
        else:
            status_str = '정지' if new_status == 'suspended' else '활성화'
            flash(f'사용자 상태가 {status_str}되었습니다.', 'success')
            
            # 정지된 경우 해당 사용자의 상품도 모두 비활성화
            if new_status == 'suspended':
                cursor.execute(
                    "UPDATE product SET status = 'inactive' WHERE seller_id = ?",
                    (user_id,)
                )
        
        db.commit()
    except Exception as e:
        db.rollback()
        app.logger.error(f'사용자 상태 변경 중 오류 발생: {str(e)}')
        flash('상태 변경 중 오류가 발생했습니다.', 'error')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/product/<product_id>/status', methods=['POST'])
@login_required
@admin_required
def update_product_status(product_id):
    new_status = request.form.get('status')
    if new_status not in ['active', 'inactive']:
        flash('잘못된 상태값입니다.', 'error')
        return redirect(url_for('admin_dashboard'))
    
    try:
        db = get_db()
        cursor = db.cursor()
        
        # 상품 정보 조회
        cursor.execute("""
            SELECT p.*, u.status as seller_status 
            FROM product p 
            JOIN user u ON p.seller_id = u.id 
            WHERE p.id = ?
        """, (product_id,))
        product = cursor.fetchone()
        
        if not product:
            flash('상품을 찾을 수 없습니다.', 'error')
            return redirect(url_for('admin_dashboard'))
        
        # 판매자가 정지 상태인 경우 상품 활성화 방지
        if new_status == 'active' and product['seller_status'] == 'suspended':
            flash('정지된 사용자의 상품은 활성화할 수 없습니다.', 'error')
            return redirect(url_for('admin_dashboard'))
        
        # 상태 변경
        cursor.execute(
            "UPDATE product SET status = ? WHERE id = ?",
            (new_status, product_id)
        )
        
        status_str = '비활성화' if new_status == 'inactive' else '활성화'
        flash(f'상품이 {status_str}되었습니다.', 'success')
        
        db.commit()
    except Exception as e:
        db.rollback()
        app.logger.error(f'상품 상태 변경 중 오류 발생: {str(e)}')
        flash('상태 변경 중 오류가 발생했습니다.', 'error')
    
    return redirect(url_for('admin_dashboard'))

# 상품 신고
@app.route('/report_product/<product_id>', methods=['POST'])
@login_required
def report_product(product_id):
    reason = request.form.get('reason')
    if not reason:
        flash('신고 사유를 입력해주세요.')
        return redirect(url_for('view_product', product_id=product_id))
    
    # 자신의 상품 신고 방지
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT seller_id FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    
    if product['seller_id'] == session['user_id']:
        flash('자신의 상품을 신고할 수 없습니다.')
        return redirect(url_for('view_product', product_id=product_id))
    
    # 신고 제한 확인
    can_report, message = check_report_limit(session['user_id'], product_id)
    if not can_report:
        flash(message)
        return redirect(url_for('view_product', product_id=product_id))
    
    # 신고 기록 추가
    report_id = str(uuid.uuid4())
    cursor.execute(
        "INSERT INTO report (id, reporter_id, target_id, target_type, reason, status) VALUES (?, ?, ?, ?, ?, ?)",
        (report_id, session['user_id'], product_id, 'product', reason, 'pending')
    )
    
    # 상품 신고 횟수 증가 및 자동 비활성화
    cursor.execute("UPDATE product SET report_count = report_count + 1 WHERE id = ?", (product_id,))
    cursor.execute("SELECT report_count FROM product WHERE id = ?", (product_id,))
    report_count = cursor.fetchone()['report_count']
    
    if report_count >= 3:
        cursor.execute("UPDATE product SET status = 'inactive' WHERE id = ?", (product_id,))
    
    db.commit()
    flash('상품 신고가 접수되었습니다.')
    return redirect(url_for('view_product', product_id=product_id))

# 1대1 채팅방 생성
@app.route('/chat/create/<product_id>', methods=['POST'])
@login_required
def create_chat_room(product_id):
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))
        
    db = get_db()
    cursor = db.cursor()
    
    # 상품 정보 확인
    cursor.execute("SELECT seller_id FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('존재하지 않는 상품입니다.')
        return redirect(url_for('dashboard'))
        
    # 판매자와 동일인인 경우 채팅방 생성 불가
    if product['seller_id'] == session['user_id']:
        flash('자신의 상품에는 채팅방을 생성할 수 없습니다.')
        return redirect(url_for('view_product', product_id=product_id))
        
    # 이미 존재하는 채팅방 확인
    cursor.execute("""
        SELECT id FROM chat_room 
        WHERE product_id = ? AND buyer_id = ? AND seller_id = ?
    """, (product_id, session['user_id'], product['seller_id']))
    
    existing_room = cursor.fetchone()
    if existing_room:
        return redirect(url_for('view_chat_room', room_id=existing_room['id']))
        
    # 새 채팅방 생성
    room_id = str(uuid.uuid4())
    cursor.execute("""
        INSERT INTO chat_room (id, product_id, buyer_id, seller_id)
        VALUES (?, ?, ?, ?)
    """, (room_id, product_id, session['user_id'], product['seller_id']))
    
    db.commit()
    flash('채팅방이 생성되었습니다.')
    return redirect(url_for('view_chat_room', room_id=room_id))

# 채팅방 보기
@app.route('/chat/room/<room_id>')
@login_required
def view_chat_room(room_id):
    db = get_db()
    cursor = db.cursor()
    
    # 채팅방 정보 조회
    cursor.execute("""
        SELECT cr.*, p.title as product_title, p.seller_id,
               s.username as seller_name, b.username as buyer_name
        FROM chat_room cr
        JOIN product p ON cr.product_id = p.id
        JOIN user s ON p.seller_id = s.id
        JOIN user b ON cr.buyer_id = b.id
        WHERE cr.id = ?
    """, (room_id,))
    
    room = cursor.fetchone()
    if not room:
        flash('존재하지 않는 채팅방입니다.')
        return redirect(url_for('dashboard'))
    
    # 채팅방 접근 권한 확인
    if room['buyer_id'] != session['user_id'] and room['seller_id'] != session['user_id']:
        flash('접근 권한이 없습니다.')
        return redirect(url_for('dashboard'))
    
    # 채팅 메시지 조회
    cursor.execute("""
        SELECT cm.*, u.username as sender_name
        FROM chat_message cm
        JOIN user u ON cm.sender_id = u.id
        WHERE cm.room_id = ?
        ORDER BY cm.created_at ASC
    """, (room_id,))
    
    messages = cursor.fetchall()
    
    return render_template('chat/room.html',
                         room=room,
                         messages=messages,
                         current_user_id=session['user_id'])

# 채팅방 목록 조회
@app.route('/chat/rooms')
def get_chat_rooms():
    if 'user_id' not in session:
        return jsonify({'error': '로그인이 필요합니다.'}), 401
        
    db = get_db()
    cursor = db.cursor()
    
    # 사용자가 참여중인 모든 채팅방 조회
    cursor.execute("""
        SELECT cr.*, p.title as product_title,
               CASE WHEN cr.buyer_id = ? THEN u.username
                    ELSE b.username
               END as other_user_name
        FROM chat_room cr
        JOIN product p ON cr.product_id = p.id
        JOIN user u ON cr.seller_id = u.id
        JOIN user b ON cr.buyer_id = b.id
        WHERE cr.buyer_id = ? OR cr.seller_id = ?
        ORDER BY cr.created_at DESC
    """, (session['user_id'], session['user_id'], session['user_id']))
    
    rooms = cursor.fetchall()
    return jsonify({'rooms': [dict(room) for room in rooms]}), 200

# 채팅 메시지 전송
@socketio.on('join')
def on_join(data):
    room = data['room']
    join_room(room)
    
@socketio.on('leave')
def on_leave(data):
    room = data['room']
    leave_room(room)

@socketio.on('chat_message')
def handle_chat_message(data):
    if 'user_id' not in session:
        return
        
    room_id = data['room']
    message = data['message']
    
    db = get_db()
    cursor = db.cursor()
    
    # 메시지 저장
    message_id = str(uuid.uuid4())
    cursor.execute("""
        INSERT INTO chat_message (id, room_id, sender_id, message)
        VALUES (?, ?, ?, ?)
    """, (message_id, room_id, session['user_id'], message))
    
    db.commit()
    
    # 채팅방의 다른 사용자들에게 메시지 전송
    emit('chat_message', {
        'message_id': message_id,
        'sender_id': session['user_id'],
        'message': message,
        'created_at': datetime.now().isoformat()
    }, room=room_id)

# 채팅 메시지 히스토리 조회
@app.route('/chat/messages/<room_id>')
def get_chat_messages(room_id):
    if 'user_id' not in session:
        return jsonify({'error': '로그인이 필요합니다.'}), 401
        
    db = get_db()
    cursor = db.cursor()
    
    # 채팅방 접근 권한 확인
    cursor.execute("""
        SELECT * FROM chat_room
        WHERE id = ? AND (buyer_id = ? OR seller_id = ?)
    """, (room_id, session['user_id'], session['user_id']))
    
    if not cursor.fetchone():
        return jsonify({'error': '접근 권한이 없습니다.'}), 403
        
    # 메시지 히스토리 조회
    cursor.execute("""
        SELECT cm.*, u.username as sender_name
        FROM chat_message cm
        JOIN user u ON cm.sender_id = u.id
        WHERE cm.room_id = ?
        ORDER BY cm.created_at ASC
    """, (room_id,))
    
    messages = cursor.fetchall()
    return jsonify({'messages': [dict(msg) for msg in messages]}), 200

# 전체 채팅방 페이지
@app.route('/chat/global')
def global_chat():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    db = get_db()
    cursor = db.cursor()
    
    # 최근 50개의 메시지 조회
    cursor.execute("""
        SELECT gm.*, u.username as sender_name
        FROM global_chat_message gm
        JOIN user u ON gm.sender_id = u.id
        ORDER BY gm.created_at DESC
        LIMIT 50
    """)
    
    messages = cursor.fetchall()
    messages = list(reversed(messages))  # 시간순 정렬
    
    # 현재 사용자 정보 조회
    cursor.execute("SELECT username FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    
    return render_template('global_chat.html', messages=messages, current_user=current_user)

# 전체 채팅 메시지 전송 처리
@socketio.on('global_message')
def handle_global_message(data):
    if 'user_id' not in session:
        return
        
    message = data.get('message', '').strip()
    if not message:
        return
        
    db = get_db()
    cursor = db.cursor()
    
    # 발신자 정보 조회
    cursor.execute("SELECT username FROM user WHERE id = ?", (session['user_id'],))
    sender = cursor.fetchone()
    
    # 메시지 저장
    message_id = str(uuid.uuid4())
    cursor.execute("""
        INSERT INTO global_chat_message (id, sender_id, message)
        VALUES (?, ?, ?)
    """, (message_id, session['user_id'], message))
    
    db.commit()
    
    # 모든 클라이언트에게 메시지 브로드캐스트
    emit('global_message', {
        'message_id': message_id,
        'sender_id': session['user_id'],
        'sender_name': sender['username'],
        'message': message,
        'created_at': datetime.now().isoformat()
    }, broadcast=True)

# 상품 검색 기능
@app.route('/search')
def search_products():
    # 검색 파라미터 받기
    keyword = request.args.get('keyword', '').strip()
    category = request.args.get('category')
    min_price = request.args.get('min_price')
    max_price = request.args.get('max_price')
    seller = request.args.get('seller')
    sort_by = request.args.get('sort', 'recent')  # recent, price_asc, price_desc
    
    db = get_db()
    cursor = db.cursor()
    
    # 기본 쿼리 구성
    query = """
        SELECT p.*, u.username as seller_name, u.warning_count as seller_warning_count
        FROM product p
        JOIN user u ON p.seller_id = u.id
        WHERE 1=1
    """
    params = []
    
    # 키워드 검색 (제목, 설명)
    if keyword:
        query += """ AND (
            p.title LIKE ? OR 
            p.description LIKE ? OR
            u.username LIKE ?
        )"""
        search_pattern = f"%{keyword}%"
        params.extend([search_pattern, search_pattern, search_pattern])
    
    # 카테고리 필터
    if category:
        query += " AND p.category = ?"
        params.append(category)
    
    # 가격 범위 필터
    if min_price:
        query += " AND CAST(REPLACE(p.price, ',', '') AS INTEGER) >= ?"
        params.append(min_price)
    if max_price:
        query += " AND CAST(REPLACE(p.price, ',', '') AS INTEGER) <= ?"
        params.append(max_price)
    
    # 판매자 필터
    if seller:
        query += " AND u.username LIKE ?"
        params.append(f"%{seller}%")
    
    # 정렬 조건
    if sort_by == 'price_asc':
        query += " ORDER BY CAST(REPLACE(p.price, ',', '') AS INTEGER) ASC"
    elif sort_by == 'price_desc':
        query += " ORDER BY CAST(REPLACE(p.price, ',', '') AS INTEGER) DESC"
    else:  # recent
        query += " ORDER BY p.created_at DESC"
    
    cursor.execute(query, params)
    products = cursor.fetchall()
    
    # 카테고리 목록 조회
    cursor.execute("SELECT DISTINCT category FROM product WHERE category IS NOT NULL")
    categories = [row['category'] for row in cursor.fetchall()]
    
    # 검색 결과 요약
    total_count = len(products)
    price_range = None
    if products:
        prices = [int(p['price'].replace(',', '')) for p in products]
        price_range = {
            'min': min(prices),
            'max': max(prices)
        }
    
    return render_template('search.html',
                         products=products,
                         categories=categories,
                         total_count=total_count,
                         price_range=price_range,
                         search_params={
                             'keyword': keyword,
                             'category': category,
                             'min_price': min_price,
                             'max_price': max_price,
                             'seller': seller,
                             'sort_by': sort_by
                         })

# 내 지갑 조회
@app.route('/wallet')
def view_wallet():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    db = get_db()
    cursor = db.cursor()
    
    # 지갑 정보 조회
    cursor.execute("""
        SELECT w.*, u.username 
        FROM wallet w 
        JOIN user u ON w.user_id = u.id 
        WHERE w.user_id = ?
    """, (session['user_id'],))
    wallet = cursor.fetchone()
    
    # 거래 내역 조회
    cursor.execute("""
        SELECT t.*, 
               s.username as sender_name,
               r.username as receiver_name
        FROM money_transaction t
        JOIN user s ON t.sender_id = s.id
        JOIN user r ON t.receiver_id = r.id
        WHERE t.sender_id = ? OR t.receiver_id = ?
        ORDER BY t.created_at DESC
        LIMIT 10
    """, (session['user_id'], session['user_id']))
    transactions = cursor.fetchall()
    
    return render_template('wallet.html', wallet=wallet, transactions=transactions)

def validate_transaction(sender_id, receiver_id, amount):
    db = get_db()
    cursor = db.cursor()
    
    # 송신자 지갑 확인
    cursor.execute("SELECT balance FROM wallet WHERE user_id = ?", (sender_id,))
    sender_wallet = cursor.fetchone()
    if not sender_wallet:
        return False, "송신자의 지갑을 찾을 수 없습니다."
    
    # 수신자 지갑 확인
    cursor.execute("SELECT user_id FROM wallet WHERE user_id = ?", (receiver_id,))
    if not cursor.fetchone():
        return False, "수신자의 지갑을 찾을 수 없습니다."
    
    # 잔액 검증
    if sender_wallet['balance'] < amount:
        return False, "잔액이 부족합니다."
    
    # 금액 검증
    if amount <= 0:
        return False, "송금액은 0보다 커야 합니다."
    
    return True, None

@app.route('/transfer', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
@login_required
def transfer_money():
    if request.method == 'POST':
        receiver_username = request.form['receiver_username']
        try:
            amount = int(request.form['amount'])
        except ValueError:
            flash('올바른 금액을 입력해주세요.')
            return redirect(url_for('transfer_money'))
            
        description = request.form.get('description', '')
        
        db = get_db()
        cursor = db.cursor()
        
        # 수신자 확인
        cursor.execute("SELECT id FROM user WHERE username = ?", (receiver_username,))
        receiver = cursor.fetchone()
        if not receiver:
            flash('존재하지 않는 사용자입니다.')
            return redirect(url_for('transfer_money'))
        
        # 자기 자신에게 송금하는 것을 방지
        if receiver['id'] == session['user_id']:
            flash('자기 자신에게는 송금할 수 없습니다.')
            return redirect(url_for('transfer_money'))
        
        # 거래 유효성 검증
        is_valid, error_message = validate_transaction(session['user_id'], receiver['id'], amount)
        if not is_valid:
            flash(error_message)
            return redirect(url_for('transfer_money'))
        
        # 거래 처리
        transaction_id = str(uuid.uuid4())
        try:
            cursor.execute("BEGIN TRANSACTION")
            
            # 송신자 잔액 감소
            cursor.execute("""
                UPDATE wallet 
                SET balance = balance - ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE user_id = ? AND balance >= ?
            """, (amount, session['user_id'], amount))
            
            if cursor.rowcount == 0:
                cursor.execute("ROLLBACK")
                flash('잔액이 부족합니다.')
                return redirect(url_for('transfer_money'))
            
            # 수신자 잔액 증가
            cursor.execute("""
                UPDATE wallet 
                SET balance = balance + ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE user_id = ?
            """, (amount, receiver['id']))
            
            # 거래 내역 저장
            cursor.execute("""
                INSERT INTO money_transaction (id, sender_id, receiver_id, amount, description)
                VALUES (?, ?, ?, ?, ?)
            """, (transaction_id, session['user_id'], receiver['id'], amount, description))
            
            cursor.execute("COMMIT")
            flash('송금이 완료되었습니다.')
            return redirect(url_for('view_wallet'))
            
        except Exception as e:
            cursor.execute("ROLLBACK")
            app.logger.error(f"Transaction error: {str(e)}")
            flash('송금 처리 중 오류가 발생했습니다.')
            return redirect(url_for('transfer_money'))
    
    # GET 요청: 송금 폼 표시
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM wallet WHERE user_id = ?", (session['user_id'],))
    wallet = cursor.fetchone()
    
    return render_template('transfer.html', wallet=wallet)

def handle_error(error_message):
    # 오류 메시지에서 민감한 정보 제거
    safe_message = error_message.replace(DATABASE, '***')
    safe_message = re.sub(r'at 0x[0-9a-fA-F]+', 'at ***', safe_message)
    return safe_message

@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', error='요청하신 페이지를 찾을 수 없습니다.'), 404

@app.errorhandler(500)
def internal_error(error):
    db = get_db()
    db.rollback()
    return render_template('error.html', error='서버 오류가 발생했습니다.'), 500

@app.route('/error')
def error():
    return render_template('error.html')

def check_login_attempts(username, ip_address):
    db = get_db()
    cursor = db.cursor()
    
    # 최근 10분간의 실패한 로그인 시도 횟수 확인
    cursor.execute("""
        SELECT COUNT(*) as attempt_count
        FROM login_attempts
        WHERE username = ? 
        AND ip_address = ?
        AND success = 0
        AND attempted_at > datetime('now', '-10 minutes')
    """, (username, ip_address))
    
    result = cursor.fetchone()
    return result['attempt_count']

def add_login_attempt(username, ip_address, success):
    db = get_db()
    cursor = db.cursor()
    attempt_id = str(uuid.uuid4())
    
    cursor.execute("""
        INSERT INTO login_attempts (id, username, ip_address, success)
        VALUES (?, ?, ?, ?)
    """, (attempt_id, username, ip_address, success))
    
    db.commit()

def is_admin():
    if 'user_id' not in session:
        return False
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT role FROM user WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    return user and user['role'] == 'admin'

@app.route('/admin/create', methods=['GET', 'POST'])
def create_admin():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', '').strip())
        password = request.form.get('password', '')
        admin_key = request.form.get('admin_key', '')

        # 입력값 검증
        if not username or not password or not admin_key:
            flash('모든 필드를 입력해주세요.', 'error')
            return redirect(url_for('create_admin'))

        # 사용자명 형식 검증
        if not re.match(r'^[a-zA-Z0-9_]{4,20}$', username):
            flash('사용자명은 4-20자의 영문, 숫자, 언더스코어만 사용 가능합니다.', 'error')
            return redirect(url_for('create_admin'))

        # 비밀번호 복잡도 검증
        if len(password) < 8 or not re.search(r'[A-Za-z]', password) or not re.search(r'[0-9]', password) or not re.search(r'[^A-Za-z0-9]', password):
            flash('비밀번호는 8자 이상의 영문, 숫자, 특수문자 조합이어야 합니다.', 'error')
            return redirect(url_for('create_admin'))

        # 관리자 키 검증
        if admin_key != app.config['ADMIN_KEY']:
            flash('관리자 키가 올바르지 않습니다.', 'error')
            return redirect(url_for('create_admin'))

        try:
            # 사용자명 중복 검사
            cursor = get_db().cursor()
            cursor.execute('SELECT 1 FROM user WHERE username = ?', (username,))
            if cursor.fetchone():
                flash('이미 존재하는 사용자명입니다.', 'error')
                return redirect(url_for('create_admin'))

            # 관리자 계정 생성
            hashed_password = generate_password_hash(password)
            cursor.execute(
                'INSERT INTO user (username, password, role, wallet_balance) VALUES (?, ?, ?, ?)',
                (username, hashed_password, 'admin', 10000)
            )
            get_db().commit()
            flash('관리자 계정이 성공적으로 생성되었습니다.', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            get_db().rollback()
            app.logger.error(f'관리자 계정 생성 중 오류 발생: {str(e)}')
            flash('계정 생성 중 오류가 발생했습니다. 나중에 다시 시도해주세요.', 'error')
            return redirect(url_for('create_admin'))

    return render_template('create_admin.html')

# 상품 수정
@app.route('/product/<product_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    db = get_db()
    cursor = db.cursor()
    
    # 상품 정보 조회
    cursor.execute("""
        SELECT * FROM product 
        WHERE id = ? AND seller_id = ?
    """, (product_id, session['user_id']))
    product = cursor.fetchone()
    
    if not product:
        flash('상품을 찾을 수 없거나 수정 권한이 없습니다.', 'error')
        return redirect(url_for('profile'))
    
    if request.method == 'POST':
        title = sanitize_input(request.form.get('title', '').strip())
        description = sanitize_input(request.form.get('description', '').strip())
        price = request.form.get('price', '').strip()
        category = request.form.get('category', '').strip()
        
        # 입력값 검증
        if not all([title, description, price, category]):
            flash('모든 필드를 입력해주세요.', 'error')
            return redirect(url_for('edit_product', product_id=product_id))
        
        # 가격 유효성 검사
        try:
            price_value = int(price)
            if price_value < 0:
                flash('가격은 0 이상이어야 합니다.', 'error')
                return redirect(url_for('edit_product', product_id=product_id))
        except ValueError:
            flash('올바른 가격을 입력해주세요.', 'error')
            return redirect(url_for('edit_product', product_id=product_id))
        
        # XSS 방지를 위한 추가 검증
        if len(title) > 100 or len(description) > 1000:
            flash('제목 또는 설명이 너무 깁니다.', 'error')
            return redirect(url_for('edit_product', product_id=product_id))
        
        # 허용된 카테고리 검증
        allowed_categories = ['전자기기', '의류', '도서', '생활용품', '기타']
        if category not in allowed_categories:
            flash('올바른 카테고리를 선택해주세요.', 'error')
            return redirect(url_for('edit_product', product_id=product_id))
        
        try:
            cursor.execute("""
                UPDATE product 
                SET title = ?, description = ?, price = ?, category = ?
                WHERE id = ? AND seller_id = ?
            """, (title, description, price, category, product_id, session['user_id']))
            
            db.commit()
            flash('상품이 수정되었습니다.', 'success')
            return redirect(url_for('view_product', product_id=product_id))
            
        except Exception as e:
            db.rollback()
            app.logger.error(f'상품 수정 중 오류 발생: {str(e)}')
            flash('상품 수정 중 오류가 발생했습니다.', 'error')
            return redirect(url_for('edit_product', product_id=product_id))
    
    return render_template('product/edit.html', product=product)

if __name__ == '__main__':
    init_db()
    socketio.run(app, debug=True, port=5000)
