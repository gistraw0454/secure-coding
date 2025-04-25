import sqlite3
import uuid
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, jsonify
from flask_socketio import SocketIO, send, join_room, leave_room, emit

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
DATABASE = 'market.db'
socketio = SocketIO(app)

# 데이터베이스 연결 관리: 요청마다 연결 생성 후 사용, 종료 시 close
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # 결과를 dict처럼 사용하기 위함
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# 테이블 생성 (최초 실행 시에만)
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # 사용자 테이블 수정
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT,
                status TEXT DEFAULT 'active',
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
            CREATE TABLE IF NOT EXISTS transaction (
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
        db.commit()

# 기본 라우트
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# 회원가입
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        # 중복 사용자 체크
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))
        user_id = str(uuid.uuid4())
        cursor.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
                       (user_id, username, password))
        # 지갑 생성 (초기 잔액 10000원)
        cursor.execute("INSERT INTO wallet (user_id, balance) VALUES (?, ?)",
                       (user_id, 10000))
        db.commit()
        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html')

# 로그인
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ? AND password = ?", (username, password))
        user = cursor.fetchone()
        if user:
            if user['status'] == 'suspended':
                flash('계정이 정지되었습니다. 관리자에게 문의하세요.')
                return redirect(url_for('login'))
            session['user_id'] = user['id']
            # 마지막 로그인 시간 업데이트
            cursor.execute("UPDATE user SET last_login = CURRENT_TIMESTAMP WHERE id = ?", (user['id'],))
            db.commit()
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))
        else:
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

# 프로필 페이지: bio 업데이트 가능
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    if request.method == 'POST':
        bio = request.form.get('bio', '')
        cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))
        db.commit()
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile'))
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    return render_template('profile.html', user=current_user)

# 상품 등록
@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = request.form['price']
        category = request.form.get('category', '')
        
        db = get_db()
        cursor = db.cursor()
        
        # 사용자 상태 확인
        cursor.execute("SELECT status FROM user WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
        if user['status'] != 'active':
            flash('정지된 계정은 상품을 등록할 수 없습니다.')
            return redirect(url_for('dashboard'))
        
        product_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO product (id, title, description, price, seller_id, category) VALUES (?, ?, ?, ?, ?, ?)",
            (product_id, title, description, price, session['user_id'], category)
        )
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('new_product.html')

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
def view_product(product_id):
    db = get_db()
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

# 사용자 신고 처리
@app.route('/report_user/<user_id>', methods=['POST'])
def report_user(user_id):
    if 'user_id' not in session:
        return jsonify({'error': '로그인이 필요합니다.'}), 401
    
    reason = request.form.get('reason')
    if not reason:
        return jsonify({'error': '신고 사유를 입력해주세요.'}), 400
        
    db = get_db()
    cursor = db.cursor()
    
    # 신고 기록 추가
    report_id = str(uuid.uuid4())
    cursor.execute(
        "INSERT INTO report (id, reporter_id, target_id, target_type, reason) VALUES (?, ?, ?, ?, ?)",
        (report_id, session['user_id'], user_id, 'user', reason)
    )
    
    # 신고 횟수 증가 및 자동 정지 처리
    cursor.execute("UPDATE user SET warning_count = warning_count + 1 WHERE id = ?", (user_id,))
    cursor.execute("SELECT warning_count FROM user WHERE id = ?", (user_id,))
    warning_count = cursor.fetchone()['warning_count']
    
    if warning_count >= 3:
        cursor.execute("UPDATE user SET status = 'suspended' WHERE id = ?", (user_id,))
        
    db.commit()
    return jsonify({'message': '신고가 접수되었습니다.'}), 200

# 관리자용: 사용자 상태 관리
@app.route('/admin')
def admin_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    db = get_db()
    cursor = db.cursor()
    
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
def update_user_status(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    new_status = request.form.get('status')
    if new_status not in ['active', 'suspended']:
        flash('잘못된 상태값입니다.')
        return redirect(url_for('admin_dashboard'))
        
    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE user SET status = ? WHERE id = ?", (new_status, user_id))
    db.commit()
    
    flash('사용자 상태가 업데이트되었습니다.')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/product/<product_id>/status', methods=['POST'])
def update_product_status(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    new_status = request.form.get('status')
    if new_status not in ['active', 'inactive']:
        flash('잘못된 상태값입니다.')
        return redirect(url_for('admin_dashboard'))
        
    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE product SET status = ? WHERE id = ?", (new_status, product_id))
    db.commit()
    
    flash('상품 상태가 업데이트되었습니다.')
    return redirect(url_for('admin_dashboard'))

# 상품 신고
@app.route('/report_product/<product_id>', methods=['POST'])
def report_product(product_id):
    if 'user_id' not in session:
        return jsonify({'error': '로그인이 필요합니다.'}), 401
    
    reason = request.form.get('reason')
    if not reason:
        return jsonify({'error': '신고 사유를 입력해주세요.'}), 400
        
    db = get_db()
    cursor = db.cursor()
    
    # 신고 기록 추가
    report_id = str(uuid.uuid4())
    cursor.execute(
        "INSERT INTO report (id, reporter_id, target_id, target_type, reason) VALUES (?, ?, ?, ?, ?)",
        (report_id, session['user_id'], product_id, 'product', reason)
    )
    
    # 상품 신고 횟수 증가 및 자동 비활성화
    cursor.execute("UPDATE product SET report_count = report_count + 1 WHERE id = ?", (product_id,))
    cursor.execute("SELECT report_count FROM product WHERE id = ?", (product_id,))
    report_count = cursor.fetchone()['report_count']
    
    if report_count >= 3:
        cursor.execute("UPDATE product SET status = 'inactive' WHERE id = ?", (product_id,))
        
    db.commit()
    return jsonify({'message': '상품 신고가 접수되었습니다.'}), 200

# 1대1 채팅방 생성
@app.route('/chat/create/<product_id>', methods=['POST'])
def create_chat_room(product_id):
    if 'user_id' not in session:
        return jsonify({'error': '로그인이 필요합니다.'}), 401
        
    db = get_db()
    cursor = db.cursor()
    
    # 상품 정보 확인
    cursor.execute("SELECT seller_id FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        return jsonify({'error': '존재하지 않는 상품입니다.'}), 404
        
    # 판매자와 동일인인 경우 채팅방 생성 불가
    if product['seller_id'] == session['user_id']:
        return jsonify({'error': '자신의 상품에는 채팅방을 생성할 수 없습니다.'}), 400
        
    # 이미 존재하는 채팅방 확인
    cursor.execute("""
        SELECT id FROM chat_room 
        WHERE product_id = ? AND buyer_id = ? AND seller_id = ?
    """, (product_id, session['user_id'], product['seller_id']))
    
    existing_room = cursor.fetchone()
    if existing_room:
        return jsonify({'room_id': existing_room['id']}), 200
        
    # 새 채팅방 생성
    room_id = str(uuid.uuid4())
    cursor.execute("""
        INSERT INTO chat_room (id, product_id, buyer_id, seller_id)
        VALUES (?, ?, ?, ?)
    """, (room_id, product_id, session['user_id'], product['seller_id']))
    
    db.commit()
    return jsonify({'room_id': room_id, 'message': '채팅방이 생성되었습니다.'}), 201

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
        FROM transaction t
        JOIN user s ON t.sender_id = s.id
        JOIN user r ON t.receiver_id = r.id
        WHERE t.sender_id = ? OR t.receiver_id = ?
        ORDER BY t.created_at DESC
        LIMIT 10
    """, (session['user_id'], session['user_id']))
    transactions = cursor.fetchall()
    
    return render_template('wallet.html', wallet=wallet, transactions=transactions)

# 송금 기능
@app.route('/transfer', methods=['GET', 'POST'])
def transfer_money():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        receiver_username = request.form['receiver_username']
        amount = int(request.form['amount'])
        description = request.form.get('description', '')
        
        db = get_db()
        cursor = db.cursor()
        
        # 수신자 확인
        cursor.execute("SELECT id FROM user WHERE username = ?", (receiver_username,))
        receiver = cursor.fetchone()
        if not receiver:
            flash('존재하지 않는 사용자입니다.')
            return redirect(url_for('transfer_money'))
            
        # 잔액 확인
        cursor.execute("SELECT balance FROM wallet WHERE user_id = ?", (session['user_id'],))
        sender_balance = cursor.fetchone()['balance']
        
        if sender_balance < amount:
            flash('잔액이 부족합니다.')
            return redirect(url_for('transfer_money'))
            
        # 거래 처리
        transaction_id = str(uuid.uuid4())
        try:
            # 송신자 잔액 감소
            cursor.execute("""
                UPDATE wallet 
                SET balance = balance - ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE user_id = ?
            """, (amount, session['user_id']))
            
            # 수신자 잔액 증가
            cursor.execute("""
                UPDATE wallet 
                SET balance = balance + ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE user_id = ?
            """, (amount, receiver['id']))
            
            # 거래 내역 저장
            cursor.execute("""
                INSERT INTO transaction (id, sender_id, receiver_id, amount, description)
                VALUES (?, ?, ?, ?, ?)
            """, (transaction_id, session['user_id'], receiver['id'], amount, description))
            
            db.commit()
            flash('송금이 완료되었습니다.')
            return redirect(url_for('view_wallet'))
            
        except Exception as e:
            db.rollback()
            flash('송금 처리 중 오류가 발생했습니다.')
            return redirect(url_for('transfer_money'))
            
    # GET 요청: 송금 폼 표시
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM wallet WHERE user_id = ?", (session['user_id'],))
    wallet = cursor.fetchone()
    
    return render_template('transfer.html', wallet=wallet)

if __name__ == '__main__':
    init_db()  # 앱 컨텍스트 내에서 테이블 생성
    socketio.run(app, debug=True)
