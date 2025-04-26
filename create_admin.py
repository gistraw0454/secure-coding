import sqlite3
import uuid
from werkzeug.security import generate_password_hash

# 데이터베이스 연결
conn = sqlite3.connect('market.db')
cursor = conn.cursor()

# 관리자 계정 정보
admin_id = str(uuid.uuid4())
username = 'admin'
password = 'Admin123!'  # 실제 운영 환경에서는 더 강력한 비밀번호 사용
hashed_password = generate_password_hash(password)

try:
    # 관리자 계정 생성
    cursor.execute(
        'INSERT INTO user (id, username, password, role) VALUES (?, ?, ?, ?)',
        (admin_id, username, hashed_password, 'admin')
    )
    
    # 관리자 지갑 생성
    cursor.execute(
        'INSERT INTO wallet (user_id, balance) VALUES (?, ?)',
        (admin_id, 1000000)  # 초기 잔액 100만원
    )
    
    conn.commit()
    print('관리자 계정이 성공적으로 생성되었습니다.')
    print(f'아이디: {username}')
    print(f'비밀번호: {password}')
    
except sqlite3.IntegrityError:
    print('이미 관리자 계정이 존재합니다.')
except Exception as e:
    print(f'오류 발생: {str(e)}')
    conn.rollback()
finally:
    conn.close() 