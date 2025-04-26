import sqlite3
import os

def init_db():
    # 기존 데이터베이스 파일이 있다면 삭제
    if os.path.exists('market.db'):
        os.remove('market.db')
    
    # 데이터베이스 생성
    db = sqlite3.connect('market.db')
    cursor = db.cursor()
    
    # 데이터베이스 권한 설정
    cursor.execute("PRAGMA journal_mode=WAL")  # Write-Ahead Logging 모드 활성화
    cursor.execute("PRAGMA foreign_keys=ON")   # 외래 키 제약 조건 활성화
    cursor.execute("PRAGMA secure_delete=ON")  # 안전한 삭제 모드 활성화
    
    # 사용자 테이블
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
    
    # 로그인 시도 테이블
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            success BOOLEAN NOT NULL
        )
    """)
    
    # 상품 테이블
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
    
    # 신고 테이블
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
    
    # 채팅방 테이블
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
    
    # 채팅 메시지 테이블
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
    
    # 전체 채팅 메시지 테이블
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS global_chat_message (
            id TEXT PRIMARY KEY,
            sender_id TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (sender_id) REFERENCES user (id)
        )
    """)
    
    # 지갑 테이블
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS wallet (
            user_id TEXT PRIMARY KEY,
            balance INTEGER DEFAULT 0,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES user (id)
        )
    """)
    
    # 거래 내역 테이블
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
    
    db.commit()
    db.close()
    
    print("데이터베이스가 성공적으로 초기화되었습니다.")

if __name__ == '__main__':
    init_db() 