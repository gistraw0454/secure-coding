import sqlite3

# 데이터베이스 연결
conn = sqlite3.connect('market.db')
cursor = conn.cursor()

try:
    # admin 계정의 role을 'admin'으로 업데이트
    cursor.execute(
        'UPDATE user SET role = ? WHERE username = ?',
        ('admin', 'admin')
    )
    
    if cursor.rowcount > 0:
        print('admin 계정이 관리자 권한으로 업그레이드되었습니다.')
    else:
        print('admin 계정을 찾을 수 없습니다.')
    
    conn.commit()
except Exception as e:
    print(f'오류 발생: {str(e)}')
    conn.rollback()
finally:
    conn.close() 