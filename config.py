import os
from datetime import timedelta

class Config:
    # Flask 설정
    SECRET_KEY = os.environ.get('SECRET_KEY', 'your-secret-key-here')
    
    # 데이터베이스 설정
    DATABASE = os.environ.get('DATABASE_URL', 'market.db')
    
    # 세션 설정
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    
    # Rate Limiting 설정
    RATELIMIT_DEFAULT = "200 per day;50 per hour"
    RATELIMIT_STORAGE_URL = "memory://"
    
    # 보안 설정
    WTF_CSRF_ENABLED = True
    WTF_CSRF_SECRET_KEY = os.environ.get('WTF_CSRF_SECRET_KEY', 'csrf-key-here')
    
    # SSL/TLS 설정
    SSL_CERT_PATH = os.environ.get('SSL_CERT_PATH', 'path/to/cert.pem')
    SSL_KEY_PATH = os.environ.get('SSL_KEY_PATH', 'path/to/key.pem')

class DevelopmentConfig(Config):
    DEBUG = True
    
class ProductionConfig(Config):
    DEBUG = False
    
    # 프로덕션 환경에서는 환경 변수 필수
    def __init__(self):
        if not os.environ.get('SECRET_KEY'):
            raise ValueError("SECRET_KEY 환경 변수가 설정되지 않았습니다.")
        if not os.environ.get('WTF_CSRF_SECRET_KEY'):
            raise ValueError("WTF_CSRF_SECRET_KEY 환경 변수가 설정되지 않았습니다.")

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
} 