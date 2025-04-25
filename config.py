import os

class Config:
    # 기본 설정
    DEBUG = False
    TESTING = False
    
    # 보안 설정
    SECRET_KEY = os.environ.get('SECRET_KEY', 'your-secret-key-here')  # 실제 운영 환경에서는 환경 변수로 설정
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = 1800  # 30분
    
    # 데이터베이스 설정
    DATABASE = 'market.db'
    
    # CSRF 보호
    WTF_CSRF_ENABLED = True
    WTF_CSRF_SECRET_KEY = os.environ.get('WTF_CSRF_SECRET_KEY', 'your-csrf-secret-key-here')
    
    # 파일 업로드 설정
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 최대 16MB
    UPLOAD_FOLDER = 'uploads'
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    
    # Rate Limiting 설정
    RATELIMIT_DEFAULT = "200 per day;50 per hour"
    RATELIMIT_STORAGE_URL = "memory://"
    
    # 로깅 설정
    LOG_LEVEL = 'INFO'
    LOG_FILE = 'app.log'

class DevelopmentConfig(Config):
    DEBUG = True
    SESSION_COOKIE_SECURE = False  # 개발 환경에서는 HTTP 허용

class TestingConfig(Config):
    TESTING = True
    SESSION_COOKIE_SECURE = False
    WTF_CSRF_ENABLED = False

class ProductionConfig(Config):
    # 운영 환경 특정 설정
    pass

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
} 