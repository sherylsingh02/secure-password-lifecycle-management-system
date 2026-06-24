import os

class Config:
    # Flask Session and Security Config
    SECRET_KEY = os.environ.get('SECRET_KEY', 'default-dev-secret-key-change-in-production')
    
    # Session Security settings (Mitigate Session Hijacking)
    SESSION_COOKIE_HTTPONLY = True  # Prevents JS access to session cookies
    SESSION_COOKIE_SAMESITE = 'Lax'  # Mitigates CSRF attacks
    SESSION_COOKIE_SECURE = False    # Set to True in production with HTTPS
    
    # Session lifespan (Auto logout after 15 minutes of inactivity)
    PERMANENT_SESSION_LIFETIME = 900  # 15 minutes in seconds
    
    # Database configuration
    # Check if DATABASE_URL is set in environment, use it if available.
    # Otherwise, fall back to SQLite to ensure a seamless "no-setup" execution.
    database_url = os.environ.get('DATABASE_URL')
    if database_url and database_url.startswith('postgresql'):
        SQLALCHEMY_DATABASE_URI = database_url
    else:
        # Fallback to local SQLite database in the instance folder
        base_dir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{os.path.join(base_dir, 'secure_auth.db')}"
        
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # AES Master Key for RSA signature key protection (32 bytes / 64 characters hex)
    AES_MASTER_KEY = os.environ.get('AES_MASTER_KEY')
