import os
from datetime import datetime, timedelta
import re
from flask import current_app
from app import db
from app.models import User, Role, PasswordHistory, AuditLog, SecurityEvent, EncryptedKey, LoginAttempt
from app.crypto import (
    hash_password, verify_password, generate_salt,
    generate_rsa_keypair, encrypt_private_key, decrypt_private_key, sign_data
)

def validate_password_strength(password: str) -> list:
    """
    Validates password complexity.
    Requirements:
    - Minimum 12 characters
    - Uppercase letters
    - Lowercase letters
    - Numbers
    - Special characters
    """
    errors = []
    if len(password) < 12:
        errors.append("Password must be at least 12 characters long.")
    if not any(c.isupper() for c in password):
        errors.append("Password must contain at least one uppercase letter.")
    if not any(c.islower() for c in password):
        errors.append("Password must contain at least one lowercase letter.")
    if not any(c.isdigit() for c in password):
        errors.append("Password must contain at least one number.")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=\[\]\\/`~;']", password):
        errors.append("Password must contain at least one special character.")
    return errors

def check_password_reuse(user: User, new_password: str) -> bool:
    """
    Checks if the new password matches the current one or any of the last 5 passwords.
    """
    # 1. Check current password
    if verify_password(user.password_hash, new_password):
        return True
        
    # 2. Check the last 5 passwords in history
    history = PasswordHistory.query.filter_by(user_id=user.id).order_by(PasswordHistory.changed_at.desc()).limit(5).all()
    for h in history:
        if verify_password(h.password_hash, new_password):
            return True
            
    return False

def get_signing_private_key() -> str:
    """
    Decrypts and retrieves the RSA private key from the database using the master AES key.
    """
    key_record = EncryptedKey.query.filter_by(key_name='audit_log_signing_rsa_private').first()
    if not key_record:
        raise RuntimeError("Cryptographic signing key is missing from the database.")
    
    master_key = current_app.config.get('AES_MASTER_KEY')
    if not master_key:
        raise ValueError("AES Master Key is not configured in the application.")
        
    # Decrypt using AES-256-GCM
    return decrypt_private_key(
        key_record.encrypted_key_data,
        key_record.nonce,
        key_record.tag,
        master_key
    )

def log_audit_event(event_type: str, description: str, user_id: int = None) -> AuditLog:
    """
    Creates an audit log entry and signs it using the RSA-4096 private key.
    Ensures the log is tamper-evident.
    """
    timestamp = datetime.utcnow()
    # Format canonical log string: "timestamp|event_type|user_id|description"
    canonical_str = f"{timestamp.isoformat()}|{event_type}|{user_id or 'SYSTEM'}|{description}"
    
    # Decrypt private key, sign, and immediately clear key from memory (handled inside crypto.py)
    try:
        private_pem = get_signing_private_key()
        signature = sign_data(private_pem, canonical_str)
    except Exception as e:
        current_app.logger.error(f"Failed to sign audit log: {str(e)}")
        signature = "UNSIGNED_ERROR"
        
    log_entry = AuditLog(
        event_type=event_type,
        user_id=user_id,
        description=description,
        timestamp=timestamp,
        signature=signature
    )
    
    db.session.add(log_entry)
    db.session.commit()
    return log_entry

def log_security_event(event_type: str, severity: str, description: str):
    """
    Logs a high-level security event (e.g. Account lockout, brute force, tampering).
    """
    event = SecurityEvent(
        event_type=event_type,
        severity=severity,
        description=description,
        timestamp=datetime.utcnow()
    )
    db.session.add(event)
    db.session.commit()

def record_login_attempt(username: str, ip_address: str, is_successful: bool):
    """
    Logs a login attempt to track brute force attacks.
    """
    attempt = LoginAttempt(
        username=username,
        ip_address=ip_address,
        attempted_at=datetime.utcnow(),
        is_successful=is_successful
    )
    db.session.add(attempt)
    db.session.commit()

def seed_database():
    """
    Seeds default roles, initializes cryptographic keys, and creates the default admin user.
    """
    # 1. Seed Roles
    admin_role = Role.query.filter_by(name='Security Administrator').first()
    if not admin_role:
        admin_role = Role(name='Security Administrator')
        db.session.add(admin_role)
        
    user_role = Role.query.filter_by(name='User').first()
    if not user_role:
        user_role = Role(name='User')
        db.session.add(user_role)
    
    db.session.commit()
    
    # 2. Check and Seed Cryptographic Keys
    key_record = EncryptedKey.query.filter_by(key_name='audit_log_signing_rsa_private').first()
    if not key_record:
        # Check if AES Master Key is set. If not, auto-generate one for local development
        master_key = current_app.config.get('AES_MASTER_KEY')
        if not master_key:
            current_app.logger.warning("AES_MASTER_KEY not found in environment! Generating a temporary key for development.")
            temp_key = os.urandom(32).hex()
            current_app.config['AES_MASTER_KEY'] = temp_key
            master_key = temp_key
            # Write to .env to persist it
            env_path = os.path.join(current_app.root_path, '..', '.env')
            if os.path.exists(env_path):
                try:
                    with open(env_path, 'r') as f:
                        lines = f.read()
                    if 'AES_MASTER_KEY=' not in lines:
                        with open(env_path, 'a') as f:
                            f.write(f"\nAES_MASTER_KEY={temp_key}\n")
                        current_app.logger.info("Successfully appended auto-generated AES_MASTER_KEY to .env file.")
                except Exception as e:
                    current_app.logger.error(f"Could not write key to .env: {str(e)}")
                    
        # Generate RSA-4096 pair
        private_pem, public_pem = generate_rsa_keypair()
        
        # Encrypt the private key
        enc_data, nonce, tag = encrypt_private_key(private_pem, master_key)
        
        key_record = EncryptedKey(
            key_name='audit_log_signing_rsa_private',
            encrypted_key_data=enc_data,
            nonce=nonce,
            tag=tag,
            public_key_data=public_pem
        )
        db.session.add(key_record)
        db.session.commit()
        current_app.logger.info("Generated and encrypted new RSA-4096 audit log signing keys.")

    # 3. Seed Default Admin User
    admin_user = User.query.filter_by(username='admin').first()
    if not admin_user:
        salt_val = generate_salt()
        default_pwd = "AdminSecure2026!"
        pwd_hash = hash_password(default_pwd)
        
        admin_user = User(
            username='admin',
            password_hash=pwd_hash,
            salt=salt_val,
            role_id=admin_role.id,
            password_expiry_days=90,
            password_changed_at=datetime.utcnow()
        )
        db.session.add(admin_user)
        db.session.commit()
        
        # Add to history
        hist = PasswordHistory(user_id=admin_user.id, password_hash=pwd_hash)
        db.session.add(hist)
        db.session.commit()
        
        # Log registration audit event (first log)
        log_audit_event(
            event_type='REGISTRATION',
            description='Default Security Administrator account "admin" initialized.',
            user_id=admin_user.id
        )
        current_app.logger.info("Default Security Administrator account 'admin' created. Password: 'AdminSecure2026!'")
