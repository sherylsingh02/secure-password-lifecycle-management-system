from datetime import datetime
from flask_login import UserMixin
from app import db

class Role(db.Model):
    __tablename__ = 'roles'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    
    # Relationships
    users = db.relationship('User', backref='role', lazy=True)

    def __repr__(self):
        return f"<Role {self.name}>"


class User(db.Model, UserMixin):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    salt = db.Column(db.String(255), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    password_expiry_days = db.Column(db.Integer, default=90, nullable=False)  # 30, 60, or 90
    password_changed_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)
    is_active_user = db.Column(db.Boolean, default=True, nullable=False)  # Renamed from is_active to avoid Flask-Login conflicts

    # Relationships
    password_history = db.relationship('PasswordHistory', backref='user', lazy=True, cascade="all, delete-orphan")
    audit_logs = db.relationship('AuditLog', backref='user', lazy=True)

    # Flask-Login integration overrides
    @property
    def is_active(self):
        return self.is_active_user

    def __repr__(self):
        return f"<User {self.username}>"


class PasswordHistory(db.Model):
    __tablename__ = 'password_history'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    changed_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<PasswordHistory UserID={self.user_id} Date={self.changed_at}>"


class LoginAttempt(db.Model):
    __tablename__ = 'login_attempts'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)
    attempted_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_successful = db.Column(db.Boolean, nullable=False)

    def __repr__(self):
        return f"<LoginAttempt {self.username} Successful={self.is_successful}>"


class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(100), nullable=False)  # REGISTRATION, LOGIN_SUCCESS, failed logins, changes, lockout, admin actions
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    description = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    signature = db.Column(db.Text, nullable=False)  # Hex or Base64 signature string

    def __repr__(self):
        return f"<AuditLog {self.event_type} at {self.timestamp}>"


class SecurityEvent(db.Model):
    __tablename__ = 'security_events'
    
    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(100), nullable=False)  # e.g., BRUTE_FORCE_DETECTED, LOG_TAMPERING_DETECTED
    severity = db.Column(db.String(20), nullable=False)  # INFO, WARNING, CRITICAL
    description = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<SecurityEvent {self.event_type} Severity={self.severity}>"


class EncryptedKey(db.Model):
    __tablename__ = 'encrypted_keys'
    
    id = db.Column(db.Integer, primary_key=True)
    key_name = db.Column(db.String(100), unique=True, nullable=False)  # e.g. audit_log_signing_rsa_private
    encrypted_key_data = db.Column(db.Text, nullable=False)  # AES-256 encrypted private key (hex string)
    nonce = db.Column(db.String(50), nullable=False)  # Hex-encoded 12-byte GCM nonce
    tag = db.Column(db.String(50), nullable=False)    # Hex-encoded 16-byte GCM tag
    public_key_data = db.Column(db.Text, nullable=False)  # Plaintext PEM RSA public key
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<EncryptedKey {self.key_name}>"
