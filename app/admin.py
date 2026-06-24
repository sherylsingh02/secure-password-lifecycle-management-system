from datetime import datetime, timedelta
from flask import Blueprint, render_template, redirect, url_for, flash, request, abort, current_app
from flask_login import login_required, current_user
from app import db
from app.models import User, Role, PasswordHistory, AuditLog, SecurityEvent, LoginAttempt, EncryptedKey
from app.auth import log_audit_event, log_security_event, get_signing_private_key
from app.crypto import (
    verify_signature, generate_rsa_keypair, encrypt_private_key, decrypt_private_key, sign_data
)

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

def admin_required(f):
    """
    Role-Based Access Control decorator:
    Ensures that only users with the 'Security Administrator' role can access these routes.
    """
    @login_required
    def decorated_function(*args, **kwargs):
        if current_user.role.name != 'Security Administrator':
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

@admin_bp.route('/dashboard')
@admin_required
def dashboard():
    # 1. Active Users
    total_users = User.query.count()
    
    # 2. Locked Accounts
    locked_users = User.query.filter(
        (User.locked_until > datetime.utcnow()) | (User.failed_login_attempts >= 5)
    ).all()
    
    # 3. Password Expiry Statistics
    all_users = User.query.all()
    expired_count = 0
    warning_count = 0
    active_count = 0
    
    for u in all_users:
        password_age = datetime.utcnow() - u.password_changed_at
        days_left = u.password_expiry_days - password_age.days
        if days_left <= 0:
            expired_count += 1
        elif days_left <= 7:
            warning_count += 1
        else:
            active_count += 1
            
    # 4. Failed Login Attempts (Last 50)
    failed_attempts = LoginAttempt.query.order_by(LoginAttempt.attempted_at.desc()).limit(50).all()
    total_failed_count = LoginAttempt.query.filter_by(is_successful=False).count()
    
    # 5. Security Events (Last 50)
    security_events = SecurityEvent.query.order_by(SecurityEvent.timestamp.desc()).limit(50).all()
    
    # 6. Audit Log Integrity Stats (Fast cached view or simple verification count)
    total_audit_logs = AuditLog.query.count()
    
    # Fetch key details for display
    signing_key = EncryptedKey.query.filter_by(key_name='audit_log_signing_rsa_private').first()
    key_created = signing_key.created_at.strftime('%Y-%m-%d %H:%M:%S UTC') if signing_key else "N/A"
    
    return render_template(
        'admin_dashboard.html',
        total_users=total_users,
        locked_users=locked_users,
        expired_count=expired_count,
        warning_count=warning_count,
        active_count=active_count,
        failed_attempts=failed_attempts,
        total_failed_count=total_failed_count,
        security_events=security_events,
        total_audit_logs=total_audit_logs,
        key_created=key_created
    )

@admin_bp.route('/verify-audit-logs')
@admin_required
def verify_audit_logs():
    """
    Tamper Detection:
    Fetches all audit logs from the database, builds their canonical representations,
    and verifies the RSA-4096 PSS signatures using the public key.
    """
    key_record = EncryptedKey.query.filter_by(key_name='audit_log_signing_rsa_private').first()
    if not key_record:
        flash("RSA Public Key is missing from the database.", "danger")
        return redirect(url_for('admin.dashboard'))
        
    public_pem = key_record.public_key_data
    logs = AuditLog.query.order_by(AuditLog.timestamp.asc()).all()
    
    verification_results = []
    tampering_detected = False
    tampered_logs_count = 0
    
    for log in logs:
        # Re-create canonical string
        canonical_str = f"{log.timestamp.isoformat()}|{log.event_type}|{log.user_id or 'SYSTEM'}|{log.description}"
        
        # Verify signature
        is_valid = verify_signature(public_pem, canonical_str, log.signature)
        
        verification_results.append({
            'log': log,
            'is_valid': is_valid
        })
        
        if not is_valid:
            tampering_detected = True
            tampered_logs_count += 1
            
    if tampering_detected:
        log_security_event(
            event_type='LOG_TAMPERING_DETECTED',
            severity='CRITICAL',
            description=f"Log verification failed! Detected {tampered_logs_count} tampered entries in audit logs."
        )
        flash(f"CRITICAL WARNING: Log tampering detected! {tampered_logs_count} log(s) failed signature verification.", "danger")
    else:
        flash("All audit logs successfully verified. Integrities intact.", "success")
        
    # Log the verification run itself
    log_audit_event('ADMIN_ACTION', f"Admin run audit trail integrity verification. Tampered logs detected: {tampered_logs_count}.", current_user.id)
        
    return render_template(
        'verify_logs.html',
        results=verification_results,
        tampering_detected=tampering_detected
    )

@admin_bp.route('/simulate-tampering/<int:log_id>')
@admin_required
def simulate_tampering(log_id):
    """
    Simulates database tampering for educational/demonstration purposes
    by direct modification of a database record.
    """
    log = AuditLog.query.get_or_4096 = AuditLog.query.get(log_id)
    if not log:
        flash("Log entry not found.", "danger")
        return redirect(url_for('admin.verify_audit_logs'))
        
    # Modify data without updating signature
    log.description = log.description + " [UNAUTHORIZED TAMPERED CONTENT]"
    db.session.commit()
    
    # Write security alert
    log_security_event(
        event_type='SIMULATED_TAMPER_ACTION',
        severity='WARNING',
        description=f"Simulated database tampering on Log ID {log_id} by Administrator."
    )
    
    flash(f"Log ID {log_id} has been modified directly in the database. Run the Integrity Check to test detection.", "warning")
    return redirect(url_for('admin.verify_audit_logs'))

@admin_bp.route('/unlock-user/<int:user_id>')
@admin_required
def unlock_user(user_id):
    user = User.query.get(user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('admin.dashboard'))
        
    user.failed_login_attempts = 0
    user.locked_until = None
    db.session.commit()
    
    # Log administrative action
    log_audit_event('ADMIN_ACTION', f"Administrative unlock for user '{user.username}'.", current_user.id)
    flash(f"User account '{user.username}' unlocked successfully.", "success")
    return redirect(url_for('admin.dashboard'))

@admin_bp.route('/rotate-keys', methods=['POST'])
@admin_required
def rotate_keys():
    """
    Enterprise Key Vault Demonstration:
    Generates a new RSA-4096 pair, encrypts the new private key using AES-256-GCM,
    and updates existing log signatures using the new key.
    """
    try:
        # 1. Fetch old keys and all logs
        old_key_record = EncryptedKey.query.filter_by(key_name='audit_log_signing_rsa_private').first()
        if not old_key_record:
            flash("Cannot rotate keys: Old signing keys not found.", "danger")
            return redirect(url_for('admin.dashboard'))
            
        logs = AuditLog.query.order_by(AuditLog.timestamp.asc()).all()
        
        # 2. Generate new RSA-4096 key pair
        new_private_pem, new_public_pem = generate_rsa_keypair()
        
        # 3. Encrypt new private key
        master_key = current_app.config.get('AES_MASTER_KEY')
        new_enc_data, new_nonce, new_tag = encrypt_private_key(new_private_pem, master_key)
        
        # 4. Decrypt old private key to verify current signatures before swap
        old_private_pem = get_signing_private_key()
        
        # 5. Re-sign all logs using the new private key to preserve the chain of custody
        re_signed_count = 0
        for log in logs:
            # Recreate canonical string
            canonical_str = f"{log.timestamp.isoformat()}|{log.event_type}|{log.user_id or 'SYSTEM'}|{log.description}"
            
            # Verify signature with old public key first (ensure only valid logs get re-signed)
            is_valid = verify_signature(old_key_record.public_key_data, canonical_str, log.signature)
            
            # Sign with the new private key
            new_sig = sign_data(new_private_pem, canonical_str)
            log.signature = new_sig
            
            if is_valid:
                re_signed_count += 1
                
        # 6. Update database record
        old_key_record.encrypted_key_data = new_enc_data
        old_key_record.nonce = new_nonce
        old_key_record.tag = new_tag
        old_key_record.public_key_data = new_public_pem
        old_key_record.created_at = datetime.utcnow()
        
        db.session.commit()
        
        # Log rotation actions
        log_security_event(
            event_type='KEYS_ROTATED',
            severity='INFO',
            description=f"RSA-4096 audit log signing keys rotated. Re-signed {len(logs)} logs."
        )
        log_audit_event('ADMIN_ACTION', f"Audit log signature keys rotated. Re-signed {len(logs)} log entries.", current_user.id)
        
        flash(f"RSA-4096 key pair rotated successfully! Re-signed {re_signed_count}/{len(logs)} audit log entries.", "success")
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Key rotation failed: {str(e)}")
        flash(f"Error during key rotation: {str(e)}", "danger")
        
    return redirect(url_for('admin.dashboard'))
