from datetime import datetime, timedelta
from flask import Blueprint, render_template, redirect, url_for, flash, request, session, abort
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models import User, Role, PasswordHistory
from app.auth import (
    validate_password_strength, check_password_reuse, log_audit_event,
    log_security_event, record_login_attempt, hash_password, generate_salt
)
from app.crypto import verify_password, verify_password_dummy

auth_bp = Blueprint('auth', __name__)

@auth_bp.before_app_request
def check_session_security():
    """
    Session Hijacking Protection:
    Anchors the session to the client's IP address and User-Agent.
    If either changes during the session lifecycle, it is treated as a potential
    session hijacking attempt, the session is cleared, and re-login is required.
    """
    if current_user.is_authenticated:
        client_ip = request.remote_addr
        client_ua = request.headers.get('User-Agent', '')
        
        # Initialize anchor values if not set
        if '_ip_anchor' not in session or '_ua_anchor' not in session:
            session['_ip_anchor'] = client_ip
            session['_ua_anchor'] = client_ua
        # Validate anchor values
        elif session['_ip_anchor'] != client_ip or session['_ua_anchor'] != client_ua:
            log_security_event(
                event_type='SESSION_HIJACKING_SUSPECTED',
                severity='CRITICAL',
                description=f"User {current_user.username} session anchor mismatch. Expected IP/UA: {session.get('_ip_anchor')}/{session.get('_ua_anchor')}. Got: {client_ip}/{client_ua}."
            )
            logout_user()
            session.clear()
            flash("Session terminated due to network/browser change for security reasons.", "danger")
            return redirect(url_for('auth.login'))

@auth_bp.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.role.name == 'Security Administrator':
            return redirect(url_for('admin.dashboard'))
        return redirect(url_for('auth.dashboard'))
    return render_template('index.html')

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('auth.index'))
        
    roles = Role.query.all()
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        role_id = request.form.get('role_id')
        expiry_days = int(request.form.get('expiry_days', 90))
        
        # Basic validation
        if not username or not password or not role_id:
            flash("All fields are required.", "danger")
            return render_template('register.html', roles=roles)
            
        # Enforce unique username
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Username already exists.", "danger")
            return render_template('register.html', roles=roles)
            
        # Enforce password strength policy
        strength_errors = validate_password_strength(password)
        if strength_errors:
            for error in strength_errors:
                flash(error, "danger")
            return render_template('register.html', roles=roles)
            
        # Secure generation of salt and hash
        salt_val = generate_salt()
        pwd_hash = hash_password(password)
        
        # Save user record
        user = User(
            username=username,
            password_hash=pwd_hash,
            salt=salt_val,
            role_id=role_id,
            password_expiry_days=expiry_days,
            password_changed_at=datetime.utcnow()
        )
        db.session.add(user)
        db.session.commit()
        
        # Store in password history
        hist = PasswordHistory(user_id=user.id, password_hash=pwd_hash)
        db.session.add(hist)
        db.session.commit()
        
        # Log audit trail
        log_audit_event(
            event_type='REGISTRATION',
            description=f"User account '{username}' registered with role '{user.role.name}'.",
            user_id=user.id
        )
        
        flash("Registration successful. Please log in.", "success")
        return redirect(url_for('auth.login'))
        
    return render_template('register.html', roles=roles)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('auth.index'))
        
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash("Username and password are required.", "danger")
            return render_template('login.html')
            
        user = User.query.filter_by(username=username).first()
        
        # 1. Mitigation of Lockout Check
        if user:
            if user.locked_until and user.locked_until > datetime.utcnow():
                cooldown_remaining = user.locked_until - datetime.utcnow()
                minutes = int(cooldown_remaining.total_seconds() // 60)
                seconds = int(cooldown_remaining.total_seconds() % 60)
                flash(f"Account is locked due to multiple failed attempts. Try again in {minutes}m {seconds}s.", "danger")
                record_login_attempt(username, request.remote_addr, is_successful=False)
                return render_template('login.html')
                
        # 2. Timing Attack mitigation check
        # We execute verifying Argon2 hash. If user doesn't exist, we execute dummy check
        is_valid = False
        if user:
            is_valid = verify_password(user.password_hash, password)
        else:
            verify_password_dummy(password) # Constant execution time match
            
        if user and is_valid:
            # Login successful
            # Check if lockout is active but expired, reset it
            user.failed_login_attempts = 0
            user.locked_until = None
            db.session.commit()
            
            # Record successful attempt
            record_login_attempt(username, request.remote_addr, is_successful=True)
            
            # Session rotation to prevent Session Hijacking
            session.clear()
            session.permanent = True
            
            # Set anchors
            session['_ip_anchor'] = request.remote_addr
            session['_ua_anchor'] = request.headers.get('User-Agent', '')
            
            # Password aging check
            password_age = datetime.utcnow() - user.password_changed_at
            if password_age > timedelta(days=user.password_expiry_days):
                # Save user ID in session for change password redirection
                session['force_change_user_id'] = user.id
                flash("Your password has expired and must be updated.", "warning")
                return redirect(url_for('auth.change_password'))
                
            # Log in the user
            login_user(user)
            log_audit_event('LOGIN_SUCCESS', f"User '{username}' logged in successfully.", user.id)
            
            # Check for near expiration (within 7 days)
            days_left = user.password_expiry_days - password_age.days
            if days_left <= 7:
                flash(f"Security Alert: Your password will expire in {days_left} days. Consider changing it now.", "warning")
                
            if user.role.name == 'Security Administrator':
                return redirect(url_for('admin.dashboard'))
            return redirect(url_for('auth.dashboard'))
        else:
            # Login failed
            record_login_attempt(username, request.remote_addr, is_successful=False)
            log_audit_event('LOGIN_FAILURE', f"Failed login attempt for user '{username}'.")
            
            if user:
                user.failed_login_attempts += 1
                if user.failed_login_attempts >= 5:
                    user.locked_until = datetime.utcnow() + timedelta(minutes=15)
                    log_security_event(
                        event_type='ACCOUNT_LOCKOUT',
                        severity='WARNING',
                        description=f"User account '{username}' locked for 15 minutes due to 5 consecutive failed logins."
                    )
                    log_audit_event('ACCOUNT_LOCKOUT', f"Account '{username}' locked due to too many failed attempts.", user.id)
                db.session.commit()
                
            flash("Invalid username or password.", "danger")
            return render_template('login.html')
            
    return render_template('login.html')

@auth_bp.route('/logout')
@login_required
def logout():
    username = current_user.username
    uid = current_user.id
    logout_user()
    session.clear()
    log_audit_event('LOGOUT', f"User '{username}' logged out.", uid)
    flash("You have been logged out.", "success")
    return redirect(url_for('auth.login'))

@auth_bp.route('/dashboard')
@login_required
def dashboard():
    # Show user details, expiry, warning if needed
    password_age = datetime.utcnow() - current_user.password_changed_at
    days_left = current_user.password_expiry_days - password_age.days
    
    expiry_date = current_user.password_changed_at + timedelta(days=current_user.password_expiry_days)
    
    remaining_delta = expiry_date - datetime.utcnow()
    hours_left = int(remaining_delta.total_seconds() // 3600) % 24
    minutes_left = int(remaining_delta.total_seconds() // 60) % 60
    
    return render_template(
        'dashboard.html',
        days_left=max(0, remaining_delta.days),
        hours_left=max(0, hours_left),
        minutes_left=max(0, minutes_left),
        expiry_date=expiry_date.strftime('%Y-%m-%d %H:%M:%S UTC'),
        created_date=current_user.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')
    )

@auth_bp.route('/change-password', methods=['GET', 'POST'])
def change_password():
    # Check if this is a forced change (stored in session) or self-initiated
    forced = 'force_change_user_id' in session
    
    if forced:
        user = User.query.get(session['force_change_user_id'])
        if not user:
            session.pop('force_change_user_id', None)
            return redirect(url_for('auth.login'))
    else:
        if not current_user.is_authenticated:
            return redirect(url_for('auth.login'))
        user = current_user
        
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if not new_password or not confirm_password or (not forced and not current_password):
            flash("All password fields are required.", "danger")
            return render_template('change_password.html', forced=forced)
            
        # Verify current password if self-initiated
        if not forced:
            if not verify_password(user.password_hash, current_password):
                flash("Invalid current password.", "danger")
                return render_template('change_password.html', forced=forced)
                
        # Confirm matching passwords
        if new_password != confirm_password:
            flash("New passwords do not match.", "danger")
            return render_template('change_password.html', forced=forced)
            
        # Validate strength of new password
        strength_errors = validate_password_strength(new_password)
        if strength_errors:
            for error in strength_errors:
                flash(error, "danger")
            return render_template('change_password.html', forced=forced)
            
        # Enforce history limit (prevent reuse of last 5)
        if check_password_reuse(user, new_password):
            flash("Security Policy Violation: You cannot reuse your current or any of your last 5 passwords.", "danger")
            log_security_event(
                event_type='PASSWORD_REUSE_BLOCKED',
                severity='INFO',
                description=f"User '{user.username}' attempted to reuse a password in history."
            )
            return render_template('change_password.html', forced=forced)
            
        # Update user record
        pwd_hash = hash_password(new_password)
        user.password_hash = pwd_hash
        user.password_changed_at = datetime.utcnow()
        user.failed_login_attempts = 0
        user.locked_until = None
        
        # Save to history
        hist = PasswordHistory(user_id=user.id, password_hash=pwd_hash)
        db.session.add(hist)
        db.session.commit()
        
        # Log event
        log_audit_event('PASSWORD_CHANGE', f"User '{user.username}' changed their password.", user.id)
        
        if forced:
            # Login the user now that they have changed their password
            session.pop('force_change_user_id', None)
            login_user(user)
            flash("Your password has been successfully updated. You have been logged in.", "success")
            if user.role.name == 'Security Administrator':
                return redirect(url_for('admin.dashboard'))
            return redirect(url_for('auth.dashboard'))
        else:
            flash("Your password has been changed.", "success")
            return redirect(url_for('auth.dashboard'))
            
    return render_template('change_password.html', forced=forced)
