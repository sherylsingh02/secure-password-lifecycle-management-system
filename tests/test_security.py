import unittest
from datetime import datetime, timedelta
import os
import sys

# Ensure project root is in sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app, db
from app.models import User, Role, PasswordHistory, AuditLog, SecurityEvent, EncryptedKey
from app.auth import (
    validate_password_strength, check_password_reuse, log_audit_event,
    get_signing_private_key, seed_database
)
from app.crypto import (
    verify_signature, decrypt_private_key, get_aes_key
)

class SecurityTestSuite(unittest.TestCase):

    def setUp(self):
        """
        Setup a temporary test environment using an in-memory SQLite database
        and a dedicated test configuration.
        """
        self.app = create_app()
        
        # Override configuration for isolated testing
        self.app.config['TESTING'] = True
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app.config['WTF_CSRF_ENABLED'] = False
        
        # Seed a dummy AES Master Key for unit test isolation
        self.test_aes_key = "d7a3f8c2e1b4a6f9c0e2d3b4f5a6e7d8c9b0a1f2e3d4c5b6a7f8e9d0c1b2a3f4"
        self.app.config['AES_MASTER_KEY'] = self.test_aes_key
        
        self.app_context = self.app.app_context()
        self.app_context.push()
        
        # Build tables and seed roles, keys, and default admin
        db.create_all()
        seed_database()
        
        # Fetch seeded role IDs
        self.user_role = Role.query.filter_by(name='User').first()
        self.admin_role = Role.query.filter_by(name='Security Administrator').first()
        
        # Client for routing tests
        self.client = self.app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_password_strength_enforcement(self):
        """
        Ensures password complexity policies are strictly enforced.
        """
        # Test Case: Too short (< 12)
        errors = validate_password_strength("Short123!")
        self.assertIn("Password must be at least 12 characters long.", errors)
        
        # Test Case: Missing Uppercase
        errors = validate_password_strength("lowercase123!")
        self.assertIn("Password must contain at least one uppercase letter.", errors)
        
        # Test Case: Missing Lowercase
        errors = validate_password_strength("UPPERCASE123!")
        self.assertIn("Password must contain at least one lowercase letter.", errors)
        
        # Test Case: Missing Number
        errors = validate_password_strength("NoNumbersHere!")
        self.assertIn("Password must contain at least one number.", errors)
        
        # Test Case: Missing Special Character
        errors = validate_password_strength("PassNoSpecial123")
        self.assertIn("Password must contain at least one special character.", errors)
        
        # Test Case: Valid Password
        errors = validate_password_strength("ComplexPass123!")
        self.assertEqual(len(errors), 0, f"Expected no errors, got: {errors}")

    def test_password_history_protection(self):
        """
        Verifies that users are blocked from reusing their current password or any of their last 5 passwords.
        """
        # Create a test user
        user = User(
            username="history_tester",
            password_hash="argon_dummy_hash_1",
            salt="salt1",
            role_id=self.user_role.id
        )
        db.session.add(user)
        db.session.commit()
        
        # Seed password history with mock hashes
        mock_passwords = [
            "PasswordOne123!", "PasswordTwo123!", "PasswordThree123!",
            "PasswordFour123!", "PasswordFive123!", "PasswordSix123!"
        ]
        
        from app.auth import hash_password
        
        # Save historical hashes
        historical_hashes = []
        for pw in mock_passwords:
            h = hash_password(pw)
            historical_hashes.append(h)
            
        # Set the current password hash to the last one (index 5)
        user.password_hash = historical_hashes[5]
        db.session.commit()
        
        # Record the other 5 in the history table
        for h in historical_hashes[:5]:
            hist = PasswordHistory(user_id=user.id, password_hash=h)
            db.session.add(hist)
        db.session.commit()
        
        # Test 1: Try reusing current password (Six)
        self.assertTrue(check_password_reuse(user, "PasswordSix123!"))
        
        # Test 2: Try reusing password in history (One through Five)
        self.assertTrue(check_password_reuse(user, "PasswordThree123!"))
        self.assertTrue(check_password_reuse(user, "PasswordOne123!"))
        
        # Test 3: Try using a fresh password
        self.assertFalse(check_password_reuse(user, "A-New-Unique-Password-2026!"))

    def test_account_lockout_and_cooldown(self):
        """
        Validates that accounts are locked after 5 failed login attempts
        and that a cooldown period is enforced.
        """
        # Create a user
        username = "lockout_tester"
        pwd = "TestPassword123!"
        from app.auth import hash_password
        
        user = User(
            username=username,
            password_hash=hash_password(pwd),
            salt="salt2",
            role_id=self.user_role.id
        )
        db.session.add(user)
        db.session.commit()
        
        # 1. First 4 failures
        for _ in range(4):
            response = self.client.post('/login', data={
                'username': username,
                'password': 'WrongPassword123!'
            })
            self.assertIn(b"Invalid username or password.", response.data)
            
        # Verify user is not locked yet
        self.assertLess(user.failed_login_attempts, 5)
        self.assertIsNone(user.locked_until)
        
        # 2. Fifth failure triggers lockout
        response = self.client.post('/login', data={
            'username': username,
            'password': 'WrongPassword123!'
        })
        
        # Refresh user instance from DB
        user = User.query.filter_by(username=username).first()
        self.assertEqual(user.failed_login_attempts, 5)
        self.assertIsNotNone(user.locked_until)
        self.assertGreater(user.locked_until, datetime.utcnow())
        
        # 3. Try logging in with CORRECT password during lockout
        response = self.client.post('/login', data={
            'username': username,
            'password': pwd
        })
        self.assertIn(b"Account is locked due to multiple failed attempts.", response.data)

    def test_audit_log_signing_and_tampering(self):
        """
        Confirms audit log signature verification detects unauthorized
        direct changes to database records.
        """
        # 1. Log an event
        log = log_audit_event("TEST_EVENT", "Initial secure audit log entry.", user_id=None)
        
        # Fetch public key for validation
        key_record = EncryptedKey.query.filter_by(key_name='audit_log_signing_rsa_private').first()
        public_pem = key_record.public_key_data
        
        # 2. Verify signature is valid initially
        canonical_str = f"{log.timestamp.isoformat()}|{log.event_type}|SYSTEM|{log.description}"
        is_valid = verify_signature(public_pem, canonical_str, log.signature)
        self.assertTrue(is_valid, "Initial signature verification should succeed.")
        
        # 3. Simulate database tampering by modifying description directly
        log.description = "Tampered secure audit log entry."
        db.session.commit()
        
        # 4. Verify signature fails on tampered data
        tampered_canonical_str = f"{log.timestamp.isoformat()}|{log.event_type}|SYSTEM|{log.description}"
        is_tampered_valid = verify_signature(public_pem, tampered_canonical_str, log.signature)
        self.assertFalse(is_tampered_valid, "Tampered signature verification must fail.")

    def test_key_rotation_and_vault_integrity(self):
        """
        Checks that key rotation generates a new valid key pair,
        re-encrypts the private key, and re-signs all past logs.
        """
        # Write some audit logs
        log_audit_event("EVENT_A", "Sample log event A")
        log_audit_event("EVENT_B", "Sample log event B")
        
        key_record = EncryptedKey.query.filter_by(key_name='audit_log_signing_rsa_private').first()
        old_public_pem = key_record.public_key_data
        old_encrypted_key = key_record.encrypted_key_data
        
        # Simulate rotation (using test credentials)
        # Log in as admin
        admin_user = User.query.filter_by(username='admin').first()
        
        # Execute key rotation via client endpoint
        # Set session variable directly since we are in test environment context
        with self.client.session_transaction() as sess:
            sess['_user_id'] = str(admin_user.id)
            sess['_fresh'] = True
            
        response = self.client.post('/admin/rotate-keys', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        
        # Fetch rotated key
        rotated_key_record = EncryptedKey.query.filter_by(key_name='audit_log_signing_rsa_private').first()
        
        # Verify keys have changed in the DB
        self.assertNotEqual(rotated_key_record.public_key_data, old_public_pem)
        self.assertNotEqual(rotated_key_record.encrypted_key_data, old_encrypted_key)
        
        # Run audit logs integrity check after key rotation
        # Ensure all logs are verified with the new public key
        logs = AuditLog.query.all()
        for l in logs:
            canonical_str = f"{l.timestamp.isoformat()}|{l.event_type}|{l.user_id or 'SYSTEM'}|{l.description}"
            is_valid = verify_signature(rotated_key_record.public_key_data, canonical_str, l.signature)
            self.assertTrue(is_valid, f"Log ID {l.id} signature must be valid under new public key.")

if __name__ == '__main__':
    unittest.main()
