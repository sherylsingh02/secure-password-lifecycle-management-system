# CryptaShield: Secure Password Lifecycle & Cryptographic Key System

CryptaShield is a modular, cybersecurity-focused Flask web application demonstrating enterprise password policy enforcement, runtime cryptographic key isolation, and tamper-evident logging.

---

## 📁 Folder Structure
```
secure_auth_system/
├── app/
│   ├── __init__.py           # Application Factory
│   ├── config.py             # Flask/Database Configuration
│   ├── models.py             # SQLAlchemy Database Models
│   ├── crypto.py             # AES-256 / RSA-4096 / Argon2 Engines
│   ├── auth.py               # Password Policy, Locking & Audits
│   ├── routes.py             # User Authentications & Session Controls
│   ├── admin.py              # Security Dashboard Router
│   ├── templates/            # Jinja HTML Interface Templates
│   └── static/css/style.css  # Premium Glassmorphic Stylesheet
├── docs/
│   └── security_documentation.md  # Architectural diagrams, threat models
├── tests/
│   └── test_security.py      # Automated security testing suite
├── run.py                    # Application Entrypoint
├── requirements.txt          # Python Packages Dependencies
├── schema.sql                # Relational PostgreSQL Database Schema
└── README.md                 # Project Overview
```

---

## ⚡ Quickstart

### 1. Install Dependencies
Ensure Python 3.8+ is installed:
```bash
pip install -r requirements.txt
```

### 2. Configure Environment (`.env`)
By default, the application auto-heals and generates its own session secrets and AES master keys if none are set. To customize, configure the `.env` file:
- `SECRET_KEY`: Flask cookie signing key
- `DATABASE_URL`: PostgreSQL connection string (falls back to local SQLite if connection fails)
- `AES_MASTER_KEY`: 64-char hex key used to encrypt the RSA Private Key.

### 3. Run Application
```bash
python run.py
```
Open your browser to `http://127.0.0.1:5000`.

### 4. Default Credentials
During database initialization, the system seeds a default Security Administrator account:
- **Username:** `admin`
- **Password:** `AdminSecure2026!`

---

## 🧪 Security Verification (Tests)
Run the isolated test suite verifying lockouts, password reuse checks, log verification, and key rotations:
```bash
python -m unittest tests/test_security.py
```
All unit tests operate on transient in-memory databases and require zero configuration to execute.

---

## 🔐 Advanced Security Features Showcased
1. **Argon2id Hashes**: Constant-time verification, GPU-hard.
2. **Timing Attack Protections**: Executes fake Argon2 verification on non-existent usernames.
3. **AES-256-GCM Envelope Encryption**: RSA private key encrypted prior to SQL storage. Decrypted only inside memory at runtime.
4. **RSA-4096-PSS Logs**: Every audit log is digitally signed. Modifying log details in DB triggers alarm.
5. **Interactive Dashboard**: Admin controls to run log verification, simulate DB tampering, and execute cryptographic key rotations.
