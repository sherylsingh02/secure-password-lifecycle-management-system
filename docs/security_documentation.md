# Secure Password Lifecycle Management System: Technical & Security Documentation

This documentation details the system architecture, database design, cryptographic workflows, threat model, security controls mapping, and setup guides for **CryptaShield**.

---

## 1. System Architecture Diagram

This diagram outlines the three-tier system architecture and the runtime decoupling of cryptographic assets:

```mermaid
graph TD
    subgraph Client Layer
        Browser[Client Browser]
    end

    subgraph Application Server [Flask Web Framework]
        Routes[Routes Controller: routes.py]
        Auth[Auth Engine & Policies: auth.py]
        Crypto[Crypto Module: crypto.py]
        Models[ORM Models: models.py]
    end

    subgraph Key Isolation
        Env[Environment Variables: .env]
    end

    subgraph Database Layer [PostgreSQL / SQLite Fallback]
        DB_Users[(Users & History Tables)]
        DB_Keys[(Encrypted Key Table)]
        DB_Logs[(Audit & Security Logs)]
    end

    Browser <-->|HTTP POST / GET| Routes
    Routes <--> Auth
    Auth <--> Crypto
    Auth <--> Models
    Models <--> DB_Users
    Models <--> DB_Logs
    Models <--> DB_Keys
    
    Env -->|AES Master Key| Crypto
    Crypto -->|Decrypt Key at Runtime| Auth
```

---

## 2. Database ER Diagram

Below is the normalized relational database design:

```mermaid
erDiagram
    ROLES {
        int id PK
        string name UNIQUE
    }
    USERS {
        int id PK
        string username UNIQUE
        string password_hash
        string salt
        int role_id FK
        datetime created_at
        int password_expiry_days
        datetime password_changed_at
        int failed_login_attempts
        datetime locked_until
        boolean is_active_user
    }
    PASSWORD_HISTORY {
        int id PK
        int user_id FK
        string password_hash
        datetime changed_at
    }
    LOGIN_ATTEMPTS {
        int id PK
        string username
        string ip_address
        datetime attempted_at
        boolean is_successful
    }
    AUDIT_LOGS {
        int id PK
        string event_type
        int user_id FK
        string description
        datetime timestamp
        string signature
    }
    SECURITY_EVENTS {
        int id PK
        string event_type
        string severity
        string description
        datetime timestamp
    }
    ENCRYPTED_KEYS {
        int id PK
        string key_name UNIQUE
        string encrypted_key_data
        string nonce
        string tag
        string public_key_data
        datetime created_at
    }

    ROLES ||--o{ USERS : "has"
    USERS ||--o{ PASSWORD_HISTORY : "maintains"
    USERS ||--o{ AUDIT_LOGS : "logs"
```

---

## 3. Data Flow Diagram (DFD)

The data flow below demonstrates the process of a standard login flow combined with password aging checks:

```mermaid
sequenceDiagram
    autonumber
    actor User as Client Browser
    participant App as Flask Server (routes.py)
    participant Auth as Auth Engine (auth.py)
    participant Crypto as Crypto Module (crypto.py)
    participant DB as Database

    User->>App: Submits credentials (username, password)
    App->>DB: Queries User record
    DB-->>App: Returns User record (hash, status, lock timer)
    
    alt Account is Locked
        App-->>User: Aborts, returns remaining Lockout duration
    else Account is Active
        App->>Crypto: Calls verify_password(hash, input_password)
        Note over Crypto: constant-time Argon2 verify
        Crypto-->>App: Verification result (True/False)
        
        alt Verification Failed
            App->>DB: Increments failed_login_attempts
            App->>DB: Record LoginAttempt (Fail)
            App-->>User: Returns "Invalid credentials"
        else Verification Succeeded
            App->>DB: Resets failed_login_attempts
            App->>DB: Record LoginAttempt (Success)
            
            alt Password is Expired (Age > Expiry Period)
                App->>User: Forces Redirect to /change-password
            else Password is Valid
                App->>Auth: log_audit_event("LOGIN_SUCCESS", ...)
                Auth->>DB: Fetch Encrypted RSA Key
                DB-->>Auth: Encrypted RSA Key (AES GCM Wrapped)
                Auth->>Crypto: Decrypt RSA Key with AES Master Key
                Crypto-->>Auth: Decrypted RSA Private Key
                Auth->>Crypto: Sign log signature ("timestamp|LOGIN_SUCCESS|...")
                Crypto-->>Auth: RSA Signature
                Note over Crypto,Auth: Clear RSA private key from memory
                Auth->>DB: Insert AuditLog with signature
                App-->>User: Access Granted, redirect to Dashboard
            end
        end
    end
```

---

## 4. Cryptographic Workflow Diagram

This diagram displays the secure key hierarchy and signing operations:

```mermaid
graph TB
    subgraph Storage [In Database]
        EncryptedRSA[Encrypted RSA Private Key]
        PublicRSA[Plaintext RSA Public Key]
    end

    subgraph Environment
        MasterKey[AES Master Key]
    end

    subgraph Runtime RAM [Ephemeral Memory]
        DecryptAction[AES-256-GCM Decrypt]
        DecryptedRSA[RSA Private Key]
        SignAction[RSA-4096-PSS SHA-256 Sign]
        WipeAction[Wipe Key from RAM]
    end

    subgraph Outputs
        Sig[Signature Hash]
    end

    MasterKey --> DecryptAction
    EncryptedRSA --> DecryptAction
    DecryptAction --> DecryptedRSA
    DecryptedRSA --> SignAction
    SignAction --> Sig
    SignAction --> WipeAction
    WipeAction -->|Wipe bytes & delete references| DecryptedRSA
```

---

## 5. Threat Model (STRIDE)

| Threat Category | Specific Threat | System Control / Countermeasure |
| :--- | :--- | :--- |
| **Spoofing** | Adversary attempts to login by guessing username credentials (Credential Stuffing). | Strict account lockouts after 5 consecutive failures, combined with a 15-minute cooldown period. |
| **Tampering** | Rogue DBA or hacker modifies audit log entries directly in the database. | RSA-4096-PSS log signature validation detects any changes in log text, user IDs, or timestamps. |
| **Repudiation** | User denies performing a specific administrative action. | Cryptographically signed audit trail logs prove origin and integrity of every critical action. |
| **Information Leak**| Attacker enumerates usernames by measuring execution time differences. | Timing attack mitigation via dummy Argon2 hashing calls when usernames do not exist in the database. |
| **Denial of Service**| Memory exhaustion via excessive concurrent password hashing. | SQLite fallback prevents downtime; Argon2 configurations are balanced to prevent GPU abuse but run smoothly in standard servers. |
| **Elevation of Privilege** | Normal user attempts to access the admin dashboard. | Role-Based Access Control (RBAC) checked server-side via python decorator (`@admin_required`). |

---

## 6. OWASP Top 10 Compliance Checklist

- **A01:2021-Broken Access Control**:
  - Enforced server-side checks for all endpoints. Admin routes require the `Security Administrator` role.
- **A02:2021-Cryptographic Failures**:
  - Never stores passwords in plaintext. Uses **Argon2id** for hashing.
  - RSA keys encrypted in-database with **AES-256-GCM**.
  - RSA signatures generated using **RSA-4096** with PSS padding and SHA-256.
- **A03:2021-Injection**:
  - Uses SQLAlchemy ORM which utilizes parameterized queries natively, neutralizing SQL Injection.
- **A07:2021-Identification and Authentication Failures**:
  - Enforces minimum 12 character password policies (upper, lower, digit, special symbol).
  - Implements password history lookup (rejects last 5 passwords).
  - Implements brute force lockouts.
  - Implements strict 15-minute session timeouts and session rotation upon state changes.

---

## 7. Installation & Deployment Guide

### Prerequisites
- Python 3.8 or higher
- PostgreSQL (optional, falls back to SQLite automatically if connection fails)

### Step 1: Clone and Setup Environment
Copy the project folder to your local directory.

### Step 2: Install Dependencies
Create a python virtual environment and run:
```bash
pip install -r requirements.txt
```

### Step 3: Configure Environment Variables
Create or edit the `.env` file at the root:
```ini
SECRET_KEY=your_flask_session_key
DATABASE_URL=postgresql://username:password@localhost:5432/secure_auth
AES_MASTER_KEY=64_char_hex_master_key
```
*Note: If `AES_MASTER_KEY` is not provided, the app will generate a secure key automatically on startup.*

### Step 4: Run Application
Start the Flask dev server:
```bash
python run.py
```
Access the application at `http://127.0.0.1:5000`.

### Step 5: Test Execution
To run the automated security checks, execute:
```bash
python -m unittest tests/test_security.py
```
All unit tests should pass with status OK.
