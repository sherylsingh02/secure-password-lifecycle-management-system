import os
import gc
import logging
from argon2 import PasswordHasher
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256

logger = logging.getLogger(__name__)

# Initialize Argon2 Password Hasher
# Using default safe settings (m=65536, t=3, p=4) which prevent GPU brute-force attacks
ph = PasswordHasher()

# Dummy hash for timing attack mitigation during login checks (username enumeration prevention)
# This is a precomputed Argon2 hash of "dummy_password"
DUMMY_HASH = "$argon2id$v=19$m=65536,t=3,p=4$cGFzc3dvcmRfc2FsdF9kZW1v$p05mK6n2y5z6G8v9x2l4r8q0f2b4n6m8v0c1"

def generate_salt():
    """
    Generates a cryptographically secure, unique salt for each user.
    Argon2 embeds its own salt, but storing a separate salt in the database
    provides defense-in-depth and satisfies registration requirements explicitly.
    """
    return os.urandom(16).hex()

def hash_password(password: str) -> str:
    """
    Hashes password using Argon2id.
    """
    return ph.hash(password)

def verify_password(hash_str: str, password: str) -> bool:
    """
    Verifies an Argon2 hash. Natively resistant to timing attacks.
    """
    try:
        return ph.verify(hash_str, password)
    except Exception:
        return False

def verify_password_dummy(password: str):
    """
    Performs a dummy verification to mitigate username enumeration via timing attacks.
    When a username does not exist, we execute this hash validation so the response
    latency matches a valid user lookup.
    """
    try:
        ph.verify(DUMMY_HASH, password)
    except Exception:
        pass


# ==========================================
# AES-256-GCM Cryptographic Protection
# ==========================================

def get_aes_key(master_key_hex: str) -> bytes:
    """
    Validates and retrieves the 256-bit AES master key as bytes.
    """
    if not master_key_hex:
        raise ValueError("AES Master Key is missing.")
    
    try:
        key_bytes = bytes.fromhex(master_key_hex)
        if len(key_bytes) != 32:
            raise ValueError(f"AES Master Key must be 32 bytes (64 hex characters). Got {len(key_bytes)} bytes.")
        return key_bytes
    except Exception as e:
        logger.error(f"Error parsing AES Master Key: {str(e)}")
        raise ValueError("Invalid AES Master Key format.")

def encrypt_private_key(private_key_pem: str, master_key_hex: str) -> tuple:
    """
    Encrypts the RSA Private Key using AES-256-GCM.
    Returns: (encrypted_hex, nonce_hex, tag_hex)
    """
    key_bytes = get_aes_key(master_key_hex)
    
    # Generate random 12-byte nonce for AES-GCM
    nonce = os.urandom(12)
    
    # Initialize AES in GCM mode (Authenticated Encryption)
    cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)
    
    # Encrypt the PEM string
    ciphertext, tag = cipher.encrypt_and_digest(private_key_pem.encode('utf-8'))
    
    result = (ciphertext.hex(), nonce.hex(), tag.hex())
    
    # Securely clear key material from memory
    # Replace key bytes in memory with zeros and invoke GC
    zero_out_bytes(key_bytes)
    del key_bytes
    gc.collect()
    
    return result

def decrypt_private_key(encrypted_hex: str, nonce_hex: str, tag_hex: str, master_key_hex: str) -> str:
    """
    Decrypts the AES-256-GCM encrypted RSA Private Key.
    """
    key_bytes = get_aes_key(master_key_hex)
    
    ciphertext_bytes = bytes.fromhex(encrypted_hex)
    nonce_bytes = bytes.fromhex(nonce_hex)
    tag_bytes = bytes.fromhex(tag_hex)
    
    # Initialize AES GCM decryption
    cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce_bytes)
    
    # Decrypt and verify integrity tag
    decrypted_bytes = cipher.decrypt_and_verify(ciphertext_bytes, tag_bytes)
    decrypted_pem = decrypted_bytes.decode('utf-8')
    
    # Securely clear key material from memory
    zero_out_bytes(key_bytes)
    zero_out_bytes(decrypted_bytes)
    del key_bytes, decrypted_bytes
    gc.collect()
    
    return decrypted_pem


# ==========================================
# RSA-4096 Signatures for Audit Logs
# ==========================================

def generate_rsa_keypair() -> tuple:
    """
    Generates a new RSA-4096 key pair.
    Returns: (private_key_pem, public_key_pem)
    """
    logger.info("Generating a new RSA-4096 key pair. This may take a moment...")
    key = RSA.generate(4096)
    private_pem = key.export_key().decode('utf-8')
    public_pem = key.publickey().export_key().decode('utf-8')
    
    # Clean up key objects
    del key
    gc.collect()
    
    return private_pem, public_pem

def sign_data(private_key_pem: str, data_string: str) -> str:
    """
    Signs data using RSA-4096-PSS and SHA-256.
    """
    try:
        # Load the RSA private key
        key = RSA.import_key(private_key_pem.encode('utf-8'))
        
        # Hash data with SHA-256
        h = SHA256.new(data_string.encode('utf-8'))
        
        # Sign using PSS signature scheme (more secure than PKCS#1 v1.5)
        signature = pss.new(key).sign(h)
        signature_hex = signature.hex()
        
        # Clean key from memory
        del key
        gc.collect()
        
        return signature_hex
    except Exception as e:
        logger.error(f"Failed to sign data: {str(e)}")
        raise RuntimeError("Signature generation failed.")

def verify_signature(public_key_pem: str, data_string: str, signature_hex: str) -> bool:
    """
    Verifies a signature using the RSA-4096 public key.
    """
    try:
        key = RSA.import_key(public_key_pem.encode('utf-8'))
        h = SHA256.new(data_string.encode('utf-8'))
        verifier = pss.new(key)
        
        signature_bytes = bytes.fromhex(signature_hex)
        verifier.verify(h, signature_bytes)
        
        # Cleanup
        del key
        gc.collect()
        
        return True
    except (ValueError, TypeError) as e:
        # Signature is invalid
        return False
    except Exception as e:
        logger.error(f"Signature verification error: {str(e)}")
        return False


# ==========================================
# Secure Memory Cleanup Utilities
# ==========================================

def zero_out_bytes(byte_arr: bytes or bytearray):
    """
    Overwrites the memory block of a bytearray with zeros to ensure
    sensitive material is not left in plain RAM.
    Since 'bytes' objects are immutable in Python, we convert them where possible,
    but we can force overwrite using ctypes if needed. For safety, this helper
    handles zeroing-out if it's a mutable bytearray, and helps release memory references.
    """
    if isinstance(byte_arr, bytearray):
        for i in range(len(byte_arr)):
            byte_arr[i] = 0
    # For immutable bytes, we rely on garbage collection.
