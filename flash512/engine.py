"""
Flash512Vanguard - Production-Ready Cryptographic Abstraction Layer v3.0

A secure-by-default encryption library combining AES-256-GCM with memory-hard KDF.
Designed for applications that need strong encryption without cryptographic expertise.
"""

import os
import logging
from base64 import b64encode, b64decode
from datetime import datetime, timezone
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from argon2.low_level import hash_secret_raw, Type



class Flash512Vanguard:
    """
    Production-ready encryption engine using AES-256-GCM with Argon2id/PBKDF2.
    
    Token format (v3): version | kdf_type | kdf_params | salt | nonce | ciphertext
    All fields are base64-encoded and separated by dots.
    """
    
    # --- Class Attributes ---
    _CORE_SECRET = None
    _INITIALIZED = False
    
    # Audit logger (class attribute)
    AUDIT_LOGGER = logging.getLogger("flash512.audit")
    
    # Default Argon2id parameters (OWASP recommended)
    ARGON2_MEMORY_COST = int(os.environ.get('ARGON2_MEMORY_COST', 102400))  # 100 MB
    ARGON2_TIME_COST = int(os.environ.get('ARGON2_TIME_COST', 4))  # 4 iterations
    ARGON2_PARALLELISM = int(os.environ.get('ARGON2_PARALLELISM', 2))  # 2 threads
    
    # PBKDF2 fallback parameters
    PBKDF2_ITERATIONS = 100_000
    PBKDF2_HASH = hashes.SHA512()
    
    # AES-GCM constants
    NONCE_SIZE = 12  # 96 bits (NIST SP 800-38D)
    SALT_SIZE = 32   # 256 bits
    
    @classmethod
    def _initialize_core(cls):
        """Initialize the Core Secret from environment."""
        if cls._INITIALIZED:
            return
        
        core = os.environ.get('FLASH512_VANGUARD_CORE')
        if not core:
            raise EnvironmentError(
                "FLASH512_VANGUARD_CORE is not defined in the environment."
            )
        
        if len(core) < 64:
            raise ValueError("FLASH512_VANGUARD_CORE must be at least 64 characters long.")
        
        cls._CORE_SECRET = core
        cls._INITIALIZED = True
    
    @classmethod
    def _derive_key_argon2id(cls, secret: str, salt: bytes, 
                             memory_cost: int = None, 
                             time_cost: int = None, 
                             parallelism: int = None) -> bytes:
        """
        Derive a 256-bit key using Argon2id.
        
        Parameters are stored in the token to allow future parameter changes
        without breaking backward compatibility.
        """
        memory_cost = memory_cost or cls.ARGON2_MEMORY_COST
        time_cost = time_cost or cls.ARGON2_TIME_COST
        parallelism = parallelism or cls.ARGON2_PARALLELISM
        
        return hash_secret_raw(
            secret.encode("utf-8"),
            salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=32,
            type=Type.ID,
        )
    
    @classmethod
    def _derive_key_pbkdf2(cls, secret: str, salt: bytes, 
                           iterations: int = None) -> bytes:
        """Derive a 256-bit key using PBKDF2-HMAC-SHA512."""
        iterations = iterations or cls.PBKDF2_ITERATIONS
        
        kdf = PBKDF2HMAC(
            algorithm=cls.PBKDF2_HASH,
            length=32,
            salt=salt,
            iterations=iterations,
        )
        return kdf.derive(secret.encode('utf-8'))
    
    @classmethod
    def protect(cls, plaintext: bytes, user_secret: str, use_argon2: bool = True) -> str:
        """
        Encrypt data and return a self-describing token.
        
        :param plaintext: Data to encrypt (must be bytes)
        :param user_secret: User-provided password
        :param use_argon2: Use Argon2id (default) or PBKDF2 if False
        :return: Token string in format: v3.kdf_type.kdf_params.salt.nonce.ciphertext
        """
        cls._initialize_core()
        
        if not plaintext:
            raise ValueError("The plaintext cannot be empty")
        
        if not isinstance(plaintext, bytes):
            raise TypeError("plaintext must be bytes, not str. Use .encode('utf-8')")
        
        if not user_secret:
            raise ValueError("The password cannot be blank")
        
        if len(user_secret) < 6:
            raise ValueError("The password must be at least 6 characters long")
        
        # 1. Generate cryptographically secure nonce and salt
        nonce = os.urandom(cls.NONCE_SIZE)
        salt = os.urandom(cls.SALT_SIZE)
        
        # 2. Derive encryption key and prepare KDF parameters
        if use_argon2:
            derived_key = cls._derive_key_argon2id(user_secret, salt)
            kdf_type = b'A'  # Argon2id marker
            # Store parameters: mem=102400,time=4,parallel=2
            kdf_params = f"mem={cls.ARGON2_MEMORY_COST},time={cls.ARGON2_TIME_COST},parallel={cls.ARGON2_PARALLELISM}".encode()
        else:
            derived_key = cls._derive_key_pbkdf2(user_secret, salt)
            kdf_type = b'P'  # PBKDF2 marker
            # Store parameters: iter=100000
            kdf_params = f"iter={cls.PBKDF2_ITERATIONS}".encode()
        
        # 3. Encrypt with AES-256-GCM
        aesgcm = AESGCM(derived_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, cls._CORE_SECRET.encode('utf-8'))
        
        # 4. Assemble token: version | kdf_type | kdf_params | salt | nonce | ciphertext
        token_parts = [
            b64encode(b'v3'),
            b64encode(kdf_type),
            b64encode(kdf_params),
            b64encode(salt),
            b64encode(nonce),
            b64encode(ciphertext),
        ]
        
        token = '.'.join(p.decode('ascii') for p in token_parts)
        
        cls.AUDIT_LOGGER.info(
            f"DATA PROTECTED | KDF: {'Argon2id' if use_argon2 else 'PBKDF2'} | "
            f"{datetime.now(timezone.utc).isoformat()}"
        )
        
        return token
    
    @classmethod
    def open(cls, token: str, user_secret: str) -> bytes:
        """
        Decrypt a token and return the plaintext as bytes.
        
        Supports both v2.1 (5 parts) and v3 (6 parts) token formats.
        
        :param token: Token string from protect()
        :param user_secret: User password used during encryption
        :return: Decrypted data as bytes
        """
        cls._initialize_core()
        
        try:
            parts = token.split('.')
            
            # Detect token version by number of parts
            if len(parts) == 5:
                # v2.1 format: version | kdf_type | salt | nonce | ciphertext
                version = b64decode(parts[0]).decode('ascii')
                if version not in ('v2.0', 'v2.1'):
                    raise ValueError(f"Invalid v2 token version: {version}")
                
                kdf_type = b64decode(parts[1])
                salt = b64decode(parts[2])
                nonce = b64decode(parts[3])
                ciphertext = b64decode(parts[4])
                
                # Use DEFAULT parameters for v2.1 tokens
                if kdf_type == b'A':
                    derived_key = cls._derive_key_argon2id(user_secret, salt)
                    kdf_name = 'Argon2id'
                elif kdf_type == b'P':
                    derived_key = cls._derive_key_pbkdf2(user_secret, salt)
                    kdf_name = 'PBKDF2'
                else:
                    raise ValueError(f"Unknown KDF type: {kdf_type}")
            
            elif len(parts) == 6:
                # v3 format: version | kdf_type | kdf_params | salt | nonce | ciphertext
                version = b64decode(parts[0]).decode('ascii')
                if version != 'v3':
                    raise ValueError(f"Unsupported version: {version}")
                
                kdf_type = b64decode(parts[1])
                kdf_params_str = b64decode(parts[2]).decode('ascii')
                salt = b64decode(parts[3])
                nonce = b64decode(parts[4])
                ciphertext = b64decode(parts[5])
                
                # Parse KDF parameters from token
                if kdf_type == b'A':
                    params = dict(p.split('=') for p in kdf_params_str.split(','))
                    derived_key = cls._derive_key_argon2id(
                        user_secret, 
                        salt,
                        memory_cost=int(params['mem']),
                        time_cost=int(params['time']),
                        parallelism=int(params['parallel'])
                    )
                    kdf_name = 'Argon2id'
                elif kdf_type == b'P':
                    params = dict(p.split('=') for p in kdf_params_str.split(','))
                    derived_key = cls._derive_key_pbkdf2(
                        user_secret,
                        salt,
                        iterations=int(params['iter'])
                    )
                    kdf_name = 'PBKDF2'
                else:
                    raise ValueError(f"Unknown KDF type: {kdf_type}")
            
            else:
                raise ValueError(f"Invalid token format: expected 5 or 6 parts, got {len(parts)}")
            
            # Decrypt
            aesgcm = AESGCM(derived_key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, cls._CORE_SECRET.encode('utf-8'))
            
            cls.AUDIT_LOGGER.info(
                f"DATA OPENED | KDF: {kdf_name} | Version: {version} | {datetime.now(timezone.utc).isoformat()}"
            )
            
            return plaintext
        
        except Exception as e:
            cls.AUDIT_LOGGER.warning(
                f"OPEN FAILED: {str(e)} | {datetime.now(timezone.utc).isoformat()}"
            )
            raise ValueError(f"Decryption failed: {str(e)}")
    
    @classmethod
    def verify(cls, token: str, user_secret: str) -> bool:
        """Verify a token without returning the content."""
        try:
            cls.open(token, user_secret)
            return True
        except Exception:
            return False
    
    @classmethod
    def rotate_secret(cls, token: str, old_secret: str, new_secret: str) -> str:
        """Re-encrypt data with a new user password."""
        plaintext = cls.open(token, old_secret)
        return cls.protect(plaintext, new_secret)