"""
Backward Compatibility Tests for Flash512-Vanguard v3

Ensures that tokens created with v2.0 and v2.1 can still be decrypted
with the v3 engine. This is critical for production deployments.
"""

import os
import pytest
from base64 import b64encode
from flash512 import Flash512Vanguard

# Configuration required for tests
os.environ['FLASH512_VANGUARD_CORE'] = 'A' * 64


class TestBackwardCompatibility:
    """Test suite for backward compatibility with v2.x tokens."""
    
    def _create_v2_token(self, plaintext: bytes, password: str, use_argon2: bool = True) -> str:
        """
        Simulate a v2.1 token format (without KDF parameters).
        
        v2.1 format: version | kdf_type | salt | nonce | ciphertext
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from argon2.low_level import hash_secret_raw, Type
        
        # Generate nonce and salt
        nonce = os.urandom(12)
        salt = os.urandom(32)
        
        # Derive key with DEFAULT parameters (what v2.1 would have used)
        if use_argon2:
            derived_key = hash_secret_raw(
                password.encode("utf-8"),
                salt,
                time_cost=4,
                memory_cost=102400,
                parallelism=2,
                hash_len=32,
                type=Type.ID,
            )
            kdf_type = b'A'
        else:
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.primitives import hashes
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA512(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            derived_key = kdf.derive(password.encode('utf-8'))
            kdf_type = b'P'
        
        # Encrypt
        core_secret = os.environ['FLASH512_VANGUARD_CORE']
        aesgcm = AESGCM(derived_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, core_secret.encode('utf-8'))
        
        # Assemble v2.1 token (5 parts, no kdf_params)
        token_parts = [
            b64encode(b'v2.1'),
            b64encode(kdf_type),
            b64encode(salt),
            b64encode(nonce),
            b64encode(ciphertext),
        ]
        
        return '.'.join(p.decode('ascii') for p in token_parts)
    
    def test_v21_argon2_token_decrypts_with_v3(self):
        """Test that v2.1 Argon2 tokens can be decrypted by v3."""
        plaintext = b"Legacy data from v2.1"
        password = "LegacyPassword123"
        
        # Create a v2.1 token
        v2_token = self._create_v2_token(plaintext, password, use_argon2=True)
        
        # Verify it's a v2.1 token (5 parts)
        parts = v2_token.split('.')
        assert len(parts) == 5
        
        # Decrypt with v3 engine
        decrypted = Flash512Vanguard.open(v2_token, password)
        assert decrypted == plaintext
    
    def test_v21_pbkdf2_token_decrypts_with_v3(self):
        """Test that v2.1 PBKDF2 tokens can be decrypted by v3."""
        plaintext = b"Legacy PBKDF2 data"
        password = "LegacyPass456"
        
        # Create a v2.1 token with PBKDF2
        v2_token = self._create_v2_token(plaintext, password, use_argon2=False)
        
        # Decrypt with v3 engine
        decrypted = Flash512Vanguard.open(v2_token, password)
        assert decrypted == plaintext
    
    def test_v3_token_has_6_parts(self):
        """Test that v3 tokens have 6 parts (includes kdf_params)."""
        plaintext = b"New v3 data"
        password = "V3Password789"
        
        token = Flash512Vanguard.protect(plaintext, password)
        parts = token.split('.')
        
        assert len(parts) == 6
        assert b64encode(b'v3').decode('ascii') == parts[0]
    
    def test_v3_token_roundtrip(self):
        """Test that v3 tokens can be encrypted and decrypted."""
        plaintext = b"Roundtrip test"
        password = "RoundtripPass"
        
        token = Flash512Vanguard.protect(plaintext, password)
        decrypted = Flash512Vanguard.open(token, password)
        
        assert decrypted == plaintext
    
    def test_mixed_v2_and_v3_tokens(self):
        """Test that both v2.1 and v3 tokens can coexist."""
        password = "MixedTest"
        
        # Create v2.1 token
        v2_plaintext = b"V2 data"
        v2_token = self._create_v2_token(v2_plaintext, password)
        
        # Create v3 token
        v3_plaintext = b"V3 data"
        v3_token = Flash512Vanguard.protect(v3_plaintext, password)
        
        # Both should decrypt correctly
        assert Flash512Vanguard.open(v2_token, password) == v2_plaintext
        assert Flash512Vanguard.open(v3_token, password) == v3_plaintext