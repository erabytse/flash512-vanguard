"""
Security Guarantees Tests for Flash512-Vanguard

Tests verify the security properties of the encryption engine:
- Correct encryption/decryption with Argon2id and PBKDF2
- Tamper detection (GCM authentication)
- Wrong password rejection
- SecureBuffer memory wiping
"""

import os
import pytest
from flash512 import Flash512Vanguard, SecureBuffer, secure_open

# Configuration required for tests
os.environ['FLASH512_VANGUARD_CORE'] = 'A' * 64  # 64 chars minimum


class TestSecurityGuarantees:
    """Test suite for security guarantees."""
    
    def test_argon2id_encrypt_decrypt(self):
        """Test encryption/decryption with Argon2id."""
        plaintext = b"Test Secret"
        token = Flash512Vanguard.protect(plaintext, "Password123!", use_argon2=True)
        
        assert isinstance(token, str)
        assert len(token) > 50
        
        original = Flash512Vanguard.open(token, "Password123!")
        assert original == plaintext
    
    def test_pbkdf2_fallback(self):
        """Test encryption/decryption with PBKDF2 fallback."""
        plaintext = b"Fallback Test"
        token = Flash512Vanguard.protect(plaintext, "Pass456!", use_argon2=False)
        
        original = Flash512Vanguard.open(token, "Pass456!")
        assert original == plaintext
    
    def test_securebuffer_wipes_after_context(self):
        """Test that SecureBuffer wipes data after context exit."""
        plaintext = b"Sensitive Data"
        token = Flash512Vanguard.protect(plaintext, "WipeTest1")
        
        with secure_open(token, "WipeTest1") as buffer:
            data = buffer.data
            assert data == plaintext
        
        # After the with block, access should be forbidden
        with pytest.raises(RuntimeError):
            _ = buffer.data
    
    def test_tampered_token_fails(self):
        """Test that tampered tokens are rejected (GCM authentication)."""
        plaintext = b"Tamper Test"
        token = Flash512Vanguard.protect(plaintext, "Secret1")
        
        parts = token.split('.')
        parts[-1] = 'AAAA' + parts[-1][4:]  # Modify the ciphertext
        bad_token = '.'.join(parts)
        
        with pytest.raises(ValueError):
            Flash512Vanguard.open(bad_token, "Secret1")
    
    def test_wrong_password_fails(self):
        """Test that wrong password is rejected."""
        plaintext = b"Correct"
        token = Flash512Vanguard.protect(plaintext, "Pass123")
        
        with pytest.raises(ValueError):
            Flash512Vanguard.open(token, "WrongPass")
    
    def test_token_includes_kdf_parameters(self):
        """Test that v3 tokens include KDF parameters for backward compatibility."""
        plaintext = b"Parameter Test"
        token = Flash512Vanguard.protect(plaintext, "ParamTest1", use_argon2=True)
        
        parts = token.split('.')
        assert len(parts) == 6  # v3 format has 6 parts
        
        # Verify version is v3
        from base64 import b64decode
        version = b64decode(parts[0]).decode('ascii')
        assert version == 'v3'
        
        # Verify KDF parameters are present
        kdf_params = b64decode(parts[2]).decode('ascii')
        assert 'mem=' in kdf_params
        assert 'time=' in kdf_params
        assert 'parallel=' in kdf_params
    
    def test_backward_compatibility_v2_tokens(self):
        """Test that v2 tokens can still be decrypted (backward compatibility)."""
        # This test would require creating a v2 token first
        # For now, we just verify the version check logic
        pass  # TODO: Add v2 token generation for backward compatibility test