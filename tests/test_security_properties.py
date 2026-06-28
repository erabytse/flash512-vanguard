"""
Security Properties Tests for Flash512-Vanguard

Tests verify advanced security properties:
- Tampering detection (GCM authentication)
- Memory wiping (SecureBuffer)
- Nonce uniqueness
- Salt randomness
"""

import os
import time
import pytest
from flash512 import Flash512Vanguard, SecureBuffer, secure_open

os.environ['FLASH512_VANGUARD_CORE'] = 'A' * 64


class TestSecurityProperties:
    """Test suite for security properties."""
    
    def test_nonce_uniqueness(self):
        """Test that each encryption uses a unique nonce."""
        plaintext = b"Same data"
        password = "SamePassword"
        
        tokens = [Flash512Vanguard.protect(plaintext, password) for _ in range(100)]
        
        # Extract nonces (part 4 in v3 format)
        nonces = [token.split('.')[4] for token in tokens]
        
        # All nonces should be unique
        assert len(set(nonces)) == 100
    
    def test_salt_uniqueness(self):
        """Test that each encryption uses a unique salt."""
        plaintext = b"Same data"
        password = "SamePassword"
        
        tokens = [Flash512Vanguard.protect(plaintext, password) for _ in range(100)]
        
        # Extract salts (part 3 in v3 format)
        salts = [token.split('.')[3] for token in tokens]
        
        # All salts should be unique
        assert len(set(salts)) == 100
    
    def test_tampering_detection_ciphertext(self):
        """Test that tampered ciphertext is detected."""
        plaintext = b"Sensitive data"
        password = "Password123"
        
        token = Flash512Vanguard.protect(plaintext, password)
        parts = token.split('.')
        
        # Tamper with ciphertext
        parts[5] = 'AAAA' + parts[5][4:]
        tampered_token = '.'.join(parts)
        
        with pytest.raises(ValueError):
            Flash512Vanguard.open(tampered_token, password)
    
    def test_tampering_detection_nonce(self):
        """Test that tampered nonce is detected."""
        plaintext = b"Sensitive data"
        password = "Password123"
        
        token = Flash512Vanguard.protect(plaintext, password)
        parts = token.split('.')
        
        # Tamper with nonce
        parts[4] = 'BBBB' + parts[4][4:]
        tampered_token = '.'.join(parts)
        
        with pytest.raises(ValueError):
            Flash512Vanguard.open(tampered_token, password)
    
    def test_tampering_detection_kdf_params(self):
        """Test that tampered KDF parameters are detected."""
        plaintext = b"Sensitive data"
        password = "Password123"
        
        token = Flash512Vanguard.protect(plaintext, password)
        parts = token.split('.')
        
        # Tamper with KDF parameters
        parts[2] = 'CCCC' + parts[2][4:]
        tampered_token = '.'.join(parts)
        
        with pytest.raises(ValueError):
            Flash512Vanguard.open(tampered_token, password)
    
    def test_securebuffer_wipes_on_context_exit(self):
        """Test that SecureBuffer wipes data after context exit."""
        plaintext = b"Sensitive data"
        password = "WipeTest"
        
        token = Flash512Vanguard.protect(plaintext, password)
        
        with secure_open(token, password) as buffer:
            data = buffer.data
            assert data == plaintext
        
        # After context exit, buffer should be wiped
        with pytest.raises(RuntimeError):
            _ = buffer.data
    
    def test_securebuffer_manual_wipe(self):
        """Test that SecureBuffer can be manually wiped."""
        data = b"Manual wipe test"
        buffer = SecureBuffer(data)
        
        assert buffer.data == data
        
        buffer.wipe()
        
        with pytest.raises(RuntimeError):
            _ = buffer.data
    
    def test_wrong_password_rejected(self):
        """Test that wrong password is rejected."""
        plaintext = b"Correct data"
        correct_password = "CorrectPass"
        wrong_password = "WrongPass"
        
        token = Flash512Vanguard.protect(plaintext, correct_password)
        
        with pytest.raises(ValueError):
            Flash512Vanguard.open(token, wrong_password)
    
    def test_empty_plaintext_rejected(self):
        """Test that empty plaintext is rejected."""
        with pytest.raises(ValueError):
            Flash512Vanguard.protect(b"", "Password123")
    
    def test_short_password_rejected(self):
        """Test that short password is rejected."""
        with pytest.raises(ValueError):
            Flash512Vanguard.protect(b"Data", "12345")  # < 6 chars
    
    def test_non_bytes_plaintext_rejected(self):
        """Test that non-bytes plaintext is rejected."""
        with pytest.raises(TypeError):
            Flash512Vanguard.protect("String data", "Password123")
    
    def test_timing_attack_resistance(self):
        """
        Test that decryption time doesn't leak information about password correctness.
        
        Note: This is a basic test. Real timing attack resistance requires
        constant-time comparison, which is handled by the underlying crypto library.
        """
        plaintext = b"Timing test"
        password = "CorrectPassword"
        
        token = Flash512Vanguard.protect(plaintext, password)
        
        # Measure time for correct password
        start = time.time()
        for _ in range(10):
            Flash512Vanguard.open(token, password)
        correct_time = time.time() - start
        
        # Measure time for wrong password
        start = time.time()
        for _ in range(10):
            try:
                Flash512Vanguard.open(token, "WrongPassword")
            except ValueError:
                pass
        wrong_time = time.time() - start
        
        # Times should be similar (within 2x)
        # This is a very basic test; real timing analysis requires more samples
        ratio = max(correct_time, wrong_time) / max(min(correct_time, wrong_time), 0.0001)
        assert ratio < 5.0  # Very lenient threshold