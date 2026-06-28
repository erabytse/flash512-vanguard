"""
Core functionality tests for Flash512-Vanguard v3

Tests basic encryption/decryption, nonce uniqueness, and tamper detection.
"""

import os
import pytest
from flash512 import Flash512Vanguard

os.environ['FLASH512_VANGUARD_CORE'] = 'A' * 64


class TestCoreFunctionality:
    """Test suite for core encryption/decryption functionality."""
    
    def test_basic_encrypt_decrypt(self):
        """Test basic encryption and decryption."""
        plaintext = b"This is a highly confidential diplomatic message."
        user_secret = "MyFLASH512-VANGUARDTopSecret123!"
        
        token = Flash512Vanguard.protect(plaintext, user_secret)
        
        # Token should be a string
        assert isinstance(token, str)
        assert len(token) > 50
        
        # Decrypt
        decrypted = Flash512Vanguard.open(token, user_secret)
        assert decrypted == plaintext
    
    def test_nonce_uniqueness(self):
        """Test that identical messages produce different tokens (unique nonces)."""
        plaintext = b"This is a highly confidential diplomatic message."
        user_secret = "MyFLASH512-VANGUARDTopSecret123!"
        
        token1 = Flash512Vanguard.protect(plaintext, user_secret)
        token2 = Flash512Vanguard.protect(plaintext, user_secret)
        
        # Tokens should be different (different nonces)
        assert token1 != token2
    
    def test_tamper_detection(self):
        """Test that tampered tokens are rejected."""
        plaintext = b"This is a highly confidential diplomatic message."
        user_secret = "MyFLASH512-VANGUARDTopSecret123!"
        
        token = Flash512Vanguard.protect(plaintext, user_secret)
        
        # Corrupt the token (modify last 5 characters)
        corrupted_token = token[:-5] + "ABCDE"
        
        # Should raise ValueError (not PermissionError)
        with pytest.raises(ValueError, match="Decryption failed"):
            Flash512Vanguard.open(corrupted_token, user_secret)
    
    def test_wrong_password_rejected(self):
        """Test that wrong password is rejected."""
        plaintext = b"Test data"
        correct_password = "CorrectPass123"
        wrong_password = "WrongPass456"
        
        token = Flash512Vanguard.protect(plaintext, correct_password)
        
        with pytest.raises(ValueError):
            Flash512Vanguard.open(token, wrong_password)