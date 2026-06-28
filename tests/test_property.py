"""
Property-Based Tests for Flash512-Vanguard

Uses hypothesis to generate random test cases and verify properties.
"""

import os
import pytest
from hypothesis import given, strategies as st, settings
from flash512 import Flash512Vanguard

os.environ['FLASH512_VANGUARD_CORE'] = 'A' * 64


LONG_DEADLINE = settings(max_examples=50, deadline=2000)
MEDIUM_DEADLINE = settings(max_examples=30, deadline=2000)
SHORT_DEADLINE = settings(max_examples=20, deadline=5000) 

class TestPropertyBased:
    """Property-based test suite using hypothesis."""
    
    @given(
        plaintext=st.binary(min_size=1, max_size=10000),
        password=st.text(min_size=6, max_size=100).filter(lambda x: len(x) >= 6)
    )
    @LONG_DEADLINE
    def test_encrypt_decrypt_roundtrip(self, plaintext, password):
        """Property: encrypt then decrypt returns original plaintext."""
        token = Flash512Vanguard.protect(plaintext, password)
        decrypted = Flash512Vanguard.open(token, password)
        assert decrypted == plaintext
    
    @given(
        plaintext=st.binary(min_size=1, max_size=1000),
        password=st.text(min_size=6, max_size=50).filter(lambda x: len(x) >= 6)
    )
    @MEDIUM_DEADLINE
    def test_token_format_is_valid(self, plaintext, password):
        """Property: generated tokens have valid format."""
        token = Flash512Vanguard.protect(plaintext, password)
        
        # Token should be a string
        assert isinstance(token, str)
        
        # Token should have 6 parts (v3 format)
        parts = token.split('.')
        assert len(parts) == 6
        
        # Each part should be base64-encoded
        from base64 import b64decode
        for part in parts:
            decoded = b64decode(part)
            assert len(decoded) > 0
    
    @given(
        plaintext=st.binary(min_size=1, max_size=1000),
        password=st.text(min_size=6, max_size=50).filter(lambda x: len(x) >= 6)
    )
    @MEDIUM_DEADLINE
    def test_wrong_password_always_fails(self, plaintext, password):
        """Property: wrong password always fails to decrypt."""
        token = Flash512Vanguard.protect(plaintext, password)
        
        # Try a different password
        wrong_password = password + "wrong"
        
        with pytest.raises(ValueError):
            Flash512Vanguard.open(token, wrong_password)
    
    @given(
        plaintext=st.binary(min_size=1, max_size=1000),
        password=st.text(min_size=6, max_size=50).filter(lambda x: len(x) >= 6)
    )
    @MEDIUM_DEADLINE
    def test_verify_matches_open(self, plaintext, password):
        """Property: verify() returns True iff open() succeeds."""
        token = Flash512Vanguard.protect(plaintext, password)
        
        # verify() should return True
        assert Flash512Vanguard.verify(token, password) is True
        
        # verify() with wrong password should return False
        assert Flash512Vanguard.verify(token, password + "wrong") is False
    
    @given(
        plaintext=st.binary(min_size=1, max_size=1000),
        old_password=st.text(min_size=6, max_size=50).filter(lambda x: len(x) >= 6),
        new_password=st.text(min_size=6, max_size=50).filter(lambda x: len(x) >= 6)
    )
    @SHORT_DEADLINE
    def test_rotate_secret(self, plaintext, old_password, new_password):
        """Property: rotate_secret() re-encrypts with new password."""
        # Skip if passwords are the same
        if old_password == new_password:
            return
        
        token = Flash512Vanguard.protect(plaintext, old_password)
        
        # Rotate to new password
        new_token = Flash512Vanguard.rotate_secret(token, old_password, new_password)
        
        # Old password should fail
        with pytest.raises(ValueError):
            Flash512Vanguard.open(new_token, old_password)
        
        # New password should succeed
        decrypted = Flash512Vanguard.open(new_token, new_password)
        assert decrypted == plaintext