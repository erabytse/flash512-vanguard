import os
import pytest
from flash512 import Flash512Vanguard, SecureBuffer, secure_open

# Config nécessaire pour les tests
os.environ['FLASH512_VANGUARD_CORE'] = 'A' * 64  # 64 chars minimum

class TestMilitaryGrade:
    def test_argon2id_encrypt_decrypt(self):
        token = Flash512Vanguard.protect("Test Secret", "Password123!", use_argon2=True)
        assert isinstance(token, str)
        assert len(token) > 50
        original = Flash512Vanguard.open(token, "Password123!")
        assert original == "Test Secret"

    def test_pbkdf2_fallback(self):
        token = Flash512Vanguard.protect("Fallback Test", "Pass456!", use_argon2=False)
        original = Flash512Vanguard.open(token, "Pass456!")
        assert original == "Fallback Test"

    def test_securebuffer_wipes_after_context(self):
        token = Flash512Vanguard.protect("Sensitive Data", "WipeTest1")
        with secure_open(token, "WipeTest1") as buffer:
            data = buffer.data
            assert data == b"Sensitive Data"
        # Après le bloc with, l'accès doit être interdit
        with pytest.raises(RuntimeError):
            _ = buffer.data

    def test_tampered_token_fails(self):
        token = Flash512Vanguard.protect("Tamper Test", "Secret1")
        parts = token.split('.')
        parts[-1] = 'AAAA' + parts[-1][4:]  # Modifie le ciphertext
        bad_token = '.'.join(parts)
        with pytest.raises(ValueError):
            Flash512Vanguard.open(bad_token, "Secret1")

    def test_wrong_password_fails(self):
        token = Flash512Vanguard.protect("Correct", "Pass123")
        with pytest.raises(ValueError):
            Flash512Vanguard.open(token, "WrongPass")