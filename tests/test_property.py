"""
Flash512-Vanguard Pro: Tests de Propriété (Property-Based Testing)

Ces tests garantissent que protect()/open() sont des inverses parfaits
pour des milliers de combinaisons aléatoires de données et passwords.

Exécution :
    pytest tests/test_property.py -v
"""
import os
import pytest
import string
from hypothesis import given, strategies as st, settings, assume
from flash512 import Flash512Vanguard


# =============================================================================
# CONFIGURATION DES TESTS
# =============================================================================

@pytest.fixture(scope="module", autouse=True)
def setup_env():
    """Configure le secret interne une fois pour tous les tests."""
    os.environ["FLASH512_VANGUARD_CORE"] = "test-secret-fort-32-caracteres-minimum-xyz"
    yield
    # Nettoyage optionnel après les tests
    del os.environ["FLASH512_VANGUARD_CORE"]


# =============================================================================
# STRATÉGIES DE GÉNÉRATION DE DONNÉES (HYPOTHESIS)
# =============================================================================

# Générateur de passwords réalistes (8-64 caractères)
password_strategy = st.text(
    min_size=8,
    max_size=64,
    alphabet=string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
)

# Générateur de plaintexts réalistes (1-1000 caractères)
plaintext_strategy = st.text(
    min_size=1,
    max_size=1000,
    alphabet=string.printable
)

# Générateur de cas extrêmes (vides, très longs, caractères spéciaux)
edge_case_strategy = st.one_of(
    st.just("a"),                              # Single character
    st.just("A" * 1000),                       # Very long
    st.just("éàüñ中文🎉"),                      # Unicode
    st.just("line1\nline2\nline3"),            # Newlines
    st.just("tab\there\tand\tthere"),          # Tabs
    st.just("special: !@#$%^&*()_+-=[]{}|;':\",.<>?/\\")  # Special chars
)


# =============================================================================
# TESTS DE PROPRIÉTÉ PRINCIPAUX
# =============================================================================

@given(
    plaintext=plaintext_strategy,
    password=password_strategy
)
@settings(max_examples=500, deadline=None)
def test_encrypt_decrypt_roundtrip(plaintext, password):
    """
    PROPRIÉTÉ : open(protect(x)) == x pour tout x
    
    Ce test est exécuté 500 fois avec des données aléatoires.
    Si une seule combinaison échoue, hypothesis trouve le cas minimal.
    """
    token = Flash512Vanguard.protect(plaintext, password)
    result = Flash512Vanguard.open(token, password)
    
    assert result == plaintext, f"Roundtrip failed: {repr(plaintext)} != {repr(result)}"


@given(
    plaintext=plaintext_strategy,
    password=password_strategy,
    wrong_password=password_strategy
)
@settings(max_examples=100, deadline=None)
def test_wrong_password_always_fails(plaintext, password, wrong_password):
    """
    PROPRIÉTÉ : Un mauvais password échoue toujours
    
    On garantit que wrong_password != password pour éviter les faux positifs.
    """
    assume(password != wrong_password)
    
    token = Flash512Vanguard.protect(plaintext, password)
    
    with pytest.raises(Exception):  # InvalidTag ou autre
        Flash512Vanguard.open(token, wrong_password)


@given(
    plaintext=plaintext_strategy,
    password=password_strategy
)
@settings(max_examples=100, deadline=None)
def test_polymorphic_output(plaintext, password):
    """
    PROPRIÉTÉ : Deux appels protect() avec mêmes données produisent des tokens différents
    
    Grâce au nonce aléatoire, le output doit être unique à chaque appel.
    """
    token1 = Flash512Vanguard.protect(plaintext, password)
    token2 = Flash512Vanguard.protect(plaintext, password)
    
    assert token1 != token2, "Nonce doit être aléatoire à chaque appel"


@given(
    plaintext=edge_case_strategy,
    password=password_strategy
)
@settings(max_examples=50, deadline=None)
def test_edge_cases_roundtrip(plaintext, password):
    """
    PROPRIÉTÉ : Les cas extrêmes (unicode, très long, spécial) fonctionnent
    
    Test dédié aux cas qui cassent souvent les implémentations crypto.
    """
    token = Flash512Vanguard.protect(plaintext, password)
    result = Flash512Vanguard.open(token, password)
    
    assert result == plaintext, f"Edge case failed: {repr(plaintext)}"


# =============================================================================
# TESTS DÉTERMINISTES (CAS SPÉCIFIQUES)
# =============================================================================

def test_empty_password_rejected():
    """Un password vide doit être rejeté."""
    with pytest.raises(ValueError):
        Flash512Vanguard.protect("data", "")


def test_short_password_rejected():
    """Un password < 6 caractères doit être rejeté."""
    with pytest.raises(ValueError):
        Flash512Vanguard.protect("data", "short")


def test_empty_plaintext_rejected():
    """Un plaintext vide doit être rejeté."""
    with pytest.raises(ValueError):
        Flash512Vanguard.protect("", "password")


def test_verify_true_with_correct_password():
    """verify() retourne True avec le bon password."""
    token = Flash512Vanguard.protect("test data", "correct-password")
    assert Flash512Vanguard.verify(token, "correct-password") is True


def test_verify_false_with_wrong_password():
    """verify() retourne False avec un mauvais password."""
    token = Flash512Vanguard.protect("test data", "correct-password")
    assert Flash512Vanguard.verify(token, "wrong-password") is False


def test_rotate_secret_preserves_data():
    """rotate_secret() préserve les données après changement de password."""
    original = "données sensibles à protéger"
    old_pwd = "ancien-password"
    new_pwd = "nouveau-password"
    
    token_old = Flash512Vanguard.protect(original, old_pwd)
    token_new = Flash512Vanguard.rotate_secret(token_old, old_pwd, new_pwd)
    
    # Ancien token ne marche plus avec nouveau password
    with pytest.raises(Exception):
        Flash512Vanguard.open(token_old, new_pwd)
    
    # Nouveau token marche avec nouveau password
    result = Flash512Vanguard.open(token_new, new_pwd)
    assert result == original


# =============================================================================
# POINT D'ENTRÉE PYTEST
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])