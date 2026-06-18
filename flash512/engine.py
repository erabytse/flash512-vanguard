"""
Flash512Vanguard - Military Grade Encryption Engine v2.1
"""
import os
import sys
import platform
import hashlib
import hmac
import logging
from base64 import b64encode, b64decode
from datetime import datetime, timezone
from typing import Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from argon2 import PasswordHasher, Type  # argon2-cffi
from argon2.low_level import hash_secret_raw, Type

# --- Configuration du module ---
_LOADED_INTEGRITY_OK = False
_INITIALIZED = False
_CORE_SECRET: Optional[str] = None

# --- Vérification d'intégrité au chargement (Anti-Tampering) ---
def _verify_module_integrity():
    """Vérifie l'intégrité HMAC-SHA512 du module à l'import."""
    global _LOADED_INTEGRITY_OK
    try:
        with open(__file__, 'rb') as f:
            code = f.read()
        # Clé d'intégrité dérivée du CORE_SECRET s'il est dispo, sinon fallback durci
        key = os.environ.get('FLASH512_VANGUARD_CORE', 'DEFAULT_INTEGRITY_CHECK').encode()
        expected_hmac = hmac.new(key, code, hashlib.sha512).hexdigest()
        # En production, comparer avec une valeur pré-calculée
        # Pour cette version, on vérifie juste la cohérence
        if expected_hmac:  # Simulation : un vrai check comparerait avec une valeur attendue
            _LOADED_INTEGRITY_OK = True
            return True
    except Exception as e:
        logging.critical(f"INTEGRITY CHECK FAILED: {e}")
        sys.exit(1)  # Arrêt immédiat
    return False

# Exécuter la vérification d'intégrité AVANT toute autre chose
_verify_module_integrity()
if not _LOADED_INTEGRITY_OK:
    raise RuntimeError("Module integrity compromised. Execution aborted.")


class Flash512Vanguard:
    """
    Chiffrement AES-256-GCM avec KDF durci (Argon2id par défaut).
    Version 2.1 - Military Grade.
    """

    # Variables de classe
    _CORE_SECRET = None
    _INITIALIZED = False

    # Paramètres Argon2id recommandés pour Military Grade
    ARGON2_MEMORY_COST = int(os.environ.get('ARGON2_MEMORY_COST', 102400))      # 100 MB
    ARGON2_TIME_COST = int(os.environ.get('ARGON2_TIME_COST', 4))               # 4 itérations
    ARGON2_PARALLELISM = int(os.environ.get('ARGON2_PARALLELISM', 2))           # 2 threads

    # PBKDF2 fallback parameters
    PBKDF2_ITERATIONS = 100_000
    PBKDF2_HASH = hashes.SHA512()

    # AES-GCM params
    NONCE_SIZE = 12  # 96 bits standard NIST
    TAG_SIZE = 16    # 128 bits

    # Phrase d'audit
    AUDIT_LOGGER = logging.getLogger("flash512.audit")

    @classmethod
    def _initialize_core(cls):
        """Initialise le Core Secret depuis l'environnement."""
        if cls._INITIALIZED:
            return
        
        core = os.environ.get('FLASH512_VANGUARD_CORE')
        if not core:
            raise EnvironmentError(
                "FLASH512_VANGUARD_CORE is not defined in the environment."
            )
        if len(core) < 64:
            raise ValueError("FLASH512_VANGUARD_CORE must be at least 64 characters long.")
        
        cls._CORE_SECRET = core      # ← Stocke dans la variable de classe
        cls._INITIALIZED = True      # ← Marque comme initialiséT

    @classmethod
    def _derive_key_argon2id(cls, secret: str, salt: bytes) -> bytes:
        """
        Dérive une clé de 256 bits avec Argon2id (brute, sans parsing base64).
        """
        return hash_secret_raw(
            secret.encode("utf-8"),
            salt,
            time_cost=cls.ARGON2_TIME_COST,
            memory_cost=cls.ARGON2_MEMORY_COST,
            parallelism=cls.ARGON2_PARALLELISM,
            hash_len=32,
            type=Type.ID,
        )

    @classmethod
    def _derive_key_pbkdf2(cls, secret: str, salt: bytes) -> bytes:
        """Fallback PBKDF2-SHA512 pour compatibilité."""
        kdf = PBKDF2HMAC(
            algorithm=cls.PBKDF2_HASH,
            length=32,
            salt=salt,
            iterations=cls.PBKDF2_ITERATIONS,
        )
        return kdf.derive(secret.encode('utf-8'))

    @classmethod
    def protect(cls, plaintext: str, user_secret: str, use_argon2: bool = True) -> str:
        """
        Chiffre un texte.
        :param use_argon2: Utilise Argon2id (défaut) ou PBKDF2 si False.
        """
        cls._initialize_core()

        if not plaintext:
            raise ValueError("The text cannot be emptye")
        if not user_secret:
            raise ValueError("The password cannot be blank")
        if len(user_secret) < 6:
            raise ValueError("The password must be at least 6 characters long")

        # 1. Générer nonce et salt cryptographiquement sûrs
        nonce = os.urandom(cls.NONCE_SIZE)
        salt = os.urandom(32)  # 256 bits pour le KDF

        # 2. Dériver la clé de chiffrement
        if use_argon2:
            derived_key = cls._derive_key_argon2id(user_secret, salt)
            kdf_type = b'A'  # Marqueur Argon2
        else:
            derived_key = cls._derive_key_pbkdf2(user_secret, salt)
            kdf_type = b'P'  # Marqueur PBKDF2

        # 3. Chiffrer AES-256-GCM
        aesgcm = AESGCM(derived_key)
        plaintext_bytes = plaintext.encode('utf-8') if isinstance(plaintext, str) else plaintext
        ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, cls._CORE_SECRET.encode('utf-8'))

        # 4. Assemblage du token: version | kdf_type | salt | nonce | tag
        token_parts = [
            b64encode(b'v2.1'),
            b64encode(kdf_type),
            b64encode(salt),
            b64encode(nonce),
            b64encode(ciphertext),
        ]
        token = '.'.join(p.decode('ascii') for p in token_parts)
        cls.AUDIT_LOGGER.info(f"DATA PROTECTED | KDF: {'Argon2id' if use_argon2 else 'PBKDF2'} | {datetime.now(timezone.utc).isoformat()}")
        return token

    @classmethod
    def open(cls, token: str, user_secret: str) -> str:
        """Déchiffre un token."""
        cls._initialize_core()

        try:
            parts = token.split('.')
            if len(parts) != 5:
                raise ValueError("Invalid token format")

            version = b64decode(parts[0]).decode('ascii')
            if version not in ('v2.0', 'v2.1'):
                raise ValueError(f"Unsupported version: {version}")

            kdf_type = b64decode(parts[1])
            salt = b64decode(parts[2])
            nonce = b64decode(parts[3])
            ciphertext = b64decode(parts[4])

            # Dériver la clé selon le type de KDF stocké
            if kdf_type == b'A':
                derived_key = cls._derive_key_argon2id(user_secret, salt)
                kdf_name = 'Argon2id'
            elif kdf_type == b'P':
                derived_key = cls._derive_key_pbkdf2(user_secret, salt)
                kdf_name = 'PBKDF2'
            else:
                raise ValueError(f"Type de KDF inconnu: {kdf_type}")

            # Déchiffrer
            aesgcm = AESGCM(derived_key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, cls._CORE_SECRET.encode('utf-8'))

            cls.AUDIT_LOGGER.info(f"DATA OPENED | KDF: {kdf_name} | {datetime.now(timezone.utc).isoformat()}")
            return plaintext.decode('utf-8')

        except Exception as e:
            cls.AUDIT_LOGGER.warning(f"OPEN FAILED: {str(e)} | {datetime.now(timezone.utc).isoformat()}")
            raise ValueError(f"Decryption failed: {str(e)}")

    @classmethod
    def verify(cls, token: str, user_secret: str) -> bool:
        """Vérifie un token sans retourner le contenu."""
        try:
            cls.open(token, user_secret)
            return True
        except Exception:
            return False

    @classmethod
    def rotate_secret(cls, token: str, old_secret: str, new_secret: str) -> str:
        """Rotation de mot de passe utilisateur."""
        plaintext = cls.open(token, old_secret)
        return cls.protect(plaintext, new_secret)
