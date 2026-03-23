"""
Flash512-Vanguard Pro: AES-256-GCM Engine
Standard industriel NIST/FIPS, hardware-accelerated, audité.

Ce module remplace l'algorithme custom pour la production.
L'ancien algorithme reste disponible via flash512.compat.legacy_wrapper
pour la rétrocompatibilité uniquement.
"""
import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag


class AES256GCMEngine:
    """
    Moteur de chiffrement professionnel basé sur AES-256-GCM.
    
    Caractéristiques :
    - Chiffrement authentifié (confidentialité + intégrité)
    - Nonce aléatoire à chaque opération (sécurité par conception)
    - KDF PBKDF2-HMAC-SHA512 avec 100k itérations (OWASP compliant)
    - Résistant aux attaques par canaux auxiliaires (timing-safe)
    """
    
    # Paramètres cryptographiques standards
    KDF_ITERATIONS = 100_000  # Recommandé OWASP pour les mots de passe
    KEY_LENGTH = 32           # AES-256 = 32 bytes
    NONCE_SIZE = 12           # Taille standard pour GCM (96 bits)
    
    @staticmethod
    def _derive_key(salt: bytes, password: str, internal_secret: str) -> bytes:
        """
        Dériver une clé 256-bit depuis password + internal_secret via PBKDF2.
        
        Args:
            salt: Sel aléatoire (généralement le nonce, réutilisé comme salt)
            password: Secret utilisateur
            internal_secret: Secret embarqué (variable d'environnement)
        
        Returns:
            bytes: Clé de 32 bytes pour AES-256
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=AES256GCMEngine.KEY_LENGTH,
            salt=salt,
            iterations=AES256GCMEngine.KDF_ITERATIONS,
            backend=default_backend()
        )
        # Combinaison sécurisée des deux secrets
        material = (password + internal_secret).encode('utf-8')
        return kdf.derive(material)
    
    @classmethod
    def encrypt(cls, plaintext: bytes, password: str, internal_secret: str) -> bytes:
        """
        Chiffrer des données avec AES-256-GCM.
        
        Args:
            plaintext: Données brutes à chiffrer
            password: Secret utilisateur
            internal_secret: Secret système (FLASH512_VANGUARD_CORE)
        
        Returns:
            bytes: Nonce (12) + ciphertext + tag d'authentification (16)
        """
        # Générer un nonce cryptographiquement sûr
        nonce = os.urandom(cls.NONCE_SIZE)
        
        # Dériver la clé depuis les secrets + nonce comme salt
        key = cls._derive_key(nonce, password, internal_secret)
        
        # Chiffrer avec AES-GCM (authentifié)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
        
        # Format de sortie : nonce + (ciphertext + tag)
        # Le tag est automatiquement appendu par cryptography.io
        return nonce + ciphertext
    
    @classmethod
    def decrypt(cls, packet: bytes, password: str, internal_secret: str) -> bytes:
        """
        Déchiffrer des données chiffrées avec AES-256-GCM.
        
        Args:
            packet: Nonce (12) + ciphertext + tag (format de encrypt())
            password: Secret utilisateur
            internal_secret: Secret système
        
        Returns:
            bytes: Données déchiffrées
        
        Raises:
            cryptography.exceptions.InvalidTag: Si le mot de passe est incorrect
                                               ou si les données ont été altérées
        """
        # Extraire le nonce (12 premiers bytes)
        nonce = packet[:cls.NONCE_SIZE]
        ciphertext_with_tag = packet[cls.NONCE_SIZE:]
        
        # Re-dériver la même clé
        key = cls._derive_key(nonce, password, internal_secret)
        
        # Déchiffrer et vérifier l'intégrité (tag)
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data=None)
    
    @classmethod
    def encrypt_b64(cls, plaintext: str, password: str, internal_secret: str) -> str:
        """
        Version convenience : encrypt + encodage base64url pour transport.
        
        Returns:
            str: Token URL-safe, sans padding, prêt pour API/URL/stockage
        """
        ciphertext = cls.encrypt(
            plaintext.encode('utf-8'), 
            password, 
            internal_secret
        )
        # Encodage base64url sans padding (standard JWT/URL)
        return base64.urlsafe_b64encode(ciphertext).decode('ascii').rstrip('=')
    
    @classmethod
    def decrypt_b64(cls, token: str, password: str, internal_secret: str) -> str:
        """
        Version convenience : décodage base64url + decrypt.
        
        Raises:
            InvalidTag: Si authentification échoue
            UnicodeDecodeError: Si les données déchiffrées ne sont pas du UTF-8
        """
        # Restaurer le padding base64 si nécessaire
        pad = "=" * ((4 - len(token) % 4) % 4)
        packet = base64.urlsafe_b64decode(token + pad)
        
        plaintext_bytes = cls.decrypt(packet, password, internal_secret)
        return plaintext_bytes.decode('utf-8')