"""
Flash512-Vanguard Pro: API Publique de Compatibilité

Ce module expose l'API Flash512Vanguard.protect()/open() familière,
mais route les opérations vers le moteur AES-256-GCM en production.

L'ancien algorithme custom reste accessible via use_legacy=True
uniquement pour la rétrocompatibilité (déconseillé en production).
"""
import os
import warnings
import zlib
import base64
from dotenv import load_dotenv
from ..core.aes_engine import AES256GCMEngine


class Flash512Vanguard:
    """
    API publique Flash512-Vanguard Pro v2.0
    
    Utilisation :
        from flash512 import Flash512Vanguard
        
        token = Flash512Vanguard.protect("secret data", "user-password")
        data = Flash512Vanguard.open(token, "user-password")
    
    Configuration requise :
        Variable d'environnement : FLASH512_VANGUARD_CORE
        (chargée automatiquement depuis .env si présent)
    """
    
    _INTERNAL_SECRET = None
    _SECRET_LOADED = False
    
    @classmethod
    def _ensure_secret(cls):
        """Charge le secret interne une seule fois au premier appel."""
        if cls._SECRET_LOADED:
            return
        
        # Charger .env si présent (silencieux si n'existe pas)
        load_dotenv()
        
        cls._INTERNAL_SECRET = os.getenv("FLASH512_VANGUARD_CORE")
        
        if not cls._INTERNAL_SECRET:
            raise EnvironmentError(
                "FLASH512_VANGUARD_CORE must be set in environment variables.\n"
                "Crée un fichier .env à la racine avec :\n"
                "FLASH512_VANGUARD_CORE=votre-secret-fort-aleatoire-32-caracteres-min"
            )
        
        cls._SECRET_LOADED = True
    
    @classmethod
    def protect(cls, plaintext: str, user_secret: str,
                use_legacy: bool = False, compress: bool = False) -> str:
        """
        Chiffre un message avec Flash512-Vanguard.
        
        Args:
            plaintext: Données texte à protéger
            user_secret: Mot de passe utilisateur (min 8 caractères recommandé)
            use_legacy: Force l'ancien algorithme custom (⚠️ déconseillé)
            compress: Active la compression avant chiffrement (⚠️ risque CRIME/BREACH)
        
        Returns:
            str: Token chiffré encodé en base64url (URL-safe, sans padding)
        
        Raises:
            EnvironmentError: Si FLASH512_VANGUARD_CORE n'est pas configuré
            ValueError: Si les paramètres sont invalides
        
        Example:
            >>> token = Flash512Vanguard.protect("mes données", "mon-password")
            >>> print(token)
            'xYz123...'
        """
        cls._ensure_secret()
        
        # Validation basique
        if not plaintext:
            raise ValueError("plaintext ne peut pas être vide")
        if not user_secret or len(user_secret) < 6:
            raise ValueError("user_secret doit faire au moins 6 caractères")
        
        # Préparation des données
        data = plaintext.encode('utf-8')
        
        if compress:
            warnings.warn(
                "Compression activée : vulnérable aux attaques CRIME/BREACH "
                "si des données utilisateur sont injectées dans le plaintext. "
                "À utiliser uniquement dans des contextes contrôlés.",
                UserWarning,
                stacklevel=2
            )
            data = zlib.compress(data, level=9)
        
        if use_legacy:
            warnings.warn(
                "Legacy mode activé : utilise l'ancien algorithme custom non audité. "
                "À réserver pour la rétrocompatibilité uniquement. "
                "Passe à use_legacy=False pour la production.",
                DeprecationWarning,
                stacklevel=2
            )
            # Route vers l'ancien algorithme (à implémenter dans legacy_cipher.py)
            from .legacy_cipher import _legacy_protect
            ciphertext = _legacy_protect(data, user_secret, cls._INTERNAL_SECRET)
            return base64.urlsafe_b64encode(ciphertext).decode('ascii').rstrip('=')
        
        # ✅ Mode production : AES-256-GCM
        return AES256GCMEngine.encrypt_b64(data.decode('utf-8'), user_secret, cls._INTERNAL_SECRET)
    
    @classmethod
    def open(cls, token: str, user_secret: str,
             use_legacy: bool = False, decompress: bool = False) -> str:
        """
        Déchiffre un token Flash512-Vanguard.
        
        Args:
            token: Token chiffré (sortie de protect())
            user_secret: Mot de passe utilisateur utilisé lors du chiffrement
            use_legacy: Force l'ancien algorithme custom (⚠️ déconseillé)
            decompress: Active la décompression après déchiffrement
        
        Returns:
            str: Données originales déchiffrées
        
        Raises:
            EnvironmentError: Si FLASH512_VANGUARD_CORE n'est pas configuré
            cryptography.exceptions.InvalidTag: Si le mot de passe est incorrect
                                               ou si le token a été altéré
            base64.binascii.Error: Si le token est mal formé
        
        Example:
            >>> data = Flash512Vanguard.open(token, "mon-password")
            >>> print(data)
            'mes données'
        """
        cls._ensure_secret()
        
        # Validation basique
        if not token:
            raise ValueError("token ne peut pas être vide")
        if not user_secret:
            raise ValueError("user_secret est requis")
        
        if use_legacy:
            from .legacy_cipher import _legacy_open
            # Restaurer padding base64
            pad = "=" * ((4 - len(token) % 4) % 4)
            packet = base64.urlsafe_b64decode(token + pad)
            data = _legacy_open(packet, user_secret, cls._INTERNAL_SECRET)
        else:
            # ✅ Mode production : AES-256-GCM
            data = AES256GCMEngine.decrypt_b64(token, user_secret, cls._INTERNAL_SECRET)
        
        if decompress:
            data = zlib.decompress(data.encode('utf-8')).decode('utf-8')
        
        return data
    
    @classmethod
    def verify(cls, token: str, user_secret: str) -> bool:
        """
        Vérifie si un token peut être déchiffré avec le secret fourni
        (sans retourner les données).
        
        Args:
            token: Token à vérifier
            user_secret: Mot de passe à tester
        
        Returns:
            bool: True si le déchiffrement réussit, False sinon
        """
        try:
            cls.open(token, user_secret)
            return True
        except Exception:
            return False
    
    @classmethod
    def rotate_secret(cls, old_token: str, old_secret: str, new_secret: str) -> str:
        """
        Re-chiffre un token avec un nouveau secret utilisateur.
        Utile pour la rotation de mots de passe.
        
        Args:
            old_token: Token actuel
            old_secret: Ancien mot de passe
            new_secret: Nouveau mot de passe
        
        Returns:
            str: Nouveau token chiffré avec new_secret
        """
        plaintext = cls.open(old_token, old_secret)
        return cls.protect(plaintext, new_secret)