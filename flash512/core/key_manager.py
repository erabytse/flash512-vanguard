"""
Flash512-Vanguard Pro: Key Manager Professionnel

Gestion des secrets avec :
- Rotation de clés (key rotation)
- Journalisation d'audit (audit logging)
- Support HSM/TPM prêt (interface extensible)
- Validation de force des secrets

Ce module est la base pour l'offre Enterprise.
"""
import os
import hashlib
import secrets
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, List
from pathlib import Path


# =============================================================================
# CONFIGURATION
# =============================================================================

# Niveau de logging pour l'audit
AUDIT_LOGGER_NAME = "flash512.audit"
DEFAULT_AUDIT_PATH = Path("./flash512_audit.log")

# Exigences de sécurité pour les secrets
MIN_SECRET_LENGTH = 32
RECOMMENDED_SECRET_LENGTH = 64


# =============================================================================
# AUDIT LOGGER
# =============================================================================

class AuditLogger:
    """
    Journalisation sécurisée des opérations sensibles.
    
    Conforme aux exigences SOC2, HIPAA, RGPD pour le tracking d'audit.
    """
    
    def __init__(self, log_path: Optional[Path] = None, enabled: bool = True):
        self.enabled = enabled
        self.log_path = log_path or DEFAULT_AUDIT_PATH
        self._logger = None
        
        if self.enabled:
            self._setup_logger()
    
    def _setup_logger(self):
        """Configure le logger d'audit."""
        self._logger = logging.getLogger(AUDIT_LOGGER_NAME)
        self._logger.setLevel(logging.INFO)
        
        # Éviter les doublons de handlers
        if not self._logger.handlers:
            handler = logging.FileHandler(self.log_path, encoding='utf-8')
            formatter = logging.Formatter(
                '%(asctime)s | %(levelname)s | %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            handler.setFormatter(formatter)
            self._logger.addHandler(handler)
    
    def log(self, event_type: str, details: Dict):
        """
        Enregistre un événement d'audit.
        
        Args:
            event_type: Type d'événement (KEY_ROTATION, SECRET_ACCESS, etc.)
            details: Dictionnaire de détails (sans secrets bruts !)
        """
        if not self.enabled or not self._logger:
            return
        
        # Ne jamais logger les secrets bruts
        safe_details = {
            k: v for k, v in details.items() 
            if not any(sensitive in k.lower() for sensitive in ['secret', 'password', 'key', 'token'])
        }
        
        self._logger.info(f"{event_type} | {safe_details}")
    
    def log_key_rotation(self, key_id: str, old_hash: str, new_hash: str):
        """Log spécifique pour rotation de clés."""
        self.log("KEY_ROTATION", {
            "key_id": key_id,
            "old_hash_prefix": old_hash[:8] if old_hash else None,
            "new_hash_prefix": new_hash[:8] if new_hash else None,
            "timestamp": datetime.utcnow().isoformat()
        })
    
    def log_secret_access(self, key_id: str, success: bool, reason: str = None):
        """Log spécifique pour accès aux secrets."""
        self.log("SECRET_ACCESS", {
            "key_id": key_id,
            "success": success,
            "reason": reason,
            "timestamp": datetime.utcnow().isoformat()
        })


# =============================================================================
# KEY MANAGER
# =============================================================================

class KeyManager:
    """
    Gestionnaire de clés professionnel pour Flash512-Vanguard.
    
    Fonctionnalités :
    - Génération de secrets cryptographiquement sûrs
    - Validation de force des secrets
    - Rotation de clés avec audit
    - Support multi-clés (préparation HSM)
    """
    
    def __init__(self, audit_logger: Optional[AuditLogger] = None):
        self.audit = audit_logger or AuditLogger()
        self._keys: Dict[str, str] = {}  # key_id -> secret (en mémoire uniquement)
        self._key_metadata: Dict[str, Dict] = {}  # key_id -> metadata
    
    @staticmethod
    def generate_secret(length: int = RECOMMENDED_SECRET_LENGTH) -> str:
        """
        Génère un secret cryptographiquement sûr.
        
        Args:
            length: Longueur du secret en caractères (min 32 recommandé)
        
        Returns:
            str: Secret aléatoire URL-safe de la longueur demandée
        
        Example:
            >>> secret = KeyManager.generate_secret(64)
            >>> len(secret)
            64
        """
        if length < MIN_SECRET_LENGTH:
            raise ValueError(f"Secret length must be at least {MIN_SECRET_LENGTH} characters")
        
        # secrets.token_urlsafe(n) génère ~4/3 * n caractères (base64url)
        # Pour obtenir length caractères, on calcule les bytes nécessaires
        # Formule : bytes_needed ≈ length * 3/4
        bytes_needed = max(1, int(length * 3 / 4))
        
        # secrets.token_urlsafe utilise os.urandom() -> cryptographically secure
        raw_secret = secrets.token_urlsafe(bytes_needed)
        
        # Tronquer ou étendre pour correspondre exactement à la longueur demandée
        if len(raw_secret) >= length:
            return raw_secret[:length]
        else:
            # Cas rare : si trop court, régénérer avec plus de bytes
            return KeyManager.generate_secret(length + 10)[:length]
    
    @staticmethod
    def validate_secret(secret: str, min_length: int = MIN_SECRET_LENGTH) -> Dict:
        """
        Valide la force d'un secret.
        
        Args:
            secret: Secret à valider
            min_length: Longueur minimale requise
        
        Returns:
            Dict: {
                'valid': bool,
                'score': int (0-100),
                'issues': List[str]
            }
        """
        issues = []
        score = 100
        
        # Check longueur
        if len(secret) < min_length:
            issues.append(f"Length below minimum ({len(secret)} < {min_length})")
            score -= 40
        
        # Check diversité caractères
        has_upper = any(c.isupper() for c in secret)
        has_lower = any(c.islower() for c in secret)
        has_digit = any(c.isdigit() for c in secret)
        has_special = any(not c.isalnum() for c in secret)
        
        diversity = sum([has_upper, has_lower, has_digit, has_special])
        
        if diversity < 3:
            issues.append(f"Limited character diversity ({diversity}/4 types)")
            score -= 20
        
        # Check patterns évidents
        if secret.lower() in ['password', 'secret', 'admin', 'flash512']:
            issues.append("Common pattern detected")
            score -= 30
        
        if len(set(secret)) < len(secret) * 0.5:
            issues.append("Too many repeated characters")
            score -= 20
        
        return {
            'valid': len(issues) == 0 and score >= 70,
            'score': max(0, score),
            'issues': issues
        }
    
    @staticmethod
    def hash_secret(secret: str) -> str:
        """
        Hash un secret pour stockage/verification sans exposition.
        
        Args:
            secret: Secret brut
        
        Returns:
            str: Hash SHA-256 du secret (pour audit/comparison)
        """
        return hashlib.sha256(secret.encode('utf-8')).hexdigest()
    
    def register_key(self, key_id: str, secret: str, metadata: Optional[Dict] = None) -> Dict:
        """
        Enregistre une nouvelle clé dans le gestionnaire.
        
        Args:
            key_id: Identifiant unique pour la clé
            secret: Secret brut (stocké en mémoire uniquement)
            metadata: Métadonnées optionnelles (created_by, purpose, etc.)
        
        Returns:
            Dict: {
                'key_id': str,
                'secret_hash': str,
                'created_at': str,
                'valid': bool
            }
        """
        # Validation
        validation = self.validate_secret(secret)
        if not validation['valid']:
            self.audit.log_secret_access(key_id, False, f"Weak secret: {validation['issues']}")
            raise ValueError(f"Secret validation failed: {validation['issues']}")
        
        # Enregistrement (mémoire uniquement - pas de persistance par défaut)
        self._keys[key_id] = secret
        self._key_metadata[key_id] = {
            'created_at': datetime.utcnow().isoformat(),
            'secret_hash': self.hash_secret(secret),
            'metadata': metadata or {}
        }
        
        self.audit.log_secret_access(key_id, True, "Key registered")
        
        return {
            'key_id': key_id,
            'secret_hash': self._key_metadata[key_id]['secret_hash'],
            'created_at': self._key_metadata[key_id]['created_at'],
            'valid': True
        }
    
    def get_key(self, key_id: str) -> Optional[str]:
        """
        Récupère un secret par son key_id.
        
        Args:
            key_id: Identifiant de la clé
        
        Returns:
            str: Secret brut, ou None si inexistant
        """
        secret = self._keys.get(key_id)
        
        if secret:
            self.audit.log_secret_access(key_id, True, "Key accessed")
        else:
            self.audit.log_secret_access(key_id, False, "Key not found")
        
        return secret
    
    def rotate_key(self, key_id: str, new_secret: str) -> Dict:
        """
        Rotation de clé : remplace un secret existant par un nouveau.
        
        Args:
            key_id: Identifiant de la clé à rotater
            new_secret: Nouveau secret
        
        Returns:
            Dict: {
                'key_id': str,
                'old_hash': str,
                'new_hash': str,
                'rotated_at': str
            }
        """
        if key_id not in self._keys:
            raise KeyError(f"Key '{key_id}' not found")
        
        old_hash = self._key_metadata[key_id]['secret_hash']
        
        # Validation du nouveau secret
        validation = self.validate_secret(new_secret)
        if not validation['valid']:
            raise ValueError(f"New secret validation failed: {validation['issues']}")
        
        # Rotation
        old_secret = self._keys[key_id]
        self._keys[key_id] = new_secret
        self._key_metadata[key_id]['secret_hash'] = self.hash_secret(new_secret)
        self._key_metadata[key_id]['rotated_at'] = datetime.utcnow().isoformat()
        
        # Audit
        self.audit.log_key_rotation(key_id, old_hash, self._key_metadata[key_id]['secret_hash'])
        
        return {
            'key_id': key_id,
            'old_hash': old_hash,
            'new_hash': self._key_metadata[key_id]['secret_hash'],
            'rotated_at': self._key_metadata[key_id]['rotated_at']
        }
    
    def list_keys(self) -> List[Dict]:
        """
        Liste toutes les clés enregistrées (sans les secrets bruts).
        
        Returns:
            List[Dict]: Métadonnées de chaque clé (hash only, pas de secrets)
        """
        return [
            {
                'key_id': key_id,
                'created_at': meta['created_at'],
                'rotated_at': meta.get('rotated_at'),
                'secret_hash_prefix': meta['secret_hash'][:8]
            }
            for key_id, meta in self._key_metadata.items()
        ]
    
    def delete_key(self, key_id: str) -> bool:
        """
        Supprime une clé du gestionnaire.
        
        Args:
            key_id: Identifiant de la clé à supprimer
        
        Returns:
            bool: True si supprimé, False si n'existait pas
        """
        if key_id in self._keys:
            del self._keys[key_id]
            del self._key_metadata[key_id]
            self.audit.log_secret_access(key_id, True, "Key deleted")
            return True
        return False


# =============================================================================
# HSM ADAPTER INTERFACE (pour extension future)
# =============================================================================

class HSMAdapter:
    """
    Interface pour adaptation HSM/TPM (Hardware Security Module).
    
    Cette classe est une base pour l'intégration avec :
    - AWS CloudHSM
    - Azure Key Vault
    - Google Cloud HSM
    - TPM matériel local
    
    À implémenter dans l'offre Enterprise.
    """
    
    def generate_key(self, key_id: str) -> str:
        """Génère une clé dans le HSM. À implémenter."""
        raise NotImplementedError("HSM adapter not implemented - Enterprise feature")
    
    def sign(self, key_id: str, data: bytes) -> bytes:
        """Signe des données avec une clé HSM. À implémenter."""
        raise NotImplementedError("HSM adapter not implemented - Enterprise feature")
    
    def verify(self, key_id: str, data: bytes, signature: bytes) -> bool:
        """Vérifie une signature avec une clé HSM. À implémenter."""
        raise NotImplementedError("HSM adapter not implemented - Enterprise feature")