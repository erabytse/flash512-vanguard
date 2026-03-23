"""
Flash512-Vanguard Pro v2.0
Bibliothèque de chiffrement sécurisée pour Python.

Usage rapide :
    from flash512 import Flash512Vanguard
    
    # Chiffrer
    token = Flash512Vanguard.protect("données sensibles", "mon-password")
    
    # Déchiffrer
    data = Flash512Vanguard.open(token, "mon-password")

Configuration :
    Définir la variable d'environnement FLASH512_VANGUARD_CORE
    ou créer un fichier .env à la racine du projet.
"""

from .compat.legacy_wrapper import Flash512Vanguard

__version__ = "2.0.0.post1"
__author__ = "erabytse"
__all__ = ["Flash512Vanguard"]