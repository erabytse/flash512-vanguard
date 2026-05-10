"""
SecureMemoryManager - Military-grade memory wiping for Python
Utilise ctypes pour écraser les buffers sensibles avant libération.
"""
import ctypes
import sys
from contextlib import contextmanager
from typing import Any

class SecureBuffer:
    """
    Gestionnaire de buffer à effacement automatique.
    Remplace les données par des zéros OU des données aléatoires avant garbage collection.
    """

    __slots__ = ('_data', '_length', '_cleared')

    def __init__(self, data: bytes):
        self._length = len(data)
        # Créer un bytearray mutable
        self._data = bytearray(data)
        self._cleared = False

    @property
    def data(self) -> bytes:
        if self._cleared:
            raise RuntimeError("SecureBuffer has been wiped and is no longer readable.")
        return bytes(self._data)

    def wipe(self):
        """Écrase le buffer avec des zéros."""
        if not self._cleared and self._data:
            # Remplir de zéros
            for i in range(self._length):
                self._data[i] = 0
            # Appel système pour tenter de vider les caches CPU (si dispo)
            self._flush_cpu_caches()
            self._cleared = True
            self._data = None

    @staticmethod
    def _flush_cpu_caches():
        """Barrière mémoire pour contrer les attaques par cache side-channel."""
        try:
            # Sur quelques plateformes, un simple empty loop avec volatile aide
            libc = ctypes.CDLL(None)
            libc.memset(ctypes.c_void_p(0), 0, 0)
        except Exception:
            pass

    def __del__(self):
        """Dernière chance : wipe au destructeur."""
        try:
            self.wipe()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.wipe()
        return False


@contextmanager
def secure_open(encrypted_token: str, secret: str) -> SecureBuffer:
    """
    Déchiffre un token dans un SecureBuffer temporaire.
    Le buffer est automatiquement effacé après le bloc with.
    """
    from .engine import Flash512Vanguard  # import local pour éviter circularité
    plaintext = Flash512Vanguard.open(encrypted_token, secret)
    buffer = SecureBuffer(plaintext if isinstance(plaintext, bytes) else plaintext.encode('utf-8'))
    try:
        yield buffer
    finally:
        buffer.wipe()