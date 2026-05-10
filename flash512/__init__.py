"""
Flash512-Vanguard v2.1 - Military Grade Encryption
"""
import sys
import platform

# Empêcher l'écriture de core dumps en cas de crash (Military Grade)
if platform.system() == 'Linux':
    import resource
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except Exception:
        pass
from .engine import Flash512Vanguard
from .secure_memory import SecureBuffer, secure_open

__version__ = "2.1.0"
__all__ = ['Flash512Vanguard', 'SecureBuffer', 'secure_open']