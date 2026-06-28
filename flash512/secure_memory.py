"""
SecureMemoryManager - Memory-hardened buffer management for Python

Uses ctypes to lock memory pages (prevent swapping) and securely wipe buffers.
"""

import ctypes
import ctypes.util
import sys
from contextlib import contextmanager
from typing import Optional


class SecureBuffer:
    """
    Memory-hardened buffer that prevents swapping to disk and auto-wipes on destruction.
    
    Features:
    - Locks memory pages using mlock() to prevent swapping to disk
    - Overwrites data with zeros before garbage collection
    - Context manager support for automatic cleanup
    """
    
    __slots__ = ('_buffer', '_size', '_locked', '_cleared')
    
    def __init__(self, data: bytes):
        if not isinstance(data, bytes):
            raise TypeError("SecureBuffer requires bytes, not str")
        
        self._size = len(data)
        self._cleared = False
        self._locked = False
        
        # Allocate mutable buffer using ctypes
        self._buffer = (ctypes.c_ubyte * self._size)()
        self._buffer[:] = data
        
        # Lock memory to prevent swapping to disk
        self._lock_memory()
    
    def _lock_memory(self):
        """Lock memory pages to prevent swapping to disk."""
        try:
            if sys.platform == 'win32':
                # Windows: VirtualLock
                ctypes.windll.kernel32.VirtualLock(
                    ctypes.pointer(self._buffer),
                    self._size
                )
                self._locked = True
            else:
                # Unix/Linux/macOS: mlock
                libc_name = ctypes.util.find_library('c')
                if libc_name:
                    libc = ctypes.CDLL(libc_name)
                    result = libc.mlock(ctypes.pointer(self._buffer), self._size)
                    if result == 0:
                        self._locked = True
        except Exception:
            # If mlock fails (e.g., insufficient permissions), continue without locking
            # This is a best-effort security measure
            pass
    
    def _unlock_memory(self):
        """Unlock memory pages."""
        if self._locked:
            try:
                if sys.platform == 'win32':
                    ctypes.windll.kernel32.VirtualUnlock(
                        ctypes.pointer(self._buffer),
                        self._size
                    )
                else:
                    libc_name = ctypes.util.find_library('c')
                    if libc_name:
                        libc = ctypes.CDLL(libc_name)
                        libc.munlock(ctypes.pointer(self._buffer), self._size)
            except Exception:
                pass
            finally:
                self._locked = False
    
    @property
    def data(self) -> bytes:
        """Get a copy of the data. Caller is responsible for clearing."""
        if self._cleared:
            raise RuntimeError("SecureBuffer has been wiped and is no longer readable.")
        return bytes(self._buffer)
    
    def wipe(self):
        """Securely wipe the buffer by overwriting with zeros."""
        if not self._cleared and self._buffer:
            # Overwrite with zeros
            for i in range(self._size):
                self._buffer[i] = 0
            
            # Unlock memory
            self._unlock_memory()
            
            self._cleared = True
            self._buffer = None
    
    def __del__(self):
        """Last chance: wipe at destructor."""
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
    Decrypt a token into a temporary SecureBuffer.
    
    The buffer is automatically wiped after the with block exits.
    
    Usage:
        with secure_open(token, password) as buffer:
            plaintext = buffer.data
            # Process plaintext...
        # Buffer is automatically wiped here
    """
    from .engine import Flash512Vanguard  # Local import to avoid circularity
    
    plaintext_bytes = Flash512Vanguard.open(encrypted_token, secret)
    buffer = SecureBuffer(plaintext_bytes)
    
    try:
        yield buffer
    finally:
        buffer.wipe()