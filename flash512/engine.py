import hashlib
import hmac
import os
import struct
import base64
import zlib

from dotenv import load_dotenv

load_dotenv()

class Flash512Vanguard:
    # On récupère le secret depuis le système de l'utilisateur ou du serveur
    # Si rien n'est configuré, le système refuse de démarrer (Sécurité maximale)
    _INTERNAL_SECRET = os.getenv("FLASH512_VANGUARD_CORE")
    _KDF_ITERATIONS = 100000  # Standard de haute sécurité
    

    @classmethod
    def _generate_matrix(cls, salt: bytes, user_secret: str) -> bytes:
        if not cls._INTERNAL_SECRET:
            raise EnvironmentError(
                "CRITICAL: FLASH512_VANGUARD_CORE environment variable not set. "
                "The engine cannot initialize without its internal soul."
            )
        # KDF Implementation: Hardens the user secret against brute-force
        stretched_key = hashlib.pbkdf2_hmac(
            'sha512', 
            user_secret.encode(), 
            salt + cls._INTERNAL_SECRET.encode(), 
            cls._KDF_ITERATIONS
        )
        return stretched_key

    @classmethod
    def protect(cls, plaintext: str, user_secret: str) -> str:
        compressed_data = zlib.compress(plaintext.encode("utf-8"), level=9)
        nonce = os.urandom(24)
        # The first 12 bytes of nonce are used as KDF salt
        matrix = cls._generate_matrix(nonce[:12], user_secret)
        
        alpha, beta, gamma, omega = matrix[0:16], matrix[16:32], matrix[32:48], matrix[48:64]
        ciphertext = bytearray()
        for i, b in enumerate(compressed_data):
            h_step = hashlib.sha512(beta + struct.pack(">I", i) + gamma).digest()
            mutated = (b + alpha[i % 16]) % 256
            ciphertext.append(mutated ^ (h_step[0] ^ omega[i % 16]))

        auth_tag = hmac.new(matrix, nonce + ciphertext, hashlib.sha512).digest()
        return base64.urlsafe_b64encode(nonce + ciphertext + auth_tag).decode("ascii").rstrip("=")

    @classmethod
    def open(cls, token: str, user_secret: str) -> str:
        pad = "=" * ((4 - len(token) % 4) % 4)
        packet = base64.urlsafe_b64decode(token + pad)
        nonce, auth_tag, ciphertext = packet[:24], packet[-64:], packet[24:-64]
        
        matrix = cls._generate_matrix(nonce[:12], user_secret)
        if not hmac.compare_digest(hmac.new(matrix, nonce + ciphertext, hashlib.sha512).digest(), auth_tag):
            raise PermissionError("Integrity failure: Wrong secret or tampered data.")

        alpha, beta, gamma, omega = matrix[0:16], matrix[16:32], matrix[32:48], matrix[48:64]
        buffer = bytearray()
        for i, b in enumerate(ciphertext):
            h_step = hashlib.sha512(beta + struct.pack(">I", i) + gamma).digest()
            original_mutated = b ^ (h_step[0] ^ omega[i % 16])
            buffer.append((original_mutated - alpha[i % 16]) % 256)

        return zlib.decompress(buffer).decode("utf-8")
