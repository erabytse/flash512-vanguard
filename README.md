<p align="center"><img width="170" height="177" alt="flash512_pic" src="https://github.com/user-attachments/assets/6175788a-e3e9-4c13-ba38-0356feab17ff" /></p>

# Flash512-Vanguard

**Production-Ready Cryptographic Abstraction Layer for Python**
A secure-by-default encryption library that combines AES-256-GCM with memory-hard key derivation (Argon2id/PBKDF2). Designed for applications that need strong encryption without requiring cryptographic expertise.

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 🎯 Philosophy

Flash512-Vanguard is **not** a cryptographic primitive library. It's an **opinionated abstraction layer** that:

- ✅ Uses industry-standard primitives (AES-256-GCM, Argon2id, PBKDF2)
- ✅ Makes the secure way the easy way (secure-by-default API)
- ✅ Handles the hard problems (nonce management, parameter rotation, memory protection)
- ✅ Provides backward compatibility (tokens are self-describing)

**We do NOT:**

- ❌ Invent new cryptographic algorithms
- ❌ Support legacy/deprecated algorithms (no RC4, DES, ECB, etc.)
- ❌ Claim to be "unbreakable" or "military-grade" (we use precise technical language)

---

## 🚀 Quick Start

### Installation

```bash
pip install flash512-vanguard
```

Basic Usage

```python
import os
from flash512 import Flash512Vanguard

# Set the Core Secret (required, must be >= 64 chars)
os.environ['FLASH512_VANGUARD_CORE'] = 'your-super-secret-core-key-at-least-64-characters-long'

# Encrypt data
plaintext = b"Sensitive user data"
password = "UserPassword123!"

token = Flash512Vanguard.protect(plaintext, password)
print(f"Token: {token}")
# Output: v3.A.bWVtPTEwMjQwMCx0aW1lPTQscGFyYWxsZWw9Mg==...

# Decrypt data
decrypted = Flash512Vanguard.open(token, password)
assert decrypted == plaintext
```

Secure Memory Management

```python
from flash512 import Flash512Vanguard, secure_open

# Decrypt into a memory-hardened buffer that auto-wipes
token = Flash512Vanguard.protect(b"Secret", "Pass123")

with secure_open(token, "Pass123") as buffer:
    plaintext = buffer.data
    # Process plaintext...
# Buffer is automatically wiped here (overwritten with zeros)
```

## 🔐 Security Features

1.Authenticated Encryption (AES-256-GCM)

- Confidentiality: AES-256 in GCM mode
- Integrity: GCM authentication tag detects tampering
- Nonce Management: Cryptographically secure random nonces (96-bit, NIST SP 800-38D)

  2.Memory-Hard Key Derivation

- Primary: Argon2id (resistant to GPU/ASIC attacks)
- Fallback: PBKDF2-HMAC-SHA512 (for compatibility)
- Configurable Parameters: Memory cost, time cost, parallelism

  3.Self-Describing Tokens

Tokens include version and KDF parameters, enabling:

- Backward compatibility (old tokens work with new library versions)
- Parameter rotation (upgrade security without breaking existing data)

Token Format (v3):

```text
v3 | kdf_type | kdf_params | salt | nonce | ciphertext
```

4.Memory Protection

- mlock(): Prevents sensitive data from being swapped to disk
- SecureBuffer: Auto-wipes memory on destruction
- Context Manager: Automatic cleanup with with statement

---

## 📊 Threat Model

**What Flash512-Vanguard Protects Against**:

✅ Database Breach: If an attacker steals your database, they cannot decrypt tokens without:

- The user's password
- The Core Secret (server-side environment variable)

✅ Tampering: GCM authentication detects any modification to tokens

✅ Memory Attacks: mlock() prevents sensitive data from being written to swap files

✅ Side-Channel Attacks: Uses constant-time operations where possible

**What Flash512-Vanguard Does NOT Protect Against**:

❌ Weak Passwords: If a user chooses "password123", no library can save them

❌ Core Secret Compromise: If an attacker gains access to your server's environment variables, all bets are off

❌ Client-Side Attacks: Keyloggers, screen capture, etc. are outside our scope

❌ Quantum Computers: AES-256 is post-quantum secure, but Argon2id/PBKDF2 are not

---

## ⚙️ Configuration

**Environment Variables**

```bash
# Required: Core Secret (must be >= 64 characters)
export FLASH512_VANGUARD_CORE="your-super-secret-core-key..."

# Optional: Argon2id parameters (OWASP recommended defaults)
export ARGON2_MEMORY_COST=102400  # 100 MB
export ARGON2_TIME_COST=4         # 4 iterations
export ARGON2_PARALLELISM=2       # 2 threads
```

**\***Choosing KDF Parameters**\***

**For most applications (default)**:

- Memory: 100 MB
- Time: 4 iterations
- Parallelism: 2 threads

**For high-security applications:**

- Memory: 256 MB
- Time: 6 iterations
- Parallelism: 4 threads

**For low-resource environments (use PBKDF2):**

```python
token = Flash512Vanguard.protect(data, password, use_argon2=False)
```

---

## 🔄 Migration & Backward Compatibility

**Token Versioning**

Flash512-Vanguard tokens are versioned. The library automatically detects the version and uses the correct parameters.

Supported versions:

- v2.0 / v2.1: Legacy format (no KDF parameters in token)
- v3: Current format (self-describing, includes KDF parameters)

**Rotating KDF Parameters**

If you want to increase security (e.g., higher Argon2 memory cost), new tokens will use the new parameters automatically. Old tokens remain decryptable because they include their original parameters.

```python
# Old token (created with mem=102400)
old_token = "v3.A.bWVtPTEwMjQwMCx0aW1lPTQscGFyYWxsZWw9Mg==..."

# Still works, even if you changed ARGON2_MEMORY_COST to 204800
plaintext = Flash512Vanguard.open(old_token, password)
```

---

## 🧪 Testing

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest --cov=flash512 tests/

# Run property-based tests
pytest tests/test_property.py
```

---

## 📚 API Reference

> Flash512Vanguard.protect(plaintext: bytes, user_secret: str, use_argon2: bool = True) -> str

Encrypt data and return a self-describing token.

**Parameters:**

- plaintext (bytes): Data to encrypt (must be bytes, not str)
- user_secret (str): User-provided password (min 6 characters)
- use_argon2 (bool): Use Argon2id (default) or PBKDF2 if False

Returns: Token string in v3 format

**Raises:**

- TypeError: If plaintext is not bytes
- ValueError: If password is too short or plaintext is empty
- EnvironmentError: If FLASH512_VANGUARD_CORE is not set

> Flash512Vanguard.open(token: str, user_secret: str) -> bytes

Decrypt a token and return the plaintext.

**Parameters:**

- token (str): Token string from protect()
- user_secret (str): User password used during encryption

Returns: Decrypted data as bytes

**Raises:**

- ValueError: If token is invalid, tampered, or password is wrong

> secure_open(token: str, secret: str) -> SecureBuffer

Context manager that decrypts into a memory-hardened buffer.

**Usage:**

```python
with secure_open(token, password) as buffer:
    plaintext = buffer.data
    # Process...
# Buffer auto-wiped here
```

---

## 🛡️ Security Best Practices

1. Use a strong Core Secret: Generate with openssl rand -base64 64
2. Rotate passwords: Use Flash512Vanguard.rotate_secret() periodically
3. Monitor audit logs: The library logs all encryption/decryption events
4. Use SecureBuffer: Always use secure_open() for sensitive data
5. Keep dependencies updated: Run pip-audit regularly

---

## 🤝 Contributing

## Contributions are welcome! Please read CONTRIBUTING.md for guidelines.

## 📄 License

MIT License - see LICENSE for details.

---

## 🙏 Acknowledgments

Built on top of:

- cryptography - AES-256-GCM implementation

- argon2-cffi - Argon2id implementation

---

📞 Support & Security

- Issues: GitHub Issues
- Security vulnerabilities: See SECURITY.md

---
