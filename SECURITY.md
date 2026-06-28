# Security Policy

## Supported Versions

| Version | Supported                                 |
| ------- | ----------------------------------------- |
| 3.x     | :white_check_mark:                        |
| 2.x     | :warning: (Legacy, security patches only) |
| < 2.0   | :x:                                       |

---

## Threat Model

### Assets Protected

1. **Confidentiality:** Encrypted data cannot be read without the user's password and Core Secret
2. **Integrity:** Tampered tokens are detected and rejected (GCM authentication)
3. **Memory Safety:** Sensitive data is protected from swap files and core dumps

### Threats Mitigated

| Threat              | Mitigation                                                                   |
| ------------------- | ---------------------------------------------------------------------------- |
| Database breach     | Tokens are encrypted with AES-256-GCM; attacker needs password + Core Secret |
| Token tampering     | GCM authentication tag detects modifications                                 |
| Memory scraping     | mlock() prevents swapping; SecureBuffer auto-wipes                           |
| Brute-force attacks | Argon2id is memory-hard (resistant to GPU/ASIC)                              |
| Replay attacks      | Nonces are cryptographically random and unique per encryption                |

### Threats NOT Mitigated (Out of Scope)

- **Weak passwords:** Library cannot compensate for "password123"
- **Core Secret compromise:** If server environment is compromised, all data is at risk
- **Client-side attacks:** Keyloggers, screen capture, etc.
- **Quantum attacks on KDF:** Argon2id/PBKDF2 are not post-quantum secure (but AES-256 is)

---

## Cryptographic Primitives

| Component                 | Algorithm          | Standard        |
| ------------------------- | ------------------ | --------------- |
| Encryption                | AES-256-GCM        | NIST SP 800-38D |
| Key Derivation (Primary)  | Argon2id           | RFC 9106        |
| Key Derivation (Fallback) | PBKDF2-HMAC-SHA512 | RFC 8018        |
| Nonce Generation          | os.urandom()       | CSPRNG          |
| Salt Generation           | os.urandom()       | CSPRNG          |

---

## Reporting a Vulnerability

**DO NOT create a public GitHub issue for security vulnerabilities.**

### Responsible Disclosure Process

1. **Email:** Send details to [security@flash512-vanguard.dev](mailto:security@flash512-vanguard.dev)
   - Include: Vulnerability description, steps to reproduce, potential impact
   - PGP key available at [PGP.txt](PGP.txt)

2. **Acknowledgment:** We will acknowledge receipt within 48 hours

3. **Assessment:** We will assess the vulnerability and provide a timeline within 7 days

4. **Fix:** We will develop and test a fix

5. **Disclosure:** We will coordinate public disclosure with you

### What to Report

- Buffer overflows or memory corruption
- Side-channel attacks (timing, cache, etc.)
- Weak random number generation
- Authentication bypass
- Token forgery
- Any deviation from documented security properties

### What NOT to Report

- Theoretical attacks without proof of concept
- Attacks requiring physical access to the server
- Attacks on deprecated algorithms (we don't support any)
- Issues in third-party libraries (report to them directly)

---

## Security Best Practices for Users

### 1. Core Secret Management

```bash
# Generate a strong Core Secret
openssl rand -base64 64 > core_secret.txt
chmod 600 core_secret.txt

# Load into environment (do NOT commit to git!)
export FLASH512_VANGUARD_CORE=$(cat core_secret.txt)
```

**Never:**

- ❌ Hardcode the Core Secret in source code
- ❌ Commit it to version control
- ❌ Share it over insecure channels
- ❌ Use a weak/short Core Secret (< 64 chars)

### 2. Password Requirements

Enforce strong passwords in your application:

- Minimum 12 characters
- Mix of uppercase, lowercase, numbers, symbols
- Check against breached password databases (e.g., Have I Been Pwned)

### 3. Memory Protection

Always use secure_open() for sensitive data:

```python
# ✅ Good: Memory is auto-wiped
with secure_open(token, password) as buffer:
    process(buffer.data)

# ❌ Bad: Plaintext stays in memory
plaintext = Flash512Vanguard.open(token, password)
process(plaintext)
# plaintext is still in memory until garbage collected
```

### 4. Audit Logging

Monitor the audit logger for suspicious activity:

```python
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("flash512.audit")

# Logs will show:
# DATA PROTECTED | KDF: Argon2id | 2026-06-29T...
# DATA OPENED | KDF: Argon2id | 2026-06-29T...
# OPEN FAILED: Decryption failed | 2026-06-29T...
```

### 5. Dependency Management

Keep dependencies updated:

```bash
# Check for vulnerabilities
pip-audit

# Update dependencies
pip install --upgrade flash512-vanguard cryptography argon2-cffi
```

---

### Known Limitations

1. Python Strings are Immutable: Once you call .decode('utf-8') on bytes, the string cannot be wiped from memory. Use SecureBuffer to keep data as bytes.

2. No Forward Secrecy: If the Core Secret is compromised, all past tokens can be decrypted (if the attacker also has the user passwords).

3. No Post-Quantum KDF: Argon2id and PBKDF2 are not quantum-resistant. However, AES-256 is post-quantum secure.

4. mlock() May Fail: On systems with low ulimit -l, mlock() may fail silently. The library continues without memory locking (best-effort).

---

### Security Audits

| Date       | Auditor  | Scope             | Report       |
| ---------- | -------- | ----------------- | ------------ |
| 2026-06-29 | Internal | v3.0 architecture | Audit Report |

> **We welcome third-party security audits. If you conduct one, please share the results.**

---

### Contact

- General questions: GitHub Discussions
