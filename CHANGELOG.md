# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.0] - 2026-06-29

### Added

- **Self-describing token format (v3)**: Tokens now include KDF parameters (memory cost, time cost, parallelism) for backward compatibility
- **SecureBuffer with mlock()**: Memory-hardened buffer that prevents swapping to disk using `mlock()` on Unix and `VirtualLock()` on Windows
- **Context manager support**: `secure_open()` for automatic memory cleanup
- **Backward compatibility**: v2.1 tokens can still be decrypted with v3 engine
- **Property-based testing**: Comprehensive test suite using `hypothesis`
- **CI/CD pipeline**: GitHub Actions for automated testing on multiple Python versions and OS

### Changed

- **API breaking change**: `protect()` now requires `bytes` instead of `str` for plaintext
- **API breaking change**: `open()` now returns `bytes` instead of `str`
- **Security improvement**: Removed Security Theater (fake cache flush, broken anti-tampering)
- **Security improvement**: KDF parameters are now stored in tokens, enabling parameter rotation
- **Documentation**: Professional README and SECURITY.md with threat model
- **Dependencies**: Updated to `cryptography>=41.0.0` and `argon2-cffi>=21.0.0`

### Fixed

- **Critical bug**: Anti-tampering check was always True (comparing string to True)
- **Critical bug**: Cache flush was ineffective (allocating memory doesn't clear CPU cache)
- **Backward compatibility**: v2.1 tokens now properly decrypted by detecting token format

### Removed

- **Security Theater**: Removed `_flush_cpu_caches()` (ineffective)
- **Security Theater**: Removed broken anti-tampering check
- **Marketing language**: Removed "Military Grade", "Unbreakable" claims
- **Legacy code**: Removed `engine.py` at root level (moved to `core/`)

### Security

- **Memory protection**: `SecureBuffer` now uses `mlock()` to prevent swapping to disk
- **Token format**: v3 tokens include KDF parameters for secure parameter rotation
- **Audit logging**: All encryption/decryption events are logged for security monitoring

## [2.1.0] - 2026-06-28

### Added

- Initial public release
- AES-256-GCM encryption with Argon2id/PBKDF2 key derivation
- Core Secret protection (defense in depth)
- Basic test suite

### Known Issues

- Security Theater present (fake cache flush, broken anti-tampering)
- No backward compatibility for parameter rotation
- Marketing language ("Military Grade") not appropriate for professional use

---

## Migration Guide: v2.x → v3.0.0

### Breaking Changes

1. **Plaintext must be bytes**:

   ```python
   # v2.x (deprecated)
   token = Flash512Vanguard.protect("my secret", password)

   # v3.0.0 (required)
   token = Flash512Vanguard.protect(b"my secret", password)
   ```

2. Decryption returns bytes:

   ```python
   # v2.x (deprecated)
   plaintext = Flash512Vanguard.open(token, password)  # returns str

   # v3.0.0 (required)
   plaintext = Flash512Vanguard.open(token, password)  # returns bytes
   text = plaintext.decode('utf-8')  # decode when needed
   ```

3. Use SecureBuffer for sensitive data:

   ```python
   # v3.0.0 (recommended)
   with secure_open(token, password) as buffer:
       plaintext = buffer.data  # bytes
       # Process plaintext...
   # Buffer is automatically wiped here
   ```

### Backward Compatibility

**_v3.0.0 can decrypt tokens created with v2.x:_**

```python
# Old token created with v2.1
old_token = "v2.1.A.c2FsdA==.bm9uY2U=.Y2lwaGVydGV4dA=="

# Still works with v3.0.0
plaintext = Flash512Vanguard.open(old_token, password)
```

### Parameter Rotation

**_v3.0.0 tokens include KDF parameters, so you can change them without breaking old tokens:_**

```python
# Change Argon2 parameters in environment
export ARGON2_MEMORY_COST=204800  # Increase from 100MB to 200MB

# New tokens use new parameters
new_token = Flash512Vanguard.protect(b"data", password)

# Old tokens still work (they include their original parameters)
old_plaintext = Flash512Vanguard.open(old_token, password)

```
