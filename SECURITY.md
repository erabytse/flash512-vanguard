# Security Policy — Flash512-Vanguard

## 📬 Reporting a Vulnerability

We take security very seriously. If you discover a vulnerability:

1. **Do NOT open a public issue** (to prevent exposure before a fix)
2. **Send an email to**: support@docudeeper.com
3. **Include**:
   - Detailed description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Affected version(s)

## ⏱️ Response Times

| Severity | Response Time | Patch Timeline |
|----------|---------------|----------------|
| Critical | 24 hours | 7 days |
| High | 48 hours | 14 days |
| Medium | 7 days | 30 days |
| Low | 14 days | Next release |

## 🔒 Best Practices for Users

1. **Internal Secret**: Generate a strong `FLASH512_VANGUARD_CORE` (64+ characters)
   ```bash
   python -c "import secrets; print(secrets.token_urlsafe(64))"
   ```
2. User Passwords: Minimum 8 characters, diversity recommended
3. Rotation: Use rotate_secret() for password changes
4. Audit: Enable logging for sensitive use cases
5. Updates: Keep the library up to date (pip install --upgrade flash512-vanguard)


🛡️ What We Guarantee

| Feature | Implementation | Standard |
| :--- | :---: | ---: |
| Encryption | AES-256-GCM | NIST FIPS 197 |
| Encryption | PBKDF2-HMAC-SHA512 (100k iterations) | OWASP recommended |
| Integrity | GCM authentication tag (16 bytes) | AEAD |
| Nonce | Cryptographically random (12 bytes) | NIST SP 800-38D |
| Secret Management | Environment-based + Key Manager | SOC2 compliant |

⚠️ What We Do NOT Guarantee
-❌ Protection against weak user passwords
-❌ Security if FLASH512_VANGUARD_CORE is compromised
-❌ Protection against side-channel attacks at application level
-❌ Legacy v1.0 custom cipher (use only for backward compatibility)

🧪 Security Testing

We maintain comprehensive test coverage:
```bash
    # Property-based testing (500+ random cases)
pytest tests/test_property.py -v

# Key Manager tests
python test_key_manager.py
```

📋 Version Security Status

| Version | Status | Support Until|
|:--- |:---:|---:|
|2.0.x|✅ Active| Current|
| 1.0.x|⚠️ Legacy (deprecated)|No security updates|


🔐 Known Limitations
1. Compression: If using compress=True, be aware of CRIME/BREACH-style attacks if user data is injectable
2. Memory: Secrets are stored in memory during operation (use HSM for enterprise isolation)
3. Timing: While we use timing-safe comparisons, application-level timing attacks are possible

📞 Security Contact

|Need|Contact|
|Vulnerability report|support@docudeeper.com
|Security audit request|support@docudeeper.com
|Enterprise security questions|support@docudeeper.com
|Last updated: March 2026|Version: 2.0.0.post1

Author: [@erabytse](https://fbfconsulting.org)