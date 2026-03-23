# ⚡ Flash512-Vanguard Pro v2.0

[![PyPI version](https://badge.fury.io/py/flash512-vanguard.svg)](https://pypi.org/project/flash512-vanguard/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

> **Next-Gen Secure Encryption Library for Python**  
> Standard industriel AES-256-GCM + PBKDF2 durci + gestion de clés professionnelle  
> Engineered for extreme privacy, designed for the international cybersecurity community.

---

## 🛡️ Why Flash512-Vanguard?

Standard encryption can be vulnerable if implemented incorrectly. Flash512-Vanguard provides a **secure-by-default abstraction layer** that combines:

| Layer | Implementation | Standard |
|-------|---------------|----------|
| **Hardened KDF** | PBKDF2-HMAC-SHA512 with 100,000 iterations | OWASP recommended |
| **Authenticated Encryption** | AES-256-GCM (128-bit tag) | NIST FIPS 197 |
| **Secure Nonce** | Cryptographically random per operation | NIST SP 800-38D |
| **Secret Management** | Environment-based + Key Manager | SOC2 compliant |

> 🔒 **v2.0 Breaking Change**: We've replaced our custom cipher with **AES-256-GCM** for production use. The legacy algorithm remains available for backward compatibility only (not recommended for new deployments).

---

## 🚀 Key Features

- ✅ **Polymorphic Output**: Same message encrypted twice = different tokens (random nonce)
- ✅ **Full Integrity**: GCM authentication tag detects any tampering
- ✅ **Key Rotation**: Built-in `rotate_secret()` for password changes
- ✅ **Audit Logging**: Enterprise-ready audit trail (SOC2/HIPAA compatible)
- ✅ **Simple API**: 2 methods (`protect()` / `open()`), zero crypto expertise needed

---

## 📢 Official Release: Flash512-Vanguard v2.0.0

**erabytse** is proud to announce the launch of Flash512-Vanguard **Pro v2.0**.

After extensive security review, we've transitioned from our custom cryptographic matrix to **industry-standard AES-256-GCM** for production deployments. This ensures:

- 🌍 **Interoperability** with other systems and languages
- 🔐 **Auditability** by third-party security firms
- ⚡ **Performance** via hardware acceleration (AES-NI)
- 📜 **Compliance** with NIST, FIPS, and enterprise security policies

The legacy v1.0 algorithm remains available via `use_legacy=True` for backward compatibility only.

---

## 🛡️ Vision

In an era of increasing cyber threats, we believe that encryption should be more than just a standard; it should be an **evolving fortress**. Flash512-Vanguard is our first step toward a suite of tools dedicated to **Digital Sovereignty** and **Advanced Privacy**.

**Our commitment**: Security through **transparency**, not obscurity. We use peer-reviewed standards so you can sleep at night.

---

## 💼 Commercial & Support

While the core engine is open-source under **Apache 2.0**, erabytse offers professional tiers for enterprise needs:

| Tier | Features | Price |
|------|----------|-------|
| **Core** | AES-GCM engine, Key Manager, audit logging | Free (Apache 2.0) |
| **Pro Support** | SLA 24h, priority patches, integration help | 499€/month |
| **Enterprise** | HSM/TPM support, SIEM integration, training | Custom quote |

**Services**:
- 🔐 **Custom Core Provisioning**: Tailored solutions for enterprise-grade isolation
- 🛡️ **Security Consulting**: Implementation audits for your infrastructure
- 📚 **Training**: Team workshops on secure encryption practices

📧 **Contact**: contact@fbfconsulting.org

---

## 💻 Quick Start

### 🔧 Installation

```bash
pip install flash512-vanguard
```
## 🔑 Configuration
Before using the engine, you must provision your Internal Core Secret. 
This secret acts as the unique architectural soul of your encryption.

**On Linux/Mac:**
export FLASH512_VANGUARD_CORE="your-secure-random-secret-64-chars-min"

**On Windows (PowerShell):**
$env:FLASH512_VANGUARD_CORE="your-secure-random-secret-64-chars-min"

Or create a .env file at your project root:

FLASH512_VANGUARD_CORE=your-secure-random-secret-64-chars-min

⚠️ Security Note: Never commit .env to version control. Add it to .gitignore.

📖 Usage

```python
from flash512 import Flash512Vanguard

# Encrypt
token = Flash512Vanguard.protect("Classified Data", "MyUltraStrongSecret")
print(f"Secure Token: {token}")

# Decrypt
original = Flash512Vanguard.open(token, "MyUltraStrongSecret")
print(f"Decrypted: {original}")

# Verify without decrypting
if Flash512Vanguard.verify(token, "MyUltraStrongSecret"):
    print("Token is valid ✓")

# Rotate user password
new_token = Flash512Vanguard.rotate_secret(token, "OldPassword", "NewPassword")

```

🧪 Testing

```bash
# Install dev dependencies
pip install -e .[dev]

# Run property-based tests (500+ random cases)
pytest tests/test_property.py -v

# Run Key Manager tests
python test_key_manager.py
```

📜 License & Commercial Use

This project is released under the Apache 2.0 License.

| Überschrift 1 | License Required |
| :--- | ---: |
| Open-source projects | Apache 2.0 (free) |
| Commercial proprietary software | Apache 2.0 (free, no disclosure required) |
| Enterprise support & SLA | Commercial agreement |
| HSM/TPM integration | Enterprise license |


For commercial integration support or enterprise features, please contact the author:

📧 Email: contact@fbfconsulting.org

🌐 GitHub: https://github.com/erabytse/flash512-vanguard

----
🙏 Credits

- Author: [@erabytse](https://fbfconsulting.org)

- Architecture v2.0: Industry-standard AES-256-GCM backend

- Inspired by: OWASP, NIST, cryptography.io

- Built for: The international cybersecurity community


📞 Support & Security

| Need                                        | Contact |
| :---                                        | :---                                             |
| Technical support                           | support@fbfconsulting.org                         |
| Security vulnerability                      | contact@fbfconsulting.org (do not open public issue) |
| Commercial inquiry                          | contact@fbfconsulting.org                            |

Security Policy: See SECURITY.md for vulnerability disclosure process.

Last updated: March 2026
Version: 2.0.0.post1


This project is released under the License apache 2.0. For commercial integration into proprietary software without disclosing your source code, please contact the author for a Commercial License.
