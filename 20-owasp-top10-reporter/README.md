# 📊 OWASP Top 10 Compliance Reporter

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://python.org)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010-red.svg)](https://owasp.org)

Gerador de relatórios de conformidade com OWASP Top 10 2021.

## 🎯 OWASP Top 10 2021

1. A01 - Broken Access Control
2. A02 - Cryptographic Failures
3. A03 - Injection
4. A04 - Insecure Design
5. A05 - Security Misconfiguration
6. A06 - Vulnerable Components
7. A07 - Authentication Failures
8. A08 - Data Integrity Failures
9. A09 - Logging Failures
10. A10 - SSRF

## 🚀 Quick Start

```bash
pip install -r requirements.txt
python owasp_reporter.py --input scan_results.json --output compliance_report.html
```
