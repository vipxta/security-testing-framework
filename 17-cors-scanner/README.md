# 🌐 CORS Configuration Scanner

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://python.org)

Scanner de configurações CORS para identificação de más configurações.

## 🎯 Vulnerabilidades Detectadas

- Wildcard origin (*)
- Credentials com wildcard
- Origin reflection
- Null origin allowed
- Subdomains bypass

## 🚀 Quick Start

```bash
pip install -r requirements.txt
python cors_scanner.py --url https://api.example.com
```
