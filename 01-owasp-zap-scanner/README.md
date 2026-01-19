# 🔓 OWASP ZAP Scanner Automation

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://python.org)
[![OWASP ZAP](https://img.shields.io/badge/OWASP%20ZAP-00549E?logo=owasp&logoColor=white)](https://zaproxy.org)
[![Docker](https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=white)](https://docker.com)

Scanner automatizado de vulnerabilidades web usando OWASP ZAP (Zed Attack Proxy).

---

## 💰 Licença

| Item | Status |
|------|--------|
| **OWASP ZAP** | ✅ **100% Gratuito e Open Source** (Apache 2.0) |
| **Todas as funcionalidades** | ✅ Gratuitas (incluindo API) |

> OWASP ZAP é mantido pela OWASP Foundation e é uma das melhores ferramentas gratuitas de segurança.

---

## 📋 Pré-requisitos

- Python 3.9 ou superior
- Docker (recomendado) ou Java 11+
- Mínimo 2GB RAM

---

## 🛠️ Instalação

### Opção 1: Docker (Recomendado)

```bash
# Baixar imagem oficial
docker pull zaproxy/zap-stable

# Verificar instalação
docker run -t zaproxy/zap-stable zap.sh -version
```

### Opção 2: Instalação Local

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install zaproxy

# macOS (via Homebrew)
brew install --cask owasp-zap

# Windows
# Baixar de: https://www.zaproxy.org/download/
# Executar o instalador .exe
```

### Opção 3: Snap (Linux)

```bash
sudo snap install zaproxy --classic
```

### Instalar dependências Python

```bash
cd 01-owasp-zap-scanner
pip install -r requirements.txt
```

---

## 🚀 Execução

### Iniciar ZAP em modo daemon

```bash
# Docker
docker run -d --name zap -p 8080:8080 zaproxy/zap-stable zap.sh -daemon -host 0.0.0.0 -port 8080

# Local
zap.sh -daemon -port 8080
```

### Executar Scanner

```bash
# Scan básico
python scanner.py --target https://example.com

# Scan completo com relatório
python scanner.py --target https://example.com --full --output report.html

# Via Docker (baseline scan)
docker run -t zaproxy/zap-stable zap-baseline.py -t https://example.com

# Via Docker (full scan)
docker run -t zaproxy/zap-stable zap-full-scan.py -t https://example.com
```

---

## 🎯 Funcionalidades

- ✅ Passive scanning
- ✅ Active scanning
- ✅ Spider/crawler
- ✅ AJAX spider
- ✅ Fuzzing
- ✅ API scanning (OpenAPI, GraphQL)
- ✅ Relatórios HTML/XML/JSON
- ✅ Integração CI/CD

---

## 📊 Vulnerabilidades Detectadas

| Categoria OWASP | Exemplos |
|-----------------|----------|
| A01 - Broken Access Control | IDOR, privilege escalation |
| A03 - Injection | SQL Injection, XSS, Command Injection |
| A05 - Security Misconfiguration | Headers faltantes, CORS |
| A07 - Authentication Failures | Session issues, weak passwords |

---

## 📁 Estrutura

```
01-owasp-zap-scanner/
├── scanner.py          # Scanner principal
├── zap_client.py       # Cliente da API ZAP
├── requirements.txt    # Dependências Python
├── config.yaml         # Configurações
└── README.md
```

---

## 👤 Autor

**Isaac Meneguini Albuquerque**
- 📧 isaacmeneguini@gmail.com
- 💼 [LinkedIn](https://www.linkedin.com/in/isaac-meneguini-albuquerque/)
