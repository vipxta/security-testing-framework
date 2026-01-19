# 🔒 SSL/TLS Security Checker

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://python.org)
[![OpenSSL](https://img.shields.io/badge/OpenSSL-721412?logo=openssl&logoColor=white)](https://openssl.org)

Verificador de configurações SSL/TLS para identificação de vulnerabilidades e más configurações.

---

## 💰 Licença

| Ferramenta | Licença | Preço |
|------------|---------|-------|
| **OpenSSL** | ✅ Apache 2.0 | **Gratuito** |
| **SSLyze** | ✅ AGPLv3 | **Gratuito** |
| **testssl.sh** | ✅ GPLv2 | **Gratuito** |
| **SSL Labs API** | ✅ Gratuito | **Gratuito** (rate limited) |

> Todas as ferramentas deste projeto são **100% gratuitas**.

---

## 📋 Pré-requisitos

- Python 3.9+
- OpenSSL instalado
- Conexão com internet (para testes externos)

---

## 🛠️ Instalação

### 1. Verificar/Instalar OpenSSL

```bash
# Verificar instalação
openssl version

# Ubuntu/Debian (geralmente já instalado)
sudo apt update
sudo apt install openssl

# macOS (geralmente já instalado via LibreSSL)
brew install openssl

# Windows
# Baixar de: https://slproweb.com/products/Win32OpenSSL.html
```

### 2. Instalar SSLyze

```bash
# Via pip (recomendado)
pip install sslyze

# Verificar
sslyze --version
```

### 3. Instalar testssl.sh (Opcional)

```bash
# Clone do repositório
git clone https://github.com/drwetter/testssl.sh.git
cd testssl.sh
./testssl.sh --version

# Ou via Docker
docker run -it drwetter/testssl.sh --version
```

### 4. Instalar dependências Python

```bash
cd 13-ssl-tls-checker
pip install -r requirements.txt
```

---

## 🚀 Execução

```bash
# Script Python
python ssl_checker.py --host example.com

# SSLyze diretamente
sslyze example.com

# testssl.sh
./testssl.sh example.com

# OpenSSL (verificação manual)
openssl s_client -connect example.com:443 -servername example.com

# Verificar certificado
openssl s_client -connect example.com:443 | openssl x509 -noout -dates
```

---

## 🎯 Funcionalidades

- ✅ Verificação de certificado
- ✅ Análise de protocolos (TLS 1.2, 1.3)
- ✅ Cipher suites testing
- ✅ Detecção de vulnerabilidades (POODLE, BEAST, Heartbleed)
- ✅ Certificate chain validation
- ✅ HSTS verification
- ✅ OCSP stapling check

---

## 📊 Vulnerabilidades Detectadas

| Vulnerabilidade | Descrição | Severidade |
|-----------------|-----------|------------|
| Heartbleed | CVE-2014-0160 | Crítica |
| POODLE | SSLv3 downgrade | Alta |
| BEAST | TLS 1.0 CBC | Média |
| ROBOT | RSA padding | Alta |
| Weak Ciphers | Export, NULL, DES | Alta |

---

## 📁 Estrutura

```
13-ssl-tls-checker/
├── ssl_checker.py      # Verificador principal
├── requirements.txt
└── README.md
```

---

## 👤 Autor

**Isaac Meneguini Albuquerque**
- 📧 isaacmeneguini@gmail.com
- 💼 [LinkedIn](https://www.linkedin.com/in/isaac-meneguini-albuquerque/)
