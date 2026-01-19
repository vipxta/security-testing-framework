# 🔓 Burp Suite API Integration

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://python.org)
[![Burp Suite](https://img.shields.io/badge/Burp%20Suite-Professional-orange.svg)](https://portswigger.net/burp)

Integração com a API REST do Burp Suite para automação de testes de penetração e análise de tráfego HTTP/HTTPS.

---

## ⚠️ Licença e Custos

| Versão | Preço | API REST |
|--------|-------|----------|
| **Community** | Gratuita | ❌ Não disponível |
| **Professional** | $449/ano | ✅ Disponível |
| **Enterprise** | Sob consulta | ✅ Disponível |

> **IMPORTANTE**: A API REST usada neste projeto **só funciona na versão Professional ou Enterprise**. A versão Community (gratuita) NÃO possui acesso à API.

### 🆓 Alternativas Gratuitas

Se você não possui Burp Suite Professional, considere:

| Ferramenta | Descrição | Link |
|------------|-----------|------|
| **OWASP ZAP** | Scanner de vulnerabilidades gratuito e open-source | [zaproxy.org](https://zaproxy.org) |
| **Nikto** | Scanner de web server | [github.com/sullo/nikto](https://github.com/sullo/nikto) |
| **SQLMap** | Detector de SQL Injection | [sqlmap.org](https://sqlmap.org) |

---

## 📋 Pré-requisitos

- Python 3.9 ou superior
- Burp Suite Professional instalado e em execução
- API Key do Burp Suite configurada

---

## 🛠️ Instalação

### 1. Instalar Python (se necessário)

```bash
# Ubuntu/Debian
sudo apt update && sudo apt install python3 python3-pip

# macOS (via Homebrew)
brew install python3

# Windows - Baixar de https://python.org/downloads/
```

### 2. Instalar Burp Suite Professional

1. Acesse [portswigger.net/burp/pro](https://portswigger.net/burp/pro)
2. Faça login ou crie uma conta
3. Baixe e instale o Burp Suite Professional
4. Ative sua licença

### 3. Configurar API do Burp Suite

1. Abra o Burp Suite Professional
2. Vá em **Settings > Suite > REST API**
3. Marque **"Service running"**
4. Copie a **API Key** gerada
5. Anote a URL da API (padrão: `http://127.0.0.1:1337`)

### 4. Instalar dependências Python

```bash
cd 02-burp-suite-api
pip install -r requirements.txt
```

---

## 🚀 Execução

```bash
# Scan básico
python burp_client.py --target https://example.com --api-key YOUR_API_KEY

# Scan completo com relatório
python burp_client.py --target https://example.com --api-key YOUR_API_KEY --output report.html
```

---

## 🎯 Funcionalidades

- ✅ Controle remoto do Burp Suite
- ✅ Scans ativos automatizados
- ✅ Extração de issues encontradas
- ✅ Gerenciamento de escopo
- ✅ Exportação de relatórios
- ✅ Integração CI/CD

---

## 📁 Estrutura

```
02-burp-suite-api/
├── burp_client.py      # Cliente principal da API
├── requirements.txt    # Dependências Python
└── README.md
```

---

## 👤 Autor

**Isaac Meneguini Albuquerque**
- 📧 isaacmeneguini@gmail.com
- 💼 [LinkedIn](https://www.linkedin.com/in/isaac-meneguini-albuquerque/)
