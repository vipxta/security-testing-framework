# 💉 SQL Injection Detector

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://python.org)
[![OWASP](https://img.shields.io/badge/OWASP-A03:2021-red.svg)](https://owasp.org)

Ferramenta especializada em detectar e reportar vulnerabilidades de SQL Injection em formulários e parâmetros de URL.

## 🎯 Funcionalidades

- ✅ Detecção de SQL Injection (Union, Blind, Time-based)
- ✅ Teste de formulários automático
- ✅ Fuzzing de parâmetros
- ✅ Bypass de WAF
- ✅ Payloads customizáveis
- ✅ Integração com Burp/ZAP

## 🚀 Quick Start

```bash
# Instalar
pip install -r requirements.txt

# Scan básico
python sqli_detector.py --url "https://example.com/search?q=test"

# Scan completo com todos os payloads
python sqli_detector.py --url "https://example.com/login" --full --forms
```

## 📊 Tipos de SQL Injection Detectados

| Tipo | Descrição | Payload Exemplo |
|------|-----------|------------------|
| Union-based | Extração via UNION | `' UNION SELECT 1,2,3--` |
| Error-based | Erros de banco expostos | `' AND 1=CONVERT(int,@@version)--` |
| Blind Boolean | Respostas diferentes | `' AND 1=1--` vs `' AND 1=2--` |
| Time-based | Delays temporizados | `'; WAITFOR DELAY '0:0:5'--` |
| Stacked | Múltiplas queries | `'; DROP TABLE users--` |

## 📁 Estrutura

```
05-sql-injection-detector/
├── sqli_detector.py    # Detector principal
├── payloads/           # Arquivos de payloads
│   ├── generic.txt
│   ├── mysql.txt
│   ├── mssql.txt
│   └── postgres.txt
├── requirements.txt
└── config.yaml
```

## ⚙️ Configuração

```yaml
# config.yaml
detection:
  techniques:
    - union
    - error
    - blind_boolean
    - time_based
  
  time_delay: 5
  threads: 10
  timeout: 30

waf_bypass:
  enabled: true
  techniques:
    - case_variation
    - url_encoding
    - comment_injection
```
