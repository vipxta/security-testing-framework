# 🔌 Burp Suite API Integration

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://python.org)
[![Burp Suite](https://img.shields.io/badge/Burp-Suite%20Pro-orange.svg)](https://portswigger.net/burp)

Integração da API do Burp Suite Professional para automação de testes de penetração e análise de tráfego HTTP/HTTPS.

## 🎯 Funcionalidades

- ✅ Controle remoto do Burp Suite via REST API
- ✅ Automação de scans ativos
- ✅ Extração de issues e vulnerabilidades
- ✅ Gerenciamento de escopo
- ✅ Exportação de relatórios
- ✅ Integração com pipelines CI/CD

## 🚀 Quick Start

```bash
# Instalar dependências
pip install -r requirements.txt

# Configurar API key do Burp
export BURP_API_KEY="your-api-key"
export BURP_URL="http://localhost:1337"

# Executar scan
python burp_client.py --target https://example.com --scan-type active
```

## 📊 Exemplo de Uso

```python
from burp_client import BurpClient

# Conectar ao Burp Suite
client = BurpClient(
    api_url="http://localhost:1337",
    api_key="your-api-key"
)

# Iniciar scan
scan_id = client.start_scan(
    target="https://example.com",
    scan_type="active"
)

# Aguardar conclusão
client.wait_for_scan(scan_id)

# Obter vulnerabilidades
issues = client.get_issues(scan_id)
for issue in issues:
    print(f"[{issue['severity']}] {issue['name']}")

# Exportar relatório
client.export_report(scan_id, "report.html")
```

## 📁 Estrutura

```
02-burp-suite-api/
├── burp_client.py      # Cliente da API
├── config.yaml         # Configurações
├── requirements.txt    # Dependências
└── examples/           # Exemplos de uso
```

## ⚙️ Configuração do Burp Suite

1. Abra Burp Suite Professional
2. Vá em User Options > Misc > REST API
3. Ative "Service running"
4. Copie a API Key

## 📋 Issues Detectadas

- SQL Injection
- Cross-Site Scripting (XSS)
- OS Command Injection
- Path Traversal
- XML Injection
- LDAP Injection
- Server-Side Request Forgery
- E muito mais...
