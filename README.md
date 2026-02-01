# 🛡️ Security Testing Framework

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://python.org)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010-red.svg)](https://owasp.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Framework completo de testes de segurança com 20 ferramentas especializadas para análise de vulnerabilidades, pentesting automatizado e conformidade OWASP.

## 📁 Projetos

| # | Projeto | Descrição | Tecnologias |
|---|---------|-----------|-------------|
| 1 | [OWASP ZAP Scanner](./01-owasp-zap-scanner) | Scanner automatizado de vulnerabilidades web | Python, OWASP ZAP, Docker |
| 2 | [Burp Suite API](./02-burp-suite-api) | Integração com API do Burp Suite Professional | Python, Burp Suite, REST API |
| 3 | [Security Gate CI/CD](./03-security-gate-cicd) | Pipeline de segurança automatizado | GitHub Actions, Jenkins, OWASP ZAP |
| 4 | [Vulnerability Dashboard](./04-vulnerability-dashboard) | Dashboard interativo de vulnerabilidades | Python, Grafana, PostgreSQL |
| 5 | [SQL Injection Detector](./05-sql-injection-detector) | Detector especializado em SQL Injection | Python, OWASP ZAP, Burp Suite |
| 6 | [XSS Scanner](./06-xss-scanner) | Scanner de Cross-Site Scripting | JavaScript, Node.js, OWASP ZAP |
| 7 | [Authentication Tests](./07-authentication-tests) | Suite de testes de autenticação | Python, Burp Suite, OWASP ZAP |
| 8 | [CSRF Validator](./08-csrf-validator) | Validador de proteção CSRF | Python, Selenium, OWASP ZAP |
| 9 | [Security Reports](./09-security-reports) | Gerador de relatórios de segurança | Python, Jinja2, PDF |
| 10 | [Pentest Suite](./10-pentest-suite) | Suite completa de penetration testing | Python, Metasploit, Nmap |
| 11 | [API Security Scanner](./11-api-security-scanner) | Scanner de segurança para APIs REST/GraphQL | Python, OWASP ZAP, Postman |
| 12 | [JWT Analyzer](./12-jwt-analyzer) | Analisador de tokens JWT | Python, PyJWT, Burp Suite |
| 13 | [SSL/TLS Checker](./13-ssl-tls-checker) | Verificador de configurações SSL/TLS | Python, OpenSSL, SSLyze |
| 14 | [Security Headers](./14-security-headers) | Validador de headers de segurança | Python, Requests, OWASP |
| 15 | [Sensitive Data Detector](./15-sensitive-data-detector) | Detector de dados sensíveis expostos | Python, Regex, ML |
| 16 | [Rate Limiting Tester](./16-rate-limiting-tester) | Testador de rate limiting | Python, Asyncio, Locust |
| 17 | [CORS Scanner](./17-cors-scanner) | Scanner de configurações CORS | Python, Requests, Burp Suite |
| 18 | [File Upload Tester](./18-file-upload-tester) | Testador de vulnerabilidades em upload | Python, Selenium, Burp Suite |
| 19 | [Session Analyzer](./19-session-analyzer) | Analisador de gerenciamento de sessões | Python, Burp Suite, OWASP ZAP |
| 20 | [OWASP Top 10 Reporter](./20-owasp-top10-reporter) | Relatório de conformidade OWASP Top 10 | Python, Jinja2, OWASP |

## 🚀 Quick Start

```bash
# Clone o repositório
git clone https://github.com/vipxta/security-testing-framework.git
cd security-testing-framework

# Instale as dependências globais
pip install -r requirements.txt

# Execute um scanner específico
cd 01-owasp-zap-scanner
python scanner.py --target https://example.com
```

## 📋 Requisitos

- Python 3.9+
- Docker (para OWASP ZAP)
- Node.js 18+ (para alguns projetos)
- Burp Suite Professional (opcional)

## 👤 Autor

**Isaac Meneguini Albuquerque**
- LinkedIn: [isaac-meneguini](https://www.linkedin.com/in/isaac-meneguini-albuquerque/)
- Email: isaacmeneguini@gmail.com

## 📄 Licença

MIT License - veja [LICENSE](LICENSE) para detalhes.
