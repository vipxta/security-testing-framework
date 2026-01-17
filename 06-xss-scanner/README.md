# 💥 XSS Scanner Automation

[![Node.js](https://img.shields.io/badge/Node.js-18+-green.svg)](https://nodejs.org)
[![OWASP](https://img.shields.io/badge/OWASP-A03:2021-red.svg)](https://owasp.org)

Scanner automatizado para detecção de vulnerabilidades Cross-Site Scripting (XSS) refletido, armazenado e baseado em DOM.

## 🎯 Funcionalidades

- ✅ XSS Refletido (Reflected)
- ✅ XSS Armazenado (Stored)
- ✅ XSS baseado em DOM
- ✅ Payloads customizáveis
- ✅ Bypass de filtros
- ✅ Geração de PoC

## 🚀 Quick Start

```bash
npm install
node xss_scanner.js --url "https://example.com/search?q=test"
```

## 📊 Tipos de XSS

| Tipo | Descrição | Vetor |
|------|-----------|-------|
| Reflected | Resposta imediata | `<script>alert(1)</script>` |
| Stored | Persistido no servidor | Comments, profiles |
| DOM-based | Manipulação client-side | `location.hash` |
