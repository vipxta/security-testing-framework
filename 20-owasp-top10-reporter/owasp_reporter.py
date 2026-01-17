#!/usr/bin/env python3
"""
OWASP Top 10 Compliance Reporter
Gera relatório de conformidade OWASP Top 10 2021.
"""

import json
import argparse
from datetime import datetime
from typing import List, Dict
from dataclasses import dataclass, asdict

from jinja2 import Template
from rich.console import Console
from rich.table import Table

console = Console()

OWASP_TOP_10 = {
    "A01": {
        "name": "Broken Access Control",
        "description": "Restrições sobre o que usuários autenticados podem fazer não são adequadamente aplicadas.",
        "keywords": ["access control", "authorization", "idor", "bola", "privilege"]
    },
    "A02": {
        "name": "Cryptographic Failures",
        "description": "Falhas relacionadas à criptografia que levam à exposição de dados sensíveis.",
        "keywords": ["crypto", "encryption", "ssl", "tls", "hash", "password"]
    },
    "A03": {
        "name": "Injection",
        "description": "SQL, NoSQL, OS, LDAP injection quando dados não confiáveis são enviados a um interpretador.",
        "keywords": ["sql", "injection", "xss", "command", "ldap", "xpath"]
    },
    "A04": {
        "name": "Insecure Design",
        "description": "Falhas de design e arquitetura que não podem ser corrigidas com implementação perfeita.",
        "keywords": ["design", "architecture", "threat model"]
    },
    "A05": {
        "name": "Security Misconfiguration",
        "description": "Configurações inseguras em qualquer nível da stack da aplicação.",
        "keywords": ["config", "header", "cors", "default", "verbose", "debug"]
    },
    "A06": {
        "name": "Vulnerable Components",
        "description": "Uso de componentes com vulnerabilidades conhecidas.",
        "keywords": ["component", "library", "dependency", "outdated", "cve"]
    },
    "A07": {
        "name": "Authentication Failures",
        "description": "Falhas em confirmar a identidade do usuário, autenticação e gerenciamento de sessão.",
        "keywords": ["auth", "session", "credential", "brute", "password"]
    },
    "A08": {
        "name": "Data Integrity Failures",
        "description": "Falhas relacionadas a código e infraestrutura que não protegem contra violações de integridade.",
        "keywords": ["integrity", "deserialization", "ci/cd", "update"]
    },
    "A09": {
        "name": "Security Logging Failures",
        "description": "Falhas em logging e monitoramento que impedem a detecção de ataques.",
        "keywords": ["log", "monitor", "audit", "alert"]
    },
    "A10": {
        "name": "Server-Side Request Forgery",
        "description": "SSRF ocorre quando uma aplicação busca um recurso remoto sem validar a URL.",
        "keywords": ["ssrf", "request forgery", "url", "fetch"]
    }
}


@dataclass
class ComplianceResult:
    category: str
    name: str
    status: str  # compliant, non-compliant, partial
    findings: int
    details: List[str]


class OWASPReporter:
    """Gerador de relatório OWASP Top 10."""
    
    def __init__(self):
        self.vulnerabilities: List[Dict] = []
        self.compliance: Dict[str, ComplianceResult] = {}
    
    def load_vulnerabilities(self, filepath: str):
        """Carrega vulnerabilidades de arquivo JSON."""
        with open(filepath) as f:
            data = json.load(f)
        self.vulnerabilities = data.get("vulnerabilities", [])
    
    def categorize_vulnerability(self, vuln: Dict) -> str:
        """Categoriza vulnerabilidade no OWASP Top 10."""
        name = vuln.get("name", "").lower()
        description = vuln.get("description", "").lower()
        combined = f"{name} {description}"
        
        for category, info in OWASP_TOP_10.items():
            for keyword in info["keywords"]:
                if keyword in combined:
                    return category
        
        return "Other"
    
    def analyze(self):
        """Analisa conformidade."""
        console.print("\n[bold cyan]📊 OWASP Top 10 Compliance Analysis[/bold cyan]\n")
        
        # Inicializar resultados
        for category, info in OWASP_TOP_10.items():
            self.compliance[category] = ComplianceResult(
                category=category,
                name=info["name"],
                status="compliant",
                findings=0,
                details=[]
            )
        
        # Categorizar vulnerabilidades
        for vuln in self.vulnerabilities:
            category = self.categorize_vulnerability(vuln)
            
            if category in self.compliance:
                result = self.compliance[category]
                result.findings += 1
                result.details.append(vuln.get("name", "Unknown"))
                
                # Atualizar status
                severity = vuln.get("severity", "").lower()
                if severity in ["critical", "high"]:
                    result.status = "non-compliant"
                elif severity == "medium" and result.status == "compliant":
                    result.status = "partial"
        
        return self.compliance
    
    def calculate_score(self) -> float:
        """Calcula score de conformidade."""
        compliant = len([r for r in self.compliance.values() if r.status == "compliant"])
        partial = len([r for r in self.compliance.values() if r.status == "partial"])
        total = len(self.compliance)
        
        return ((compliant + partial * 0.5) / total) * 100
    
    def print_results(self):
        """Imprime resultados."""
        table = Table(title="\n📊 OWASP Top 10 2021 Compliance")
        table.add_column("Categoria")
        table.add_column("Nome")
        table.add_column("Status")
        table.add_column("Findings")
        
        for category in sorted(self.compliance.keys()):
            result = self.compliance[category]
            
            if result.status == "compliant":
                status = "[green]✅ Compliant[/green]"
            elif result.status == "partial":
                status = "[yellow]⚠️ Partial[/yellow]"
            else:
                status = "[red]❌ Non-Compliant[/red]"
            
            table.add_row(
                result.category,
                result.name,
                status,
                str(result.findings)
            )
        
        console.print(table)
        
        # Score
        score = self.calculate_score()
        color = "green" if score >= 80 else "yellow" if score >= 50 else "red"
        console.print(f"\n[{color}]🎯 Compliance Score: {score:.0f}%[/{color}]")
    
    def generate_report(self, output_path: str):
        """Gera relatório HTML."""
        template = Template('''
<!DOCTYPE html>
<html>
<head>
    <title>OWASP Top 10 Compliance Report</title>
    <style>
        body { font-family: Arial; margin: 40px; }
        .compliant { color: green; }
        .partial { color: orange; }
        .non-compliant { color: red; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #ddd; padding: 12px; }
        th { background: #2c3e50; color: white; }
    </style>
</head>
<body>
    <h1>📊 OWASP Top 10 Compliance Report</h1>
    <p>Generated: {{ timestamp }}</p>
    <p><strong>Score: {{ score }}%</strong></p>
    
    <table>
        <tr><th>Category</th><th>Name</th><th>Status</th><th>Findings</th></tr>
        {% for r in results %}
        <tr>
            <td>{{ r.category }}</td>
            <td>{{ r.name }}</td>
            <td class="{{ r.status }}">{{ r.status }}</td>
            <td>{{ r.findings }}</td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>
        ''')
        
        html = template.render(
            timestamp=datetime.now().isoformat(),
            score=f"{self.calculate_score():.0f}",
            results=[asdict(r) for r in self.compliance.values()]
        )
        
        with open(output_path, "w") as f:
            f.write(html)
        
        console.print(f"\n[green]✅ Relatório salvo: {output_path}[/green]")


def main():
    parser = argparse.ArgumentParser(description="OWASP Top 10 Reporter")
    parser.add_argument("--input", "-i", help="Arquivo JSON de vulnerabilidades")
    parser.add_argument("--output", "-o", help="Arquivo de saída HTML")
    parser.add_argument("--demo", action="store_true", help="Usar dados de demonstração")
    
    args = parser.parse_args()
    
    reporter = OWASPReporter()
    
    if args.input:
        reporter.load_vulnerabilities(args.input)
    elif args.demo:
        # Dados de demonstração
        reporter.vulnerabilities = [
            {"name": "SQL Injection", "severity": "Critical"},
            {"name": "XSS Reflected", "severity": "High"},
            {"name": "Missing HTTPS", "severity": "Medium"},
            {"name": "Weak Password Policy", "severity": "Medium"},
        ]
    
    reporter.analyze()
    reporter.print_results()
    
    if args.output:
        reporter.generate_report(args.output)


if __name__ == "__main__":
    main()
