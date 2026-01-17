#!/usr/bin/env python3
"""
Security Headers Validator
Valida headers de segurança HTTP.
"""

import argparse
from typing import Dict, List
from dataclasses import dataclass

import requests
from rich.console import Console
from rich.table import Table

console = Console()

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "High",
        "description": "Previne XSS e injeção de conteúdo"
    },
    "X-Frame-Options": {
        "severity": "Medium",
        "description": "Previne clickjacking"
    },
    "X-Content-Type-Options": {
        "severity": "Medium",
        "description": "Previne MIME sniffing"
    },
    "Strict-Transport-Security": {
        "severity": "High",
        "description": "Força conexões HTTPS"
    },
    "Referrer-Policy": {
        "severity": "Low",
        "description": "Controla informação de referrer"
    },
    "Permissions-Policy": {
        "severity": "Medium",
        "description": "Controla recursos do navegador"
    },
    "X-XSS-Protection": {
        "severity": "Low",
        "description": "Filtro XSS do navegador (legado)"
    }
}


@dataclass
class HeaderResult:
    name: str
    present: bool
    value: str
    severity: str
    recommendation: str


class HeadersValidator:
    """Validador de headers de segurança."""
    
    def __init__(self, url: str):
        self.url = url
        self.headers = {}
        self.results: List[HeaderResult] = []
    
    def fetch_headers(self) -> Dict:
        """Busca headers do servidor."""
        response = requests.get(self.url, timeout=10, allow_redirects=True)
        self.headers = dict(response.headers)
        return self.headers
    
    def validate(self):
        """Valida todos os headers de segurança."""
        console.print(f"\n[bold cyan]📝 Security Headers Validator - {self.url}[/bold cyan]\n")
        
        self.fetch_headers()
        
        for header_name, info in SECURITY_HEADERS.items():
            value = self.headers.get(header_name, "")
            present = bool(value)
            
            if present:
                recommendation = self._validate_value(header_name, value)
            else:
                recommendation = f"Adicionar header {header_name}"
            
            self.results.append(HeaderResult(
                name=header_name,
                present=present,
                value=value[:50] if value else "Ausente",
                severity=info["severity"] if not present else "OK",
                recommendation=recommendation
            ))
        
        return self.results
    
    def _validate_value(self, header: str, value: str) -> str:
        """Valida o valor de um header."""
        if header == "X-Frame-Options":
            if value.upper() not in ["DENY", "SAMEORIGIN"]:
                return f"Valor recomendado: DENY ou SAMEORIGIN"
        
        elif header == "X-Content-Type-Options":
            if value.lower() != "nosniff":
                return "Valor deve ser: nosniff"
        
        elif header == "Strict-Transport-Security":
            if "max-age" not in value.lower():
                return "Adicionar max-age"
            if "includeSubDomains" not in value:
                return "Considerar adicionar includeSubDomains"
        
        elif header == "Content-Security-Policy":
            if "unsafe-inline" in value or "unsafe-eval" in value:
                return "Remover 'unsafe-inline' e 'unsafe-eval'"
        
        return "✅ Configurado corretamente"
    
    def print_results(self):
        """Imprime resultados."""
        table = Table(title="\n📊 Resultados da Validação")
        table.add_column("Header")
        table.add_column("Status")
        table.add_column("Valor")
        table.add_column("Recomendação")
        
        for r in self.results:
            if r.present:
                status = "[green]✅ Presente[/green]"
            else:
                color = "red" if r.severity == "High" else "yellow"
                status = f"[{color}]❌ Ausente[/{color}]"
            
            table.add_row(
                r.name,
                status,
                r.value[:40],
                r.recommendation
            )
        
        console.print(table)
        
        # Score
        present_count = len([r for r in self.results if r.present])
        total = len(self.results)
        score = (present_count / total) * 100
        
        color = "green" if score >= 80 else "yellow" if score >= 50 else "red"
        console.print(f"\n[{color}]🎯 Score: {score:.0f}% ({present_count}/{total} headers)[/{color}]")


def main():
    parser = argparse.ArgumentParser(description="Security Headers Validator")
    parser.add_argument("--url", "-u", required=True, help="URL alvo")
    
    args = parser.parse_args()
    
    validator = HeadersValidator(args.url)
    validator.validate()
    validator.print_results()


if __name__ == "__main__":
    main()
