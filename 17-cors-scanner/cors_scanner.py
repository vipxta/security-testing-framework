#!/usr/bin/env python3
"""
CORS Configuration Scanner
Escaneia configurações CORS em busca de vulnerabilidades.
"""

import argparse
from typing import List, Dict
from dataclasses import dataclass
from urllib.parse import urlparse

import requests
from rich.console import Console
from rich.table import Table

console = Console()


@dataclass
class CORSVulnerability:
    name: str
    severity: str
    origin_tested: str
    acao_header: str
    acac_header: str
    description: str


class CORSScanner:
    """Scanner de CORS."""
    
    def __init__(self, url: str):
        self.url = url
        self.vulnerabilities: List[CORSVulnerability] = []
        self.domain = urlparse(url).netloc
    
    def test_origin(self, origin: str) -> Dict:
        """Testa uma origem específica."""
        headers = {"Origin": origin}
        
        try:
            response = requests.get(self.url, headers=headers, timeout=10)
            return {
                "acao": response.headers.get("Access-Control-Allow-Origin", ""),
                "acac": response.headers.get("Access-Control-Allow-Credentials", ""),
                "methods": response.headers.get("Access-Control-Allow-Methods", ""),
                "headers": response.headers.get("Access-Control-Allow-Headers", "")
            }
        except Exception as e:
            return {}
    
    def scan(self):
        """Executa scan completo."""
        console.print(f"\n[bold cyan]🌐 CORS Scanner - {self.url}[/bold cyan]\n")
        
        # Testes a executar
        tests = [
            ("https://evil.com", "Arbitrary Origin"),
            ("null", "Null Origin"),
            (f"https://{self.domain}.evil.com", "Subdomain Prefix"),
            (f"https://evil{self.domain}", "Domain Suffix"),
            (f"https://{self.domain}", "Same Origin"),
            ("https://evil.com", "Origin Reflection"),
        ]
        
        for origin, test_name in tests:
            console.print(f"[cyan]🔍 Testando: {test_name} ({origin})[/cyan]")
            result = self.test_origin(origin)
            
            acao = result.get("acao", "")
            acac = result.get("acac", "")
            
            # Verificar vulnerabilidades
            if acao == "*":
                self.vulnerabilities.append(CORSVulnerability(
                    name="Wildcard Origin",
                    severity="High" if acac.lower() == "true" else "Medium",
                    origin_tested=origin,
                    acao_header=acao,
                    acac_header=acac,
                    description="ACAO permite qualquer origem (*)"
                ))
            
            elif acao == origin and origin not in [f"https://{self.domain}", f"http://{self.domain}"]:
                severity = "Critical" if acac.lower() == "true" else "High"
                self.vulnerabilities.append(CORSVulnerability(
                    name="Origin Reflection",
                    severity=severity,
                    origin_tested=origin,
                    acao_header=acao,
                    acac_header=acac,
                    description=f"Servidor reflete origem arbitrária: {origin}"
                ))
            
            elif acao == "null":
                self.vulnerabilities.append(CORSVulnerability(
                    name="Null Origin Allowed",
                    severity="High",
                    origin_tested=origin,
                    acao_header=acao,
                    acac_header=acac,
                    description="Servidor aceita origem 'null'"
                ))
        
        return self.vulnerabilities
    
    def print_results(self):
        """Imprime resultados."""
        if not self.vulnerabilities:
            console.print("\n[green]✅ Nenhuma vulnerabilidade CORS encontrada![/green]")
            return
        
        table = Table(title=f"\n🚨 {len(self.vulnerabilities)} Vulnerabilidades CORS")
        table.add_column("Vulnerabilidade")
        table.add_column("Severidade")
        table.add_column("Origin Testado")
        table.add_column("ACAO")
        table.add_column("ACAC")
        
        for v in self.vulnerabilities:
            color = "red" if v.severity in ["Critical", "High"] else "yellow"
            table.add_row(
                v.name,
                f"[{color}]{v.severity}[/{color}]",
                v.origin_tested[:30],
                v.acao_header,
                v.acac_header or "-"
            )
        
        console.print(table)
        
        # Recomendações
        console.print("\n[yellow]💡 Recomendações:[/yellow]")
        console.print("  • Não usar wildcard (*) com credenciais")
        console.print("  • Validar origem contra whitelist")
        console.print("  • Não aceitar origem 'null'")
        console.print("  • Implementar validação estrita de domínio")


def main():
    parser = argparse.ArgumentParser(description="CORS Scanner")
    parser.add_argument("--url", "-u", required=True, help="URL alvo")
    
    args = parser.parse_args()
    
    scanner = CORSScanner(args.url)
    scanner.scan()
    scanner.print_results()


if __name__ == "__main__":
    main()
