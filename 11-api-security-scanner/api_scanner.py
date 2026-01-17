#!/usr/bin/env python3
"""
API Security Scanner
Scanner de segurança para APIs REST e GraphQL.
"""

import json
import argparse
from typing import List, Dict, Optional
from dataclasses import dataclass
from urllib.parse import urljoin

import requests
from rich.console import Console
from rich.table import Table

console = Console()

INJECTION_PAYLOADS = [
    "'", '"', "<script>", "{{7*7}}", "${7*7}",
    "' OR '1'='1", "1; DROP TABLE users",
    "../../../etc/passwd", "%00", "\\x00"
]


@dataclass
class APIVulnerability:
    endpoint: str
    method: str
    vulnerability: str
    severity: str
    details: str


class APIScanner:
    """Scanner de segurança para APIs."""
    
    def __init__(self, base_url: str, auth_token: str = None):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        if auth_token:
            self.session.headers["Authorization"] = f"Bearer {auth_token}"
        self.vulnerabilities: List[APIVulnerability] = []
    
    def test_endpoint(self, endpoint: str, method: str = "GET", params: Dict = None):
        """Testa um endpoint específico."""
        url = urljoin(self.base_url, endpoint)
        
        try:
            if method == "GET":
                response = self.session.get(url, params=params, timeout=10)
            elif method == "POST":
                response = self.session.post(url, json=params, timeout=10)
            else:
                response = self.session.request(method, url, json=params, timeout=10)
            
            return response
        except Exception as e:
            return None
    
    def test_authentication(self, endpoint: str) -> Optional[APIVulnerability]:
        """Testa autenticação do endpoint."""
        console.print(f"[cyan]🔐 Testando autenticação: {endpoint}[/cyan]")
        
        # Testar sem autenticação
        session = requests.Session()  # Nova sessão sem token
        url = urljoin(self.base_url, endpoint)
        
        try:
            response = session.get(url, timeout=10)
            
            if response.status_code == 200:
                return APIVulnerability(
                    endpoint=endpoint,
                    method="GET",
                    vulnerability="Broken Authentication",
                    severity="High",
                    details="Endpoint acessível sem autenticação"
                )
        except:
            pass
        
        return None
    
    def test_injection(self, endpoint: str, param: str) -> Optional[APIVulnerability]:
        """Testa vulnerabilidades de injeção."""
        console.print(f"[cyan]💉 Testando injeção: {endpoint}[/cyan]")
        
        for payload in INJECTION_PAYLOADS:
            params = {param: payload}
            response = self.test_endpoint(endpoint, "GET", params)
            
            if response:
                # Verificar indicadores de vulnerabilidade
                if response.status_code == 500:
                    return APIVulnerability(
                        endpoint=endpoint,
                        method="GET",
                        vulnerability="Injection",
                        severity="Critical",
                        details=f"Erro 500 com payload: {payload[:20]}"
                    )
                
                # Verificar reflectão do payload
                if payload in response.text:
                    return APIVulnerability(
                        endpoint=endpoint,
                        method="GET",
                        vulnerability="Injection (Reflected)",
                        severity="High",
                        details=f"Payload refletido: {payload[:20]}"
                    )
        
        return None
    
    def test_rate_limiting(self, endpoint: str, requests_count: int = 100) -> Optional[APIVulnerability]:
        """Testa rate limiting."""
        console.print(f"[cyan]⏱️  Testando rate limiting: {endpoint}[/cyan]")
        
        blocked = False
        for i in range(requests_count):
            response = self.test_endpoint(endpoint)
            if response and response.status_code == 429:
                blocked = True
                break
        
        if not blocked:
            return APIVulnerability(
                endpoint=endpoint,
                method="GET",
                vulnerability="No Rate Limiting",
                severity="Medium",
                details=f"{requests_count} requests sem bloqueio"
            )
        
        return None
    
    def test_idor(self, endpoint: str) -> Optional[APIVulnerability]:
        """Testa BOLA/IDOR."""
        console.print(f"[cyan]🔍 Testando BOLA/IDOR: {endpoint}[/cyan]")
        
        # Testar acesso a recursos de outros usuários
        test_ids = ["1", "2", "admin", "0", "-1", "9999999"]
        
        for test_id in test_ids:
            test_endpoint = endpoint.replace("{id}", test_id)
            response = self.test_endpoint(test_endpoint)
            
            if response and response.status_code == 200:
                # Verificar se retornou dados que não deveriam ser acessados
                try:
                    data = response.json()
                    if data and isinstance(data, dict):
                        return APIVulnerability(
                            endpoint=test_endpoint,
                            method="GET",
                            vulnerability="BOLA/IDOR",
                            severity="High",
                            details=f"Acesso a recurso com ID: {test_id}"
                        )
                except:
                    pass
        
        return None
    
    def scan(self, endpoints: List[Dict]):
        """Executa scan em múltiplos endpoints."""
        console.print(f"\n[bold cyan]🔍 API Security Scanner - {self.base_url}[/bold cyan]\n")
        
        for ep in endpoints:
            endpoint = ep.get("path", "")
            method = ep.get("method", "GET")
            
            # Testes
            vuln = self.test_authentication(endpoint)
            if vuln:
                self.vulnerabilities.append(vuln)
            
            vuln = self.test_injection(endpoint, "id")
            if vuln:
                self.vulnerabilities.append(vuln)
            
            vuln = self.test_rate_limiting(endpoint, 50)
            if vuln:
                self.vulnerabilities.append(vuln)
        
        return self.vulnerabilities
    
    def print_results(self):
        """Imprime resultados."""
        if not self.vulnerabilities:
            console.print("\n[green]✅ Nenhuma vulnerabilidade encontrada![/green]")
            return
        
        table = Table(title="\n🚨 Vulnerabilidades de API Encontradas")
        table.add_column("Endpoint")
        table.add_column("Método")
        table.add_column("Vulnerabilidade")
        table.add_column("Severidade")
        table.add_column("Detalhes")
        
        for v in self.vulnerabilities:
            sev_color = "red" if v.severity in ["Critical", "High"] else "yellow"
            table.add_row(
                v.endpoint[:30],
                v.method,
                v.vulnerability,
                f"[{sev_color}]{v.severity}[/{sev_color}]",
                v.details[:40]
            )
        
        console.print(table)


def main():
    parser = argparse.ArgumentParser(description="API Security Scanner")
    parser.add_argument("--url", "-u", required=True, help="Base URL da API")
    parser.add_argument("--token", "-t", help="Bearer token")
    parser.add_argument("--endpoints", "-e", help="Lista de endpoints (JSON)")
    
    args = parser.parse_args()
    
    scanner = APIScanner(args.url, args.token)
    
    # Endpoints padrão para teste
    endpoints = [
        {"path": "/api/users", "method": "GET"},
        {"path": "/api/users/{id}", "method": "GET"},
        {"path": "/api/admin", "method": "GET"},
    ]
    
    if args.endpoints:
        with open(args.endpoints) as f:
            endpoints = json.load(f)
    
    scanner.scan(endpoints)
    scanner.print_results()


if __name__ == "__main__":
    main()
