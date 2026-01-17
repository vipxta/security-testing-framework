#!/usr/bin/env python3
"""
JWT Security Analyzer
Analisa segurança de tokens JWT.
"""

import json
import base64
import hmac
import hashlib
import argparse
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

WEAK_SECRETS = [
    "secret", "password", "123456", "key", "private",
    "admin", "jwt_secret", "supersecret", "changeme",
    "your-256-bit-secret", "your-secret-key"
]


@dataclass
class JWTVulnerability:
    name: str
    severity: str
    description: str


class JWTAnalyzer:
    """Analisador de tokens JWT."""
    
    def __init__(self, token: str):
        self.token = token
        self.header = {}
        self.payload = {}
        self.signature = ""
        self.vulnerabilities: List[JWTVulnerability] = []
    
    def _base64_decode(self, data: str) -> str:
        """Decodifica base64url."""
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        return base64.urlsafe_b64decode(data).decode("utf-8")
    
    def decode(self) -> bool:
        """Decodifica o token JWT."""
        try:
            parts = self.token.split(".")
            if len(parts) != 3:
                console.print("[red]Token inválido: deve ter 3 partes[/red]")
                return False
            
            self.header = json.loads(self._base64_decode(parts[0]))
            self.payload = json.loads(self._base64_decode(parts[1]))
            self.signature = parts[2]
            
            return True
        except Exception as e:
            console.print(f"[red]Erro ao decodificar: {e}[/red]")
            return False
    
    def analyze_algorithm(self):
        """Analisa o algoritmo usado."""
        alg = self.header.get("alg", "")
        
        if alg.lower() == "none":
            self.vulnerabilities.append(JWTVulnerability(
                name="Algorithm None",
                severity="Critical",
                description="Token usa alg:none - assinatura pode ser removida"
            ))
        
        if alg in ["HS256", "HS384", "HS512"]:
            self.vulnerabilities.append(JWTVulnerability(
                name="Symmetric Algorithm",
                severity="Medium",
                description=f"Usa algoritmo simétrico ({alg}) - secret pode ser forçado"
            ))
        
        if alg == "RS256":
            # Verificar se aceita HS256 (confusão de algoritmo)
            pass
    
    def analyze_claims(self):
        """Analisa claims do payload."""
        # Verificar expiração
        exp = self.payload.get("exp")
        if not exp:
            self.vulnerabilities.append(JWTVulnerability(
                name="No Expiration",
                severity="High",
                description="Token não tem claim 'exp' - nunca expira"
            ))
        elif exp < datetime.now().timestamp():
            self.vulnerabilities.append(JWTVulnerability(
                name="Expired Token",
                severity="Info",
                description="Token já expirou"
            ))
        
        # Verificar issuer
        if not self.payload.get("iss"):
            self.vulnerabilities.append(JWTVulnerability(
                name="No Issuer",
                severity="Low",
                description="Token não tem claim 'iss'"
            ))
        
        # Verificar audience
        if not self.payload.get("aud"):
            self.vulnerabilities.append(JWTVulnerability(
                name="No Audience",
                severity="Low",
                description="Token não tem claim 'aud'"
            ))
        
        # Verificar dados sensíveis
        sensitive_keys = ["password", "secret", "key", "credit_card"]
        for key in self.payload:
            if any(s in key.lower() for s in sensitive_keys):
                self.vulnerabilities.append(JWTVulnerability(
                    name="Sensitive Data in Token",
                    severity="High",
                    description=f"Dados sensíveis encontrados: {key}"
                ))
    
    def brute_force_secret(self, wordlist: List[str] = None) -> Optional[str]:
        """Tenta descobrir o secret por força bruta."""
        console.print("[cyan]🔐 Testando secrets comuns...[/cyan]")
        
        secrets = wordlist or WEAK_SECRETS
        parts = self.token.split(".")
        message = f"{parts[0]}.{parts[1]}".encode()
        
        for secret in secrets:
            # Testar HMAC-SHA256
            expected = hmac.new(
                secret.encode(),
                message,
                hashlib.sha256
            ).digest()
            
            expected_b64 = base64.urlsafe_b64encode(expected).rstrip(b"=").decode()
            
            if expected_b64 == self.signature:
                self.vulnerabilities.append(JWTVulnerability(
                    name="Weak Secret",
                    severity="Critical",
                    description=f"Secret descoberto: {secret}"
                ))
                return secret
        
        return None
    
    def analyze(self):
        """Executa análise completa."""
        console.print(f"\n[bold cyan]🔑 JWT Security Analyzer[/bold cyan]\n")
        
        if not self.decode():
            return
        
        self.analyze_algorithm()
        self.analyze_claims()
        self.brute_force_secret()
        
        return self.vulnerabilities
    
    def print_token_info(self):
        """Imprime informações do token."""
        # Header
        console.print(Panel(
            json.dumps(self.header, indent=2),
            title="Header",
            border_style="cyan"
        ))
        
        # Payload
        console.print(Panel(
            json.dumps(self.payload, indent=2),
            title="Payload",
            border_style="green"
        ))
    
    def print_vulnerabilities(self):
        """Imprime vulnerabilidades encontradas."""
        if not self.vulnerabilities:
            console.print("\n[green]✅ Nenhuma vulnerabilidade encontrada![/green]")
            return
        
        table = Table(title="\n🚨 Vulnerabilidades")
        table.add_column("Nome")
        table.add_column("Severidade")
        table.add_column("Descrição")
        
        for v in self.vulnerabilities:
            sev_color = "red" if v.severity in ["Critical", "High"] else "yellow" if v.severity == "Medium" else "cyan"
            table.add_row(
                v.name,
                f"[{sev_color}]{v.severity}[/{sev_color}]",
                v.description
            )
        
        console.print(table)


def main():
    parser = argparse.ArgumentParser(description="JWT Security Analyzer")
    parser.add_argument("--token", "-t", required=True, help="Token JWT")
    parser.add_argument("--wordlist", "-w", help="Wordlist para brute force")
    
    args = parser.parse_args()
    
    analyzer = JWTAnalyzer(args.token)
    analyzer.analyze()
    analyzer.print_token_info()
    analyzer.print_vulnerabilities()


if __name__ == "__main__":
    main()
