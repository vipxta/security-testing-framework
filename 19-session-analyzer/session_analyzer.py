#!/usr/bin/env python3
"""
Session Security Analyzer
Analisa segurança de sessões.
"""

import math
import argparse
from typing import List, Dict, Set
from dataclasses import dataclass
from collections import Counter

import requests
from rich.console import Console
from rich.table import Table

console = Console()


@dataclass
class SessionIssue:
    name: str
    severity: str
    description: str
    recommendation: str


class SessionAnalyzer:
    """Analisador de sessões."""
    
    def __init__(self, url: str):
        self.url = url
        self.session_ids: List[str] = []
        self.cookies: Dict = {}
        self.issues: List[SessionIssue] = []
    
    def collect_sessions(self, count: int = 10):
        """Coleta múltiplos session IDs."""
        console.print(f"[cyan]Coletando {count} session IDs...[/cyan]")
        
        for _ in range(count):
            session = requests.Session()
            response = session.get(self.url, timeout=10)
            
            for cookie in session.cookies:
                if "session" in cookie.name.lower() or "sid" in cookie.name.lower():
                    self.session_ids.append(cookie.value)
                    self.cookies[cookie.name] = {
                        "value": cookie.value,
                        "secure": cookie.secure,
                        "httponly": cookie.has_nonstandard_attr("HttpOnly"),
                        "samesite": cookie.get_nonstandard_attr("SameSite"),
                        "path": cookie.path,
                        "domain": cookie.domain
                    }
    
    def calculate_entropy(self, session_id: str) -> float:
        """Calcula entropia do session ID."""
        if not session_id:
            return 0
        
        freq = Counter(session_id)
        length = len(session_id)
        
        entropy = 0
        for count in freq.values():
            prob = count / length
            entropy -= prob * math.log2(prob)
        
        return entropy * length  # Entropia total em bits
    
    def analyze_entropy(self):
        """Analisa entropia dos session IDs."""
        console.print("[cyan]Analisando entropia...[/cyan]")
        
        if not self.session_ids:
            return
        
        entropies = [self.calculate_entropy(sid) for sid in self.session_ids]
        avg_entropy = sum(entropies) / len(entropies)
        
        console.print(f"  Entropia média: {avg_entropy:.2f} bits")
        
        if avg_entropy < 64:
            self.issues.append(SessionIssue(
                name="Low Session ID Entropy",
                severity="High",
                description=f"Entropia média de {avg_entropy:.2f} bits (recomendado: 128+)",
                recommendation="Usar gerador criptograficamente seguro com 128+ bits"
            ))
    
    def analyze_cookie_attributes(self):
        """Analisa atributos dos cookies."""
        console.print("[cyan]Analisando atributos dos cookies...[/cyan]")
        
        for name, attrs in self.cookies.items():
            # Secure
            if not attrs.get("secure"):
                self.issues.append(SessionIssue(
                    name="Missing Secure Flag",
                    severity="High",
                    description=f"Cookie '{name}' sem flag Secure",
                    recommendation="Adicionar flag Secure ao cookie"
                ))
            
            # HttpOnly
            if not attrs.get("httponly"):
                self.issues.append(SessionIssue(
                    name="Missing HttpOnly Flag",
                    severity="Medium",
                    description=f"Cookie '{name}' sem flag HttpOnly",
                    recommendation="Adicionar flag HttpOnly para prevenir acesso via JavaScript"
                ))
            
            # SameSite
            if not attrs.get("samesite"):
                self.issues.append(SessionIssue(
                    name="Missing SameSite Attribute",
                    severity="Medium",
                    description=f"Cookie '{name}' sem atributo SameSite",
                    recommendation="Adicionar SameSite=Strict ou SameSite=Lax"
                ))
    
    def analyze_predictability(self):
        """Analisa previsibilidade dos session IDs."""
        console.print("[cyan]Analisando previsibilidade...[/cyan]")
        
        if len(self.session_ids) < 2:
            return
        
        # Verificar se há duplicatas
        unique = set(self.session_ids)
        if len(unique) < len(self.session_ids):
            self.issues.append(SessionIssue(
                name="Duplicate Session IDs",
                severity="Critical",
                description="Session IDs duplicados detectados",
                recommendation="Garantir que cada sessão tenha ID único"
            ))
        
        # Verificar padrões sequenciais
        if all(sid.isdigit() for sid in self.session_ids):
            nums = [int(sid) for sid in self.session_ids]
            if nums == sorted(nums):
                self.issues.append(SessionIssue(
                    name="Sequential Session IDs",
                    severity="Critical",
                    description="Session IDs parecem ser sequenciais",
                    recommendation="Usar gerador aleatório criptograficamente seguro"
                ))
    
    def analyze(self):
        """Executa análise completa."""
        console.print(f"\n[bold cyan]📝 Session Analyzer - {self.url}[/bold cyan]\n")
        
        self.collect_sessions()
        self.analyze_entropy()
        self.analyze_cookie_attributes()
        self.analyze_predictability()
        
        return self.issues
    
    def print_results(self):
        """Imprime resultados."""
        # Info de cookies
        if self.cookies:
            table = Table(title="\n🍪 Cookies de Sessão Encontrados")
            table.add_column("Nome")
            table.add_column("Secure")
            table.add_column("HttpOnly")
            table.add_column("SameSite")
            table.add_column("Tamanho")
            
            for name, attrs in self.cookies.items():
                table.add_row(
                    name,
                    "✅" if attrs.get("secure") else "❌",
                    "✅" if attrs.get("httponly") else "❌",
                    attrs.get("samesite") or "❌",
                    str(len(attrs.get("value", "")))
                )
            
            console.print(table)
        
        # Issues
        if not self.issues:
            console.print("\n[green]✅ Nenhum problema de sessão encontrado![/green]")
            return
        
        table = Table(title=f"\n🚨 {len(self.issues)} Problemas de Sessão")
        table.add_column("Problema")
        table.add_column("Severidade")
        table.add_column("Descrição")
        table.add_column("Recomendação")
        
        for issue in self.issues:
            color = "red" if issue.severity in ["Critical", "High"] else "yellow"
            table.add_row(
                issue.name,
                f"[{color}]{issue.severity}[/{color}]",
                issue.description[:40],
                issue.recommendation[:40]
            )
        
        console.print(table)


def main():
    parser = argparse.ArgumentParser(description="Session Analyzer")
    parser.add_argument("--url", "-u", required=True, help="URL alvo")
    parser.add_argument("--samples", "-s", type=int, default=10, help="Número de amostras")
    
    args = parser.parse_args()
    
    analyzer = SessionAnalyzer(args.url)
    analyzer.analyze()
    analyzer.print_results()


if __name__ == "__main__":
    main()
