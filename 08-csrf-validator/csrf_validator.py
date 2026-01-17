#!/usr/bin/env python3
"""
CSRF Protection Validator
Valida implementação de proteção contra CSRF.
"""

import re
import argparse
from typing import List, Dict, Optional
from dataclasses import dataclass
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table

console = Console()


@dataclass
class CSRFTestResult:
    """Resultado de teste CSRF."""
    test_name: str
    status: str
    details: str
    severity: str


class CSRFValidator:
    """Validador de proteção CSRF."""
    
    def __init__(self, url: str):
        self.url = url
        self.session = requests.Session()
        self.results: List[CSRFTestResult] = []
        self.page_content = None
        self.cookies = {}
    
    def fetch_page(self):
        """Busca a página alvo."""
        response = self.session.get(self.url)
        self.page_content = response.text
        self.cookies = dict(response.cookies)
        return response
    
    def test_csrf_token_present(self) -> CSRFTestResult:
        """Verifica se há CSRF token nos formulários."""
        console.print("[cyan]🔍 Verificando presença de CSRF token...[/cyan]")
        
        soup = BeautifulSoup(self.page_content, "html.parser")
        forms = soup.find_all("form")
        
        csrf_patterns = [
            r"csrf", r"_token", r"authenticity_token",
            r"__RequestVerificationToken", r"csrfmiddlewaretoken"
        ]
        
        forms_with_token = 0
        forms_without_token = 0
        
        for form in forms:
            has_token = False
            for inp in form.find_all("input", type="hidden"):
                name = inp.get("name", "").lower()
                for pattern in csrf_patterns:
                    if re.search(pattern, name, re.IGNORECASE):
                        has_token = True
                        break
            
            if has_token:
                forms_with_token += 1
            else:
                forms_without_token += 1
        
        if forms_without_token > 0:
            return CSRFTestResult(
                test_name="CSRF Token Present",
                status="failed",
                details=f"{forms_without_token} formulários sem CSRF token",
                severity="high"
            )
        elif forms_with_token > 0:
            return CSRFTestResult(
                test_name="CSRF Token Present",
                status="passed",
                details=f"{forms_with_token} formulários com CSRF token",
                severity="info"
            )
        else:
            return CSRFTestResult(
                test_name="CSRF Token Present",
                status="warning",
                details="Nenhum formulário encontrado",
                severity="low"
            )
    
    def test_samesite_cookie(self) -> CSRFTestResult:
        """Verifica atributo SameSite nos cookies."""
        console.print("[cyan]🔍 Verificando SameSite cookies...[/cyan]")
        
        response = self.session.get(self.url)
        set_cookie_headers = response.headers.get("Set-Cookie", "")
        
        if "SameSite=Strict" in set_cookie_headers:
            return CSRFTestResult(
                test_name="SameSite Cookie",
                status="passed",
                details="SameSite=Strict configurado",
                severity="info"
            )
        elif "SameSite=Lax" in set_cookie_headers:
            return CSRFTestResult(
                test_name="SameSite Cookie",
                status="passed",
                details="SameSite=Lax configurado",
                severity="info"
            )
        else:
            return CSRFTestResult(
                test_name="SameSite Cookie",
                status="warning",
                details="SameSite não configurado",
                severity="medium"
            )
    
    def test_token_validation(self) -> CSRFTestResult:
        """Testa se o servidor valida o CSRF token."""
        console.print("[cyan]🔍 Testando validação de token...[/cyan]")
        
        soup = BeautifulSoup(self.page_content, "html.parser")
        form = soup.find("form", method=re.compile("post", re.I))
        
        if not form:
            return CSRFTestResult(
                test_name="Token Validation",
                status="warning",
                details="Nenhum formulário POST encontrado",
                severity="low"
            )
        
        # Preparar dados do formulário
        form_data = {}
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if name:
                form_data[name] = inp.get("value", "test")
        
        # Modificar token CSRF
        for key in form_data:
            if "csrf" in key.lower() or "token" in key.lower():
                form_data[key] = "invalid_token_12345"
        
        # Enviar com token inválido
        action = form.get("action", self.url)
        if not action.startswith("http"):
            parsed = urlparse(self.url)
            action = f"{parsed.scheme}://{parsed.netloc}{action}"
        
        try:
            response = self.session.post(action, data=form_data)
            
            if response.status_code in [403, 400, 419]:
                return CSRFTestResult(
                    test_name="Token Validation",
                    status="passed",
                    details=f"Servidor rejeitou token inválido (HTTP {response.status_code})",
                    severity="info"
                )
            elif "csrf" in response.text.lower() or "token" in response.text.lower():
                return CSRFTestResult(
                    test_name="Token Validation",
                    status="passed",
                    details="Servidor detectou token inválido",
                    severity="info"
                )
            else:
                return CSRFTestResult(
                    test_name="Token Validation",
                    status="failed",
                    details="Servidor aceitou token inválido!",
                    severity="critical"
                )
        except Exception as e:
            return CSRFTestResult(
                test_name="Token Validation",
                status="warning",
                details=f"Erro ao testar: {str(e)}",
                severity="low"
            )
    
    def test_referer_check(self) -> CSRFTestResult:
        """Testa verificação de Referer header."""
        console.print("[cyan]🔍 Testando verificação de Referer...[/cyan]")
        
        soup = BeautifulSoup(self.page_content, "html.parser")
        form = soup.find("form", method=re.compile("post", re.I))
        
        if not form:
            return CSRFTestResult(
                test_name="Referer Check",
                status="warning",
                details="Nenhum formulário POST encontrado",
                severity="low"
            )
        
        # Enviar sem Referer
        headers = {"Referer": "https://evil.com"}
        
        form_data = {}
        for inp in form.find_all("input"):
            name = inp.get("name")
            if name:
                form_data[name] = inp.get("value", "test")
        
        action = form.get("action", self.url)
        if not action.startswith("http"):
            parsed = urlparse(self.url)
            action = f"{parsed.scheme}://{parsed.netloc}{action}"
        
        try:
            response = requests.post(action, data=form_data, headers=headers)
            
            if response.status_code in [403, 400]:
                return CSRFTestResult(
                    test_name="Referer Check",
                    status="passed",
                    details="Servidor verifica Referer header",
                    severity="info"
                )
            else:
                return CSRFTestResult(
                    test_name="Referer Check",
                    status="warning",
                    details="Servidor não verifica Referer (opcional)",
                    severity="low"
                )
        except:
            return CSRFTestResult(
                test_name="Referer Check",
                status="warning",
                details="Não foi possível testar",
                severity="low"
            )
    
    def run_all_tests(self) -> List[CSRFTestResult]:
        """Executa todos os testes."""
        console.print(f"\n[bold cyan]🛡️ Validando proteção CSRF em {self.url}[/bold cyan]\n")
        
        self.fetch_page()
        
        self.results.append(self.test_csrf_token_present())
        self.results.append(self.test_samesite_cookie())
        self.results.append(self.test_token_validation())
        self.results.append(self.test_referer_check())
        
        return self.results
    
    def print_results(self):
        """Imprime resultados."""
        table = Table(title="\n📊 Resultados da Validação CSRF")
        table.add_column("Teste")
        table.add_column("Status")
        table.add_column("Severidade")
        table.add_column("Detalhes")
        
        for r in self.results:
            status_icon = "✅" if r.status == "passed" else "❌" if r.status == "failed" else "⚠️"
            status_color = "green" if r.status == "passed" else "red" if r.status == "failed" else "yellow"
            
            table.add_row(
                r.test_name,
                f"[{status_color}]{status_icon} {r.status}[/{status_color}]",
                r.severity,
                r.details
            )
        
        console.print(table)


def main():
    parser = argparse.ArgumentParser(description="CSRF Protection Validator")
    parser.add_argument("--url", "-u", required=True, help="URL do formulário")
    
    args = parser.parse_args()
    
    validator = CSRFValidator(args.url)
    validator.run_all_tests()
    validator.print_results()
    
    failed = len([r for r in validator.results if r.status == "failed"])
    exit(1 if failed > 0 else 0)


if __name__ == "__main__":
    main()
