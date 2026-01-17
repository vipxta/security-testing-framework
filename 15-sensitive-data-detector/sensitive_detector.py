#!/usr/bin/env python3
"""
Sensitive Data Detector
Detecta dados sensíveis expostos.
"""

import re
import argparse
from typing import List, Dict
from dataclasses import dataclass

import requests
from rich.console import Console
from rich.table import Table

console = Console()

PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"[A-Za-z0-9/+=]{40}",
    "GitHub Token": r"ghp_[a-zA-Z0-9]{36}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "JWT Token": r"eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*",
    "Private Key": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "Credit Card": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
    "Email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "Internal IP": r"\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b",
    "Password in URL": r"[?&](?:password|passwd|pwd|pass)=[^&\s]+",
    "API Key Generic": r"['\"][a-zA-Z0-9_-]*(?:api[_-]?key|apikey|api[_-]?secret)['\"]\s*[:=]\s*['\"][a-zA-Z0-9_-]+['\"]",
    "Bearer Token": r"Bearer\s+[a-zA-Z0-9\-_\.]+",
    "Basic Auth": r"Basic\s+[a-zA-Z0-9+/=]+",
    "CPF": r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b",
    "CNPJ": r"\b\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\b",
}


@dataclass
class SensitiveData:
    data_type: str
    value: str
    location: str
    severity: str


class SensitiveDetector:
    """Detector de dados sensíveis."""
    
    def __init__(self):
        self.findings: List[SensitiveData] = []
    
    def scan_text(self, text: str, location: str = "response") -> List[SensitiveData]:
        """Escaneia texto em busca de dados sensíveis."""
        findings = []
        
        for data_type, pattern in PATTERNS.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            
            for match in matches:
                # Determinar severidade
                if any(k in data_type.lower() for k in ["key", "token", "password", "private", "credit"]):
                    severity = "Critical"
                elif any(k in data_type.lower() for k in ["cpf", "cnpj", "email"]):
                    severity = "High"
                else:
                    severity = "Medium"
                
                finding = SensitiveData(
                    data_type=data_type,
                    value=self._mask_value(match),
                    location=location,
                    severity=severity
                )
                findings.append(finding)
        
        return findings
    
    def _mask_value(self, value: str) -> str:
        """Mascara parte do valor sensível."""
        if len(value) <= 8:
            return "*" * len(value)
        return value[:4] + "*" * (len(value) - 8) + value[-4:]
    
    def scan_url(self, url: str) -> List[SensitiveData]:
        """Escaneia uma URL e sua resposta."""
        console.print(f"\n[bold cyan]🔍 Scanning {url}[/bold cyan]\n")
        
        # Verificar URL
        self.findings.extend(self.scan_text(url, "URL"))
        
        # Buscar e verificar resposta
        try:
            response = requests.get(url, timeout=10)
            self.findings.extend(self.scan_text(response.text, "Response Body"))
            
            # Verificar headers
            for header, value in response.headers.items():
                self.findings.extend(self.scan_text(value, f"Header: {header}"))
        except Exception as e:
            console.print(f"[yellow]Erro ao acessar URL: {e}[/yellow]")
        
        return self.findings
    
    def scan_file(self, filepath: str) -> List[SensitiveData]:
        """Escaneia um arquivo."""
        console.print(f"\n[bold cyan]🔍 Scanning {filepath}[/bold cyan]\n")
        
        with open(filepath, "r", errors="ignore") as f:
            content = f.read()
        
        self.findings.extend(self.scan_text(content, filepath))
        return self.findings
    
    def print_results(self):
        """Imprime resultados."""
        if not self.findings:
            console.print("\n[green]✅ Nenhum dado sensível encontrado![/green]")
            return
        
        # Remover duplicatas
        unique = {}
        for f in self.findings:
            key = f"{f.data_type}:{f.value}"
            if key not in unique:
                unique[key] = f
        
        table = Table(title=f"\n🚨 {len(unique)} Dados Sensíveis Encontrados")
        table.add_column("Tipo")
        table.add_column("Valor (mascarado)")
        table.add_column("Local")
        table.add_column("Severidade")
        
        for f in unique.values():
            color = "red" if f.severity == "Critical" else "yellow" if f.severity == "High" else "cyan"
            table.add_row(
                f.data_type,
                f.value,
                f.location,
                f"[{color}]{f.severity}[/{color}]"
            )
        
        console.print(table)


def main():
    parser = argparse.ArgumentParser(description="Sensitive Data Detector")
    parser.add_argument("--url", "-u", help="URL para escanear")
    parser.add_argument("--file", "-f", help="Arquivo para escanear")
    parser.add_argument("--text", "-t", help="Texto para escanear")
    
    args = parser.parse_args()
    
    detector = SensitiveDetector()
    
    if args.url:
        detector.scan_url(args.url)
    elif args.file:
        detector.scan_file(args.file)
    elif args.text:
        detector.scan_text(args.text, "input")
    
    detector.print_results()


if __name__ == "__main__":
    main()
