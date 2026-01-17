#!/usr/bin/env python3
"""
SSL/TLS Security Checker
Verifica configurações SSL/TLS de servidores.
"""

import ssl
import socket
import argparse
from datetime import datetime
from typing import List, Dict, Optional
from dataclasses import dataclass

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

WEAK_CIPHERS = [
    "DES", "3DES", "RC4", "MD5", "NULL", "EXPORT", "anon"
]


@dataclass
class SSLVulnerability:
    name: str
    severity: str
    description: str


class SSLChecker:
    """Verificador de SSL/TLS."""
    
    def __init__(self, host: str, port: int = 443):
        self.host = host
        self.port = port
        self.cert = None
        self.cipher = None
        self.protocol = None
        self.vulnerabilities: List[SSLVulnerability] = []
    
    def connect(self) -> bool:
        """Conecta ao servidor."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.host, self.port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    self.cert = ssock.getpeercert(binary_form=False)
                    self.cipher = ssock.cipher()
                    self.protocol = ssock.version()
            
            return True
        except Exception as e:
            console.print(f"[red]Erro de conexão: {e}[/red]")
            return False
    
    def check_certificate(self):
        """Verifica o certificado."""
        console.print("[cyan]📜 Verificando certificado...[/cyan]")
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.host, self.port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Verificar expiração
                    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                    days_left = (not_after - datetime.now()).days
                    
                    if days_left < 0:
                        self.vulnerabilities.append(SSLVulnerability(
                            name="Expired Certificate",
                            severity="Critical",
                            description=f"Certificado expirou há {abs(days_left)} dias"
                        ))
                    elif days_left < 30:
                        self.vulnerabilities.append(SSLVulnerability(
                            name="Certificate Expiring Soon",
                            severity="Medium",
                            description=f"Certificado expira em {days_left} dias"
                        ))
                    
                    return cert
        except ssl.SSLCertVerificationError as e:
            self.vulnerabilities.append(SSLVulnerability(
                name="Certificate Verification Failed",
                severity="High",
                description=str(e)
            ))
        except Exception as e:
            console.print(f"[yellow]Aviso: {e}[/yellow]")
        
        return None
    
    def check_protocols(self):
        """Verifica protocolos suportados."""
        console.print("[cyan]🔐 Verificando protocolos...[/cyan]")
        
        protocols = {
            "SSLv2": ssl.PROTOCOL_SSLv23,
            "SSLv3": ssl.PROTOCOL_SSLv23,
            "TLSv1.0": ssl.PROTOCOL_TLSv1 if hasattr(ssl, 'PROTOCOL_TLSv1') else None,
            "TLSv1.1": ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, 'PROTOCOL_TLSv1_1') else None,
            "TLSv1.2": ssl.PROTOCOL_TLSv1_2 if hasattr(ssl, 'PROTOCOL_TLSv1_2') else None,
        }
        
        deprecated = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]
        
        if self.protocol in deprecated:
            self.vulnerabilities.append(SSLVulnerability(
                name="Deprecated Protocol",
                severity="High",
                description=f"Usando protocolo depreciado: {self.protocol}"
            ))
    
    def check_cipher(self):
        """Verifica cipher suite."""
        console.print("[cyan]🔐 Verificando cipher suites...[/cyan]")
        
        if self.cipher:
            cipher_name = self.cipher[0]
            
            for weak in WEAK_CIPHERS:
                if weak in cipher_name.upper():
                    self.vulnerabilities.append(SSLVulnerability(
                        name="Weak Cipher",
                        severity="High",
                        description=f"Cipher fraco em uso: {cipher_name}"
                    ))
                    break
    
    def check_hsts(self):
        """Verifica HSTS header."""
        console.print("[cyan]🔒 Verificando HSTS...[/cyan]")
        
        import requests
        try:
            response = requests.get(f"https://{self.host}", timeout=10)
            hsts = response.headers.get("Strict-Transport-Security")
            
            if not hsts:
                self.vulnerabilities.append(SSLVulnerability(
                    name="No HSTS",
                    severity="Medium",
                    description="Header Strict-Transport-Security não configurado"
                ))
        except:
            pass
    
    def analyze(self):
        """Executa análise completa."""
        console.print(f"\n[bold cyan]🔒 SSL/TLS Checker - {self.host}:{self.port}[/bold cyan]\n")
        
        if not self.connect():
            return
        
        self.check_certificate()
        self.check_protocols()
        self.check_cipher()
        self.check_hsts()
        
        return self.vulnerabilities
    
    def print_info(self):
        """Imprime informações da conexão."""
        info = f"""
Protocolo: {self.protocol}
Cipher: {self.cipher[0] if self.cipher else 'N/A'}
Bits: {self.cipher[2] if self.cipher else 'N/A'}
"""
        console.print(Panel(info, title="Informações SSL/TLS", border_style="cyan"))
    
    def print_vulnerabilities(self):
        """Imprime vulnerabilidades."""
        if not self.vulnerabilities:
            console.print("\n[green]✅ Configuração SSL/TLS segura![/green]")
            return
        
        table = Table(title="\n🚨 Problemas Encontrados")
        table.add_column("Problema")
        table.add_column("Severidade")
        table.add_column("Descrição")
        
        for v in self.vulnerabilities:
            color = "red" if v.severity in ["Critical", "High"] else "yellow"
            table.add_row(v.name, f"[{color}]{v.severity}[/{color}]", v.description)
        
        console.print(table)


def main():
    parser = argparse.ArgumentParser(description="SSL/TLS Checker")
    parser.add_argument("--host", "-H", required=True, help="Hostname")
    parser.add_argument("--port", "-p", type=int, default=443, help="Port")
    
    args = parser.parse_args()
    
    checker = SSLChecker(args.host, args.port)
    checker.analyze()
    checker.print_info()
    checker.print_vulnerabilities()


if __name__ == "__main__":
    main()
