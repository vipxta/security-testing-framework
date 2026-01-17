#!/usr/bin/env python3
"""
Burp Suite API Client
Cliente para integração com a REST API do Burp Suite Professional.
"""

import os
import time
import json
import requests
from typing import List, Dict, Optional
from dataclasses import dataclass
from rich.console import Console
from rich.table import Table

console = Console()


@dataclass
class Issue:
    """Representa uma vulnerabilidade encontrada."""
    name: str
    severity: str
    confidence: str
    url: str
    description: str
    remediation: str
    evidence: Optional[str] = None


class BurpClient:
    """Cliente para a API REST do Burp Suite."""
    
    def __init__(self, api_url: str = None, api_key: str = None):
        self.api_url = api_url or os.getenv("BURP_URL", "http://localhost:1337")
        self.api_key = api_key or os.getenv("BURP_API_KEY")
        self.session = requests.Session()
        if self.api_key:
            self.session.headers["Authorization"] = f"Bearer {self.api_key}"
    
    def _request(self, method: str, endpoint: str, **kwargs) -> dict:
        """Faz requisição à API."""
        url = f"{self.api_url}{endpoint}"
        response = self.session.request(method, url, **kwargs)
        response.raise_for_status()
        return response.json() if response.content else {}
    
    def get_version(self) -> str:
        """Obtém versão do Burp Suite."""
        result = self._request("GET", "/v0.1/")
        return result.get("version", "unknown")
    
    def start_scan(self, target: str, scan_type: str = "active", 
                   config: Dict = None) -> str:
        """Inicia um scan no alvo especificado."""
        console.print(f"[cyan]🚀 Iniciando scan {scan_type} em {target}...[/cyan]")
        
        payload = {
            "urls": [target],
            "scan_configurations": config or [{"type": "NamedConfiguration", "name": "Crawl and Audit - Balanced"}]
        }
        
        result = self._request("POST", "/v0.1/scan", json=payload)
        scan_id = str(result.get("task_id"))
        
        console.print(f"[green]✅ Scan iniciado! ID: {scan_id}[/green]")
        return scan_id
    
    def get_scan_status(self, scan_id: str) -> dict:
        """Obtém status do scan."""
        return self._request("GET", f"/v0.1/scan/{scan_id}")
    
    def wait_for_scan(self, scan_id: str, timeout: int = 3600) -> bool:
        """Aguarda conclusão do scan."""
        console.print("[cyan]⏳ Aguardando conclusão do scan...[/cyan]")
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            status = self.get_scan_status(scan_id)
            state = status.get("scan_status", "unknown")
            
            if state == "succeeded":
                console.print("[green]✅ Scan concluído com sucesso![/green]")
                return True
            elif state == "failed":
                console.print("[red]❌ Scan falhou![/red]")
                return False
            
            time.sleep(10)
        
        console.print("[yellow]⚠️ Timeout atingido[/yellow]")
        return False
    
    def get_issues(self, scan_id: str = None) -> List[Issue]:
        """Obtém lista de vulnerabilidades."""
        endpoint = f"/v0.1/scan/{scan_id}" if scan_id else "/v0.1/knowledge_base/issue_definitions"
        result = self._request("GET", endpoint)
        
        issues = []
        for item in result.get("issue_events", []):
            issue = item.get("issue", {})
            issues.append(Issue(
                name=issue.get("name", "Unknown"),
                severity=issue.get("severity", "info"),
                confidence=issue.get("confidence", "tentative"),
                url=issue.get("origin", "") + issue.get("path", ""),
                description=issue.get("description", ""),
                remediation=issue.get("remediation", "")
            ))
        
        return issues
    
    def get_issues_summary(self, scan_id: str) -> dict:
        """Obtém resumo das vulnerabilidades."""
        issues = self.get_issues(scan_id)
        
        summary = {"high": 0, "medium": 0, "low": 0, "info": 0}
        for issue in issues:
            severity = issue.severity.lower()
            if severity in summary:
                summary[severity] += 1
        
        return summary
    
    def print_issues_table(self, issues: List[Issue]):
        """Imprime tabela de vulnerabilidades."""
        table = Table(title="🛡️ Vulnerabilidades Encontradas")
        table.add_column("Severidade", style="bold")
        table.add_column("Nome")
        table.add_column("URL")
        table.add_column("Confiança")
        
        severity_colors = {
            "high": "red",
            "medium": "yellow",
            "low": "cyan",
            "info": "white"
        }
        
        for issue in sorted(issues, key=lambda x: ["high", "medium", "low", "info"].index(x.severity.lower())):
            color = severity_colors.get(issue.severity.lower(), "white")
            table.add_row(
                f"[{color}]{issue.severity}[/{color}]",
                issue.name,
                issue.url[:50] + "..." if len(issue.url) > 50 else issue.url,
                issue.confidence
            )
        
        console.print(table)
    
    def export_report(self, scan_id: str, output_path: str, 
                      format: str = "html") -> bool:
        """Exporta relatório do scan."""
        console.print(f"[cyan]📝 Exportando relatório para {output_path}...[/cyan]")
        
        payload = {
            "report_type": format.upper(),
            "scan_id": scan_id
        }
        
        result = self._request("POST", "/v0.1/report", json=payload)
        
        with open(output_path, "wb") as f:
            f.write(result.get("report_data", b""))
        
        console.print(f"[green]✅ Relatório salvo em {output_path}[/green]")
        return True
    
    def add_to_scope(self, urls: List[str]):
        """Adiciona URLs ao escopo."""
        for url in urls:
            self._request("PUT", f"/v0.1/scope/include", json={"url": url})
        console.print(f"[green]✅ {len(urls)} URLs adicionadas ao escopo[/green]")
    
    def remove_from_scope(self, urls: List[str]):
        """Remove URLs do escopo."""
        for url in urls:
            self._request("DELETE", f"/v0.1/scope/include", json={"url": url})


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Burp Suite API Client")
    parser.add_argument("--target", "-t", required=True, help="URL alvo")
    parser.add_argument("--scan-type", choices=["active", "passive"], default="active")
    parser.add_argument("--output", "-o", default="burp_report.html")
    parser.add_argument("--api-url", default="http://localhost:1337")
    parser.add_argument("--api-key", help="Burp API Key")
    parser.add_argument("--timeout", type=int, default=3600)
    
    args = parser.parse_args()
    
    client = BurpClient(api_url=args.api_url, api_key=args.api_key)
    
    # Verificar conexão
    version = client.get_version()
    console.print(f"[green]Conectado ao Burp Suite {version}[/green]")
    
    # Iniciar scan
    scan_id = client.start_scan(args.target, args.scan_type)
    
    # Aguardar
    if client.wait_for_scan(scan_id, args.timeout):
        # Obter issues
        issues = client.get_issues(scan_id)
        client.print_issues_table(issues)
        
        # Exportar relatório
        client.export_report(scan_id, args.output)
        
        # Exit code
        summary = client.get_issues_summary(scan_id)
        exit(1 if summary["high"] > 0 else 0)
    else:
        exit(1)


if __name__ == "__main__":
    main()
