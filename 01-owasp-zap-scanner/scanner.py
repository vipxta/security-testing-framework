#!/usr/bin/env python3
"""
OWASP ZAP Scanner Automatizado
Scanner de vulnerabilidades web com suporte a Docker e relatórios automatizados.
"""

import time
import json
import yaml
import argparse
from pathlib import Path
from datetime import datetime
from zapv2 import ZAPv2
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

console = Console()


class ZAPScanner:
    """Scanner automatizado utilizando OWASP ZAP."""
    
    def __init__(self, target: str, zap_host: str = "localhost", zap_port: int = 8080, api_key: str = None):
        self.target = target
        self.zap_host = zap_host
        self.zap_port = zap_port
        self.api_key = api_key
        self.zap = ZAPv2(
            apikey=api_key,
            proxies={
                "http": f"http://{zap_host}:{zap_port}",
                "https": f"http://{zap_host}:{zap_port}"
            }
        )
        self.scan_id = None
        self.alerts = []
        
    def spider_scan(self, max_depth: int = 5) -> int:
        """Executa spider scan para descobrir URLs."""
        console.print(f"[cyan]🕷️  Iniciando Spider Scan em {self.target}...[/cyan]")
        
        scan_id = self.zap.spider.scan(
            url=self.target,
            maxchildren=max_depth
        )
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Spider scan em progresso...", total=100)
            
            while int(self.zap.spider.status(scan_id)) < 100:
                progress.update(task, completed=int(self.zap.spider.status(scan_id)))
                time.sleep(1)
            
            progress.update(task, completed=100)
        
        urls_found = len(self.zap.spider.results(scan_id))
        console.print(f"[green]✅ Spider concluído! {urls_found} URLs descobertas.[/green]")
        return urls_found
    
    def ajax_spider_scan(self, max_duration: int = 60) -> int:
        """Executa AJAX Spider para aplicações SPA."""
        console.print(f"[cyan]🕷️  Iniciando AJAX Spider...[/cyan]")
        
        self.zap.ajaxSpider.scan(url=self.target)
        
        start_time = time.time()
        while self.zap.ajaxSpider.status == "running":
            if time.time() - start_time > max_duration:
                self.zap.ajaxSpider.stop()
                break
            time.sleep(2)
        
        results = len(self.zap.ajaxSpider.results())
        console.print(f"[green]✅ AJAX Spider concluído! {results} recursos encontrados.[/green]")
        return results
    
    def active_scan(self, policy: str = None) -> dict:
        """Executa scan ativo de vulnerabilidades."""
        console.print(f"[cyan]🛡️  Iniciando Scan Ativo...[/cyan]")
        
        scan_id = self.zap.ascan.scan(
            url=self.target,
            scanpolicyname=policy
        )
        self.scan_id = scan_id
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Scan ativo em progresso...", total=100)
            
            while int(self.zap.ascan.status(scan_id)) < 100:
                progress.update(task, completed=int(self.zap.ascan.status(scan_id)))
                time.sleep(2)
            
            progress.update(task, completed=100)
        
        self.alerts = self.zap.core.alerts(baseurl=self.target)
        console.print(f"[green]✅ Scan concluído! {len(self.alerts)} alertas encontrados.[/green]")
        
        return self._categorize_alerts()
    
    def _categorize_alerts(self) -> dict:
        """Categoriza alertas por severidade."""
        categories = {"High": [], "Medium": [], "Low": [], "Informational": []}
        
        for alert in self.alerts:
            risk = alert.get("risk", "Informational")
            if risk in categories:
                categories[risk].append(alert)
        
        return categories
    
    def full_scan(self, spider: bool = True, ajax_spider: bool = False, active_scan: bool = True) -> dict:
        """Executa scan completo."""
        console.print(f"\n[bold cyan]🚀 Iniciando Scan Completo em {self.target}[/bold cyan]\n")
        
        results = {
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "urls_found": 0,
            "alerts": {}
        }
        
        if spider:
            results["urls_found"] = self.spider_scan()
        
        if ajax_spider:
            results["urls_found"] += self.ajax_spider_scan()
        
        if active_scan:
            results["alerts"] = self.active_scan()
        
        self._print_summary(results)
        return results
    
    def _print_summary(self, results: dict):
        """Imprime resumo dos resultados."""
        table = Table(title="\n📊 Resumo do Scan")
        table.add_column("Severidade", style="cyan")
        table.add_column("Quantidade", justify="right")
        
        alerts = results.get("alerts", {})
        table.add_row("🔴 High", str(len(alerts.get("High", []))))
        table.add_row("🟠 Medium", str(len(alerts.get("Medium", []))))
        table.add_row("🟡 Low", str(len(alerts.get("Low", []))))
        table.add_row("🟢 Info", str(len(alerts.get("Informational", []))))
        
        console.print(table)
    
    def generate_report(self, output_path: str, format: str = "html"):
        """Gera relatório do scan."""
        console.print(f"[cyan]📝 Gerando relatório em {output_path}...[/cyan]")
        
        if format == "html":
            report = self.zap.core.htmlreport()
        elif format == "json":
            report = self.zap.core.jsonreport()
        elif format == "xml":
            report = self.zap.core.xmlreport()
        else:
            raise ValueError(f"Formato não suportado: {format}")
        
        with open(output_path, "w") as f:
            f.write(report)
        
        console.print(f"[green]✅ Relatório salvo em {output_path}[/green]")


def main():
    parser = argparse.ArgumentParser(description="OWASP ZAP Scanner Automatizado")
    parser.add_argument("--target", "-t", required=True, help="URL alvo")
    parser.add_argument("--host", default="localhost", help="ZAP host")
    parser.add_argument("--port", type=int, default=8080, help="ZAP port")
    parser.add_argument("--api-key", help="ZAP API key")
    parser.add_argument("--output", "-o", default="report.html", help="Arquivo de saída")
    parser.add_argument("--format", choices=["html", "json", "xml"], default="html")
    parser.add_argument("--no-spider", action="store_true", help="Pular spider scan")
    parser.add_argument("--ajax-spider", action="store_true", help="Incluir AJAX spider")
    
    args = parser.parse_args()
    
    scanner = ZAPScanner(
        target=args.target,
        zap_host=args.host,
        zap_port=args.port,
        api_key=args.api_key
    )
    
    results = scanner.full_scan(
        spider=not args.no_spider,
        ajax_spider=args.ajax_spider,
        active_scan=True
    )
    
    scanner.generate_report(args.output, format=args.format)
    
    # Exit code baseado em vulnerabilidades críticas
    high_vulns = len(results.get("alerts", {}).get("High", []))
    exit(1 if high_vulns > 0 else 0)


if __name__ == "__main__":
    main()
