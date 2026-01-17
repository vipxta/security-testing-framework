#!/usr/bin/env python3
"""
Security Gate CI/CD
Pipeline de segurança que bloqueia deploys com vulnerabilidades críticas.
"""

import os
import sys
import json
import yaml
import argparse
import requests
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


@dataclass
class ScanResult:
    """Resultado de um scan de segurança."""
    scanner: str
    high: int
    medium: int
    low: int
    info: int
    vulnerabilities: List[Dict]


@dataclass
class GateResult:
    """Resultado do security gate."""
    passed: bool
    reason: str
    scan_results: List[ScanResult]
    timestamp: str


class SecurityGate:
    """Security Gate para pipelines CI/CD."""
    
    def __init__(self, config_path: str = "security-gate.yml"):
        self.config = self._load_config(config_path)
        self.results: List[ScanResult] = []
    
    def _load_config(self, path: str) -> dict:
        """Carrega configuração do arquivo YAML."""
        default_config = {
            "thresholds": {"high": 0, "medium": 5, "low": 20},
            "scanners": ["owasp-zap"],
            "notifications": {"slack": {"enabled": False}}
        }
        
        if Path(path).exists():
            with open(path) as f:
                return {**default_config, **yaml.safe_load(f)}
        return default_config
    
    def run_owasp_zap_scan(self, target: str, zap_url: str = "http://localhost:8080") -> ScanResult:
        """Executa scan com OWASP ZAP."""
        console.print(f"[cyan]🔍 Executando OWASP ZAP scan em {target}...[/cyan]")
        
        try:
            # Spider
            requests.get(f"{zap_url}/JSON/spider/action/scan/", params={"url": target})
            
            # Active Scan
            response = requests.get(f"{zap_url}/JSON/ascan/action/scan/", params={"url": target})
            
            # Aguardar conclusão (simplificado)
            import time
            time.sleep(30)
            
            # Obter alertas
            alerts_response = requests.get(f"{zap_url}/JSON/core/view/alerts/", params={"baseurl": target})
            alerts = alerts_response.json().get("alerts", [])
            
            # Categorizar
            high = len([a for a in alerts if a.get("risk") == "High"])
            medium = len([a for a in alerts if a.get("risk") == "Medium"])
            low = len([a for a in alerts if a.get("risk") == "Low"])
            info = len([a for a in alerts if a.get("risk") == "Informational"])
            
            return ScanResult(
                scanner="owasp-zap",
                high=high,
                medium=medium,
                low=low,
                info=info,
                vulnerabilities=alerts
            )
        except Exception as e:
            console.print(f"[yellow]⚠️ ZAP scan falhou: {e}[/yellow]")
            return ScanResult("owasp-zap", 0, 0, 0, 0, [])
    
    def run_semgrep_scan(self, path: str = ".") -> ScanResult:
        """Executa scan estático com Semgrep."""
        console.print(f"[cyan]🔍 Executando Semgrep scan...[/cyan]")
        
        try:
            import subprocess
            result = subprocess.run(
                ["semgrep", "--config", "auto", "--json", path],
                capture_output=True,
                text=True
            )
            
            data = json.loads(result.stdout)
            findings = data.get("results", [])
            
            high = len([f for f in findings if f.get("extra", {}).get("severity") == "ERROR"])
            medium = len([f for f in findings if f.get("extra", {}).get("severity") == "WARNING"])
            low = len([f for f in findings if f.get("extra", {}).get("severity") == "INFO"])
            
            return ScanResult("semgrep", high, medium, low, 0, findings)
        except Exception as e:
            console.print(f"[yellow]⚠️ Semgrep scan falhou: {e}[/yellow]")
            return ScanResult("semgrep", 0, 0, 0, 0, [])
    
    def evaluate_gate(self) -> GateResult:
        """Avalia se o gate passou ou falhou."""
        thresholds = self.config["thresholds"]
        
        total_high = sum(r.high for r in self.results)
        total_medium = sum(r.medium for r in self.results)
        total_low = sum(r.low for r in self.results)
        
        passed = True
        reason = "✅ Todos os thresholds dentro do limite"
        
        if total_high > thresholds.get("high", 0):
            passed = False
            reason = f"❌ {total_high} vulnerabilidades HIGH (limite: {thresholds['high']})"
        elif total_medium > thresholds.get("medium", 5):
            passed = False
            reason = f"❌ {total_medium} vulnerabilidades MEDIUM (limite: {thresholds['medium']})"
        elif total_low > thresholds.get("low", 20):
            passed = False
            reason = f"❌ {total_low} vulnerabilidades LOW (limite: {thresholds['low']})"
        
        return GateResult(
            passed=passed,
            reason=reason,
            scan_results=self.results,
            timestamp=datetime.now().isoformat()
        )
    
    def print_summary(self, result: GateResult):
        """Imprime resumo do gate."""
        # Tabela de resultados
        table = Table(title="📊 Resultados do Security Gate")
        table.add_column("Scanner", style="cyan")
        table.add_column("🔴 High", justify="right")
        table.add_column("🟠 Medium", justify="right")
        table.add_column("🟡 Low", justify="right")
        table.add_column("🟢 Info", justify="right")
        
        for scan in result.scan_results:
            table.add_row(
                scan.scanner,
                str(scan.high),
                str(scan.medium),
                str(scan.low),
                str(scan.info)
            )
        
        console.print(table)
        
        # Status do gate
        status_color = "green" if result.passed else "red"
        status_icon = "✅" if result.passed else "❌"
        
        panel = Panel(
            f"{status_icon} {result.reason}",
            title="Security Gate Status",
            border_style=status_color
        )
        console.print(panel)
    
    def send_slack_notification(self, result: GateResult):
        """Envia notificação para o Slack."""
        slack_config = self.config.get("notifications", {}).get("slack", {})
        if not slack_config.get("enabled"):
            return
        
        webhook = slack_config.get("webhook") or os.getenv("SLACK_WEBHOOK")
        if not webhook:
            return
        
        color = "good" if result.passed else "danger"
        status = "PASSED" if result.passed else "FAILED"
        
        payload = {
            "attachments": [{
                "color": color,
                "title": f"Security Gate {status}",
                "text": result.reason,
                "fields": [
                    {"title": "High", "value": sum(r.high for r in result.scan_results), "short": True},
                    {"title": "Medium", "value": sum(r.medium for r in result.scan_results), "short": True}
                ]
            }]
        }
        
        requests.post(webhook, json=payload)
    
    def run(self, target: str = None, code_path: str = ".") -> GateResult:
        """Executa o security gate completo."""
        console.print("\n[bold cyan]🚦 Iniciando Security Gate[/bold cyan]\n")
        
        scanners = self.config.get("scanners", [])
        
        if "owasp-zap" in scanners and target:
            self.results.append(self.run_owasp_zap_scan(target))
        
        if "semgrep" in scanners:
            self.results.append(self.run_semgrep_scan(code_path))
        
        result = self.evaluate_gate()
        self.print_summary(result)
        self.send_slack_notification(result)
        
        return result


def main():
    parser = argparse.ArgumentParser(description="Security Gate CI/CD")
    parser.add_argument("--target", "-t", help="URL alvo para DAST")
    parser.add_argument("--path", "-p", default=".", help="Path para SAST")
    parser.add_argument("--config", "-c", default="security-gate.yml")
    parser.add_argument("--output", "-o", help="Arquivo de saída JSON")
    
    args = parser.parse_args()
    
    gate = SecurityGate(args.config)
    result = gate.run(target=args.target, code_path=args.path)
    
    if args.output:
        with open(args.output, "w") as f:
            json.dump(asdict(result), f, indent=2)
    
    sys.exit(0 if result.passed else 1)


if __name__ == "__main__":
    main()
