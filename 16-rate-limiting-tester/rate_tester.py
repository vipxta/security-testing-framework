#!/usr/bin/env python3
"""
Rate Limiting Tester
Testa rate limiting de APIs.
"""

import time
import argparse
import asyncio
from typing import List, Dict
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor

import requests
from rich.console import Console
from rich.progress import Progress
from rich.table import Table

console = Console()


@dataclass
class TestResult:
    total_requests: int
    successful: int
    blocked: int
    avg_response_time: float
    rate_limit_detected: bool
    threshold: int
    headers: Dict


class RateLimitTester:
    """Testador de rate limiting."""
    
    def __init__(self, url: str, headers: Dict = None):
        self.url = url
        self.headers = headers or {}
        self.responses: List[Dict] = []
    
    def make_request(self) -> Dict:
        """Faz uma requisição."""
        start = time.time()
        try:
            response = requests.get(self.url, headers=self.headers, timeout=10)
            elapsed = time.time() - start
            
            return {
                "status": response.status_code,
                "time": elapsed,
                "headers": dict(response.headers)
            }
        except Exception as e:
            return {"status": 0, "time": 0, "error": str(e)}
    
    def test_rate_limit(self, num_requests: int = 100, delay: float = 0) -> TestResult:
        """Testa rate limiting."""
        console.print(f"\n[bold cyan]⏱️  Rate Limit Tester - {self.url}[/bold cyan]")
        console.print(f"Enviando {num_requests} requisições...\n")
        
        blocked_at = None
        rate_limit_headers = {}
        
        with Progress() as progress:
            task = progress.add_task("Testing...", total=num_requests)
            
            for i in range(num_requests):
                result = self.make_request()
                self.responses.append(result)
                progress.advance(task)
                
                # Detectar bloqueio
                if result["status"] == 429 and blocked_at is None:
                    blocked_at = i + 1
                    rate_limit_headers = result.get("headers", {})
                
                if delay > 0:
                    time.sleep(delay)
        
        # Analisar resultados
        successful = len([r for r in self.responses if r["status"] == 200])
        blocked = len([r for r in self.responses if r["status"] == 429])
        times = [r["time"] for r in self.responses if r["time"] > 0]
        avg_time = sum(times) / len(times) if times else 0
        
        return TestResult(
            total_requests=num_requests,
            successful=successful,
            blocked=blocked,
            avg_response_time=avg_time,
            rate_limit_detected=blocked > 0,
            threshold=blocked_at or 0,
            headers=rate_limit_headers
        )
    
    def test_bypass_techniques(self) -> Dict:
        """Testa técnicas de bypass."""
        console.print("\n[cyan]🔐 Testando técnicas de bypass...[/cyan]")
        
        bypasses = {}
        
        # Teste com X-Forwarded-For
        for ip in ["127.0.0.1", "10.0.0.1", "192.168.1.1"]:
            headers = {"X-Forwarded-For": ip}
            response = requests.get(self.url, headers=headers, timeout=10)
            if response.status_code == 200:
                bypasses["X-Forwarded-For"] = ip
                break
        
        # Teste com X-Real-IP
        headers = {"X-Real-IP": "127.0.0.1"}
        response = requests.get(self.url, headers=headers, timeout=10)
        if response.status_code == 200:
            bypasses["X-Real-IP"] = "127.0.0.1"
        
        return bypasses
    
    def print_results(self, result: TestResult):
        """Imprime resultados."""
        table = Table(title="\n📊 Resultados")
        table.add_column("Métrica")
        table.add_column("Valor")
        
        table.add_row("Total de Requisições", str(result.total_requests))
        table.add_row("Bem-sucedidas (200)", f"[green]{result.successful}[/green]")
        table.add_row("Bloqueadas (429)", f"[red]{result.blocked}[/red]")
        table.add_row("Tempo Médio", f"{result.avg_response_time:.3f}s")
        
        if result.rate_limit_detected:
            table.add_row("Rate Limit Detectado", f"[green]✅ Sim[/green]")
            table.add_row("Threshold", f"{result.threshold} requisições")
        else:
            table.add_row("Rate Limit Detectado", f"[red]❌ Não[/red]")
        
        console.print(table)
        
        # Headers de rate limit
        if result.headers:
            rate_headers = {k: v for k, v in result.headers.items() 
                          if "rate" in k.lower() or "limit" in k.lower() or "retry" in k.lower()}
            if rate_headers:
                console.print("\n[cyan]Headers de Rate Limit:[/cyan]")
                for k, v in rate_headers.items():
                    console.print(f"  {k}: {v}")
        
        # Veredicto
        if result.rate_limit_detected:
            console.print(f"\n[green]✅ Endpoint protegido com rate limiting (threshold: {result.threshold})[/green]")
        else:
            console.print(f"\n[red]⚠️ ALERTA: Endpoint sem rate limiting detectado![/red]")


def main():
    parser = argparse.ArgumentParser(description="Rate Limiting Tester")
    parser.add_argument("--url", "-u", required=True, help="URL alvo")
    parser.add_argument("--requests", "-r", type=int, default=100, help="Número de requisições")
    parser.add_argument("--delay", "-d", type=float, default=0, help="Delay entre requisições")
    parser.add_argument("--bypass", action="store_true", help="Testar bypasses")
    
    args = parser.parse_args()
    
    tester = RateLimitTester(args.url)
    result = tester.test_rate_limit(args.requests, args.delay)
    tester.print_results(result)
    
    if args.bypass:
        bypasses = tester.test_bypass_techniques()
        if bypasses:
            console.print(f"\n[red]⚠️ Bypasses encontrados: {bypasses}[/red]")


if __name__ == "__main__":
    main()
