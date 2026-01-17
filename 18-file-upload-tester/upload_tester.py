#!/usr/bin/env python3
"""
File Upload Security Tester
Testa segurança de funcionalidades de upload.
"""

import io
import argparse
from typing import List, Dict
from dataclasses import dataclass

import requests
from rich.console import Console
from rich.table import Table

console = Console()

# Payloads de teste
TEST_FILES = [
    {"name": "test.php", "content": b"<?php echo 'test'; ?>", "type": "application/x-php"},
    {"name": "test.php.jpg", "content": b"<?php echo 'test'; ?>", "type": "image/jpeg"},
    {"name": "test.jpg.php", "content": b"<?php echo 'test'; ?>", "type": "application/x-php"},
    {"name": "test.phtml", "content": b"<?php echo 'test'; ?>", "type": "text/html"},
    {"name": "test.php5", "content": b"<?php echo 'test'; ?>", "type": "application/x-php"},
    {"name": "test.PhP", "content": b"<?php echo 'test'; ?>", "type": "application/x-php"},
    {"name": "..\\..\\test.txt", "content": b"path traversal test", "type": "text/plain"},
    {"name": "../../../etc/passwd", "content": b"path traversal test", "type": "text/plain"},
    {"name": "test.svg", "content": b'<svg onload="alert(1)">', "type": "image/svg+xml"},
    {"name": "test.html", "content": b"<script>alert(1)</script>", "type": "text/html"},
]

# Magic bytes para diferentes tipos
MAGIC_BYTES = {
    "jpg": b"\xff\xd8\xff\xe0",
    "png": b"\x89PNG\r\n\x1a\n",
    "gif": b"GIF89a",
    "pdf": b"%PDF-1.4",
}


@dataclass
class UploadTestResult:
    filename: str
    technique: str
    accepted: bool
    severity: str
    details: str


class FileUploadTester:
    """Testador de upload de arquivos."""
    
    def __init__(self, url: str, field_name: str = "file"):
        self.url = url
        self.field_name = field_name
        self.results: List[UploadTestResult] = []
    
    def upload_file(self, filename: str, content: bytes, content_type: str) -> Dict:
        """Faz upload de um arquivo."""
        files = {
            self.field_name: (filename, io.BytesIO(content), content_type)
        }
        
        try:
            response = requests.post(self.url, files=files, timeout=30)
            return {
                "status": response.status_code,
                "body": response.text,
                "success": response.status_code in [200, 201, 302]
            }
        except Exception as e:
            return {"status": 0, "error": str(e), "success": False}
    
    def test_extension_bypass(self):
        """Testa bypass de extensão."""
        console.print("[cyan]🔍 Testando bypass de extensão...[/cyan]")
        
        for test in TEST_FILES:
            result = self.upload_file(test["name"], test["content"], test["type"])
            
            if result["success"]:
                self.results.append(UploadTestResult(
                    filename=test["name"],
                    technique="Extension Bypass",
                    accepted=True,
                    severity="Critical" if ".php" in test["name"].lower() else "High",
                    details=f"Arquivo aceito com status {result['status']}"
                ))
    
    def test_magic_bytes(self):
        """Testa manipulação de magic bytes."""
        console.print("[cyan]🔍 Testando magic bytes...[/cyan]")
        
        # PHP com magic bytes de imagem
        for img_type, magic in MAGIC_BYTES.items():
            php_content = magic + b"<?php echo 'test'; ?>"
            filename = f"test.{img_type}.php"
            
            result = self.upload_file(filename, php_content, f"image/{img_type}")
            
            if result["success"]:
                self.results.append(UploadTestResult(
                    filename=filename,
                    technique="Magic Bytes Bypass",
                    accepted=True,
                    severity="Critical",
                    details=f"PHP com magic bytes de {img_type} aceito"
                ))
    
    def test_content_type_bypass(self):
        """Testa bypass de Content-Type."""
        console.print("[cyan]🔍 Testando Content-Type bypass...[/cyan]")
        
        # PHP com Content-Type de imagem
        result = self.upload_file(
            "test.php",
            b"<?php echo 'test'; ?>",
            "image/jpeg"  # Content-Type falso
        )
        
        if result["success"]:
            self.results.append(UploadTestResult(
                filename="test.php",
                technique="Content-Type Bypass",
                accepted=True,
                severity="Critical",
                details="PHP aceito com Content-Type image/jpeg"
            ))
    
    def test_null_byte(self):
        """Testa injeção de null byte."""
        console.print("[cyan]🔍 Testando null byte injection...[/cyan]")
        
        result = self.upload_file(
            "test.php%00.jpg",
            b"<?php echo 'test'; ?>",
            "image/jpeg"
        )
        
        if result["success"]:
            self.results.append(UploadTestResult(
                filename="test.php%00.jpg",
                technique="Null Byte Injection",
                accepted=True,
                severity="Critical",
                details="Null byte injection aceito"
            ))
    
    def scan(self):
        """Executa todos os testes."""
        console.print(f"\n[bold cyan]📁 File Upload Tester - {self.url}[/bold cyan]\n")
        
        self.test_extension_bypass()
        self.test_magic_bytes()
        self.test_content_type_bypass()
        self.test_null_byte()
        
        return self.results
    
    def print_results(self):
        """Imprime resultados."""
        if not self.results:
            console.print("\n[green]✅ Nenhuma vulnerabilidade de upload encontrada![/green]")
            return
        
        table = Table(title=f"\n🚨 {len(self.results)} Vulnerabilidades de Upload")
        table.add_column("Arquivo")
        table.add_column("Técnica")
        table.add_column("Severidade")
        table.add_column("Detalhes")
        
        for r in self.results:
            color = "red" if r.severity == "Critical" else "yellow"
            table.add_row(
                r.filename,
                r.technique,
                f"[{color}]{r.severity}[/{color}]",
                r.details
            )
        
        console.print(table)


def main():
    parser = argparse.ArgumentParser(description="File Upload Tester")
    parser.add_argument("--url", "-u", required=True, help="URL de upload")
    parser.add_argument("--field", "-f", default="file", help="Nome do campo de arquivo")
    
    args = parser.parse_args()
    
    tester = FileUploadTester(args.url, args.field)
    tester.scan()
    tester.print_results()


if __name__ == "__main__":
    main()
