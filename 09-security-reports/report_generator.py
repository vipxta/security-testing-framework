#!/usr/bin/env python3
"""
Security Reports Generator
Gera relatórios de segurança profissionais.
"""

import json
import argparse
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict

from jinja2 import Template
from rich.console import Console
import matplotlib.pyplot as plt

console = Console()

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Security Report - {{ title }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1 { color: #2c3e50; }
        .summary { background: #ecf0f1; padding: 20px; border-radius: 5px; }
        .critical { color: #e74c3c; }
        .high { color: #e67e22; }
        .medium { color: #f39c12; }
        .low { color: #3498db; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background: #2c3e50; color: white; }
        tr:nth-child(even) { background: #f9f9f9; }
    </style>
</head>
<body>
    <h1>🛡️ {{ title }}</h1>
    <p>Generated: {{ timestamp }}</p>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p>Total vulnerabilities found: <strong>{{ total }}</strong></p>
        <ul>
            <li class="critical">Critical: {{ summary.critical }}</li>
            <li class="high">High: {{ summary.high }}</li>
            <li class="medium">Medium: {{ summary.medium }}</li>
            <li class="low">Low: {{ summary.low }}</li>
        </ul>
    </div>
    
    <h2>Vulnerabilities</h2>
    <table>
        <tr>
            <th>Severity</th>
            <th>Name</th>
            <th>URL</th>
            <th>Description</th>
        </tr>
        {% for vuln in vulnerabilities %}
        <tr>
            <td class="{{ vuln.severity|lower }}">{{ vuln.severity }}</td>
            <td>{{ vuln.name }}</td>
            <td>{{ vuln.url }}</td>
            <td>{{ vuln.description }}</td>
        </tr>
        {% endfor %}
    </table>
    
    <h2>Recommendations</h2>
    <ol>
        {% for rec in recommendations %}
        <li>{{ rec }}</li>
        {% endfor %}
    </ol>
</body>
</html>
"""


@dataclass
class Vulnerability:
    name: str
    severity: str
    url: str
    description: str
    remediation: str


class ReportGenerator:
    """Gerador de relatórios de segurança."""
    
    def __init__(self, title: str = "Security Assessment Report"):
        self.title = title
        self.vulnerabilities: List[Vulnerability] = []
        self.timestamp = datetime.now().isoformat()
    
    def load_from_json(self, filepath: str):
        """Carrega vulnerabilidades de arquivo JSON."""
        with open(filepath) as f:
            data = json.load(f)
        
        for item in data.get("vulnerabilities", []):
            self.vulnerabilities.append(Vulnerability(
                name=item.get("name", "Unknown"),
                severity=item.get("severity", "info"),
                url=item.get("url", ""),
                description=item.get("description", ""),
                remediation=item.get("remediation", "")
            ))
    
    def get_summary(self) -> Dict:
        """Retorna resumo por severidade."""
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in self.vulnerabilities:
            sev = v.severity.lower()
            if sev in summary:
                summary[sev] += 1
        return summary
    
    def get_recommendations(self) -> List[str]:
        """Gera recomendações baseadas nas vulnerabilidades."""
        recommendations = set()
        
        for v in self.vulnerabilities:
            if "sql" in v.name.lower():
                recommendations.add("Implementar prepared statements e parameterized queries")
            if "xss" in v.name.lower():
                recommendations.add("Implementar encoding de output e Content Security Policy")
            if "csrf" in v.name.lower():
                recommendations.add("Implementar tokens CSRF e SameSite cookies")
            if "auth" in v.name.lower():
                recommendations.add("Implementar autenticação multi-fator e rate limiting")
        
        if not recommendations:
            recommendations.add("Continuar monitoramento de segurança")
        
        return list(recommendations)
    
    def generate_chart(self, output_path: str):
        """Gera gráfico de vulnerabilidades."""
        summary = self.get_summary()
        
        labels = ["Critical", "High", "Medium", "Low"]
        values = [summary["critical"], summary["high"], summary["medium"], summary["low"]]
        colors = ["#e74c3c", "#e67e22", "#f39c12", "#3498db"]
        
        fig, ax = plt.subplots(figsize=(8, 6))
        bars = ax.bar(labels, values, color=colors)
        
        ax.set_ylabel("Count")
        ax.set_title("Vulnerabilities by Severity")
        
        for bar, val in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                   str(val), ha="center", va="bottom", fontweight="bold")
        
        plt.tight_layout()
        plt.savefig(output_path, dpi=150)
        console.print(f"[green]✅ Gráfico salvo: {output_path}[/green]")
    
    def generate_html(self, output_path: str):
        """Gera relatório HTML."""
        template = Template(HTML_TEMPLATE)
        
        html = template.render(
            title=self.title,
            timestamp=self.timestamp,
            total=len(self.vulnerabilities),
            summary=self.get_summary(),
            vulnerabilities=[asdict(v) for v in self.vulnerabilities],
            recommendations=self.get_recommendations()
        )
        
        with open(output_path, "w") as f:
            f.write(html)
        
        console.print(f"[green]✅ Relatório HTML salvo: {output_path}[/green]")
    
    def generate_json(self, output_path: str):
        """Gera relatório JSON."""
        report = {
            "title": self.title,
            "timestamp": self.timestamp,
            "summary": self.get_summary(),
            "total": len(self.vulnerabilities),
            "vulnerabilities": [asdict(v) for v in self.vulnerabilities],
            "recommendations": self.get_recommendations()
        }
        
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)
        
        console.print(f"[green]✅ Relatório JSON salvo: {output_path}[/green]")


def main():
    parser = argparse.ArgumentParser(description="Security Report Generator")
    parser.add_argument("--input", "-i", required=True, help="Arquivo de entrada JSON")
    parser.add_argument("--output", "-o", required=True, help="Arquivo de saída")
    parser.add_argument("--title", default="Security Assessment Report")
    parser.add_argument("--chart", help="Gerar gráfico")
    
    args = parser.parse_args()
    
    generator = ReportGenerator(title=args.title)
    generator.load_from_json(args.input)
    
    output_path = args.output
    if output_path.endswith(".html"):
        generator.generate_html(output_path)
    elif output_path.endswith(".json"):
        generator.generate_json(output_path)
    
    if args.chart:
        generator.generate_chart(args.chart)


if __name__ == "__main__":
    main()
