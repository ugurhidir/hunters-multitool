#!/usr/bin/env python3

import os
import json
import datetime
from typing import Dict, Any, List, Optional
from jinja2 import Template
import re

from src.config import get_setting

class Reports:
    def __init__(self):
        """Initialize the Reports module."""
        self.report_format = get_setting("report_format") or "html"
    
    def generate_report(self, data: Dict[str, Any], target: str, output_name: str, 
                       report_type: str = "recon") -> str:
        """Generate a report from scan data.
        
        Args:
            data: Dictionary containing scan results
            target: Target that was scanned
            output_name: Base name for output file
            report_type: Type of report ("recon" or "vulnerability")
            
        Returns:
            Path to generated report file
        """
        # Create reports directory if not exists
        reports_dir = os.path.join(os.getcwd(), "reports")
        if not os.path.exists(reports_dir):
            os.makedirs(reports_dir)
        
        # Create timestamp for filename
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Generate report based on format
        if self.report_format == "html":
            return self._generate_html_report(data, target, output_name, timestamp, report_type, reports_dir)
        else:
            return self._generate_markdown_report(data, target, output_name, timestamp, report_type, reports_dir)
    
    def _generate_html_report(self, data: Dict[str, Any], target: str, output_name: str, 
                             timestamp: str, report_type: str, reports_dir: str) -> str:
        """Generate HTML report.
        
        Args:
            data: Dictionary containing scan results
            target: Target that was scanned
            output_name: Base name for output file
            timestamp: Timestamp for filename
            report_type: Type of report
            reports_dir: Directory to save reports
            
        Returns:
            Path to generated report file
        """
        if report_type == "recon":
            template = self._get_recon_html_template()
        else:
            template = self._get_vulnerability_html_template()
        
        report_data = {
            "target": target,
            "date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "data": data,
            "summary": self._generate_summary(data, report_type)
        }
        
        rendered = Template(template).render(**report_data)
        
        output_file = os.path.join(reports_dir, f"{output_name}_{timestamp}.html")
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(rendered)
        
        return output_file
    
    def _generate_markdown_report(self, data: Dict[str, Any], target: str, output_name: str, 
                                timestamp: str, report_type: str, reports_dir: str) -> str:
        """Generate Markdown report.
        
        Args:
            data: Dictionary containing scan results
            target: Target that was scanned
            output_name: Base name for output file
            timestamp: Timestamp for filename
            report_type: Type of report
            reports_dir: Directory to save reports
            
        Returns:
            Path to generated report file
        """
        if report_type == "recon":
            template = self._get_recon_markdown_template()
        else:
            template = self._get_vulnerability_markdown_template()
        
        report_data = {
            "target": target,
            "date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "data": data,
            "summary": self._generate_summary(data, report_type)
        }
        
        rendered = Template(template).render(**report_data)
        
        output_file = os.path.join(reports_dir, f"{output_name}_{timestamp}.md")
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(rendered)
        
        return output_file
    
    def _generate_summary(self, data: Dict[str, Any], report_type: str) -> Dict[str, Any]:
        """Generate summary statistics for report.
        
        Args:
            data: Dictionary containing scan results
            report_type: Type of report
            
        Returns:
            Dictionary with summary statistics
        """
        summary = {}
        
        if report_type == "recon":
            # Count various recon findings
            summary["subdomains"] = len(data.get("subdomains", []))
            summary["apis"] = len(data.get("apis", []))
            summary["js_files"] = len(data.get("js_files", []))
            summary["secrets"] = len(data.get("secrets", []))
            summary["google_dorks"] = len(data.get("google_dorks", []))
            summary["github_dorks"] = len(data.get("github_dorks", []))
            
            # Count takeover vulnerable subdomains
            takeover_count = 0
            for subdomain in data.get("subdomains", []):
                if subdomain.get("takeover_vulnerable", False):
                    takeover_count += 1
            summary["takeover_vulnerable"] = takeover_count
            
        else:  # vulnerability scan
            # Count vulnerabilities by type
            summary["sql_injection"] = len(data.get("sql_injection", []))
            summary["xss"] = len(data.get("xss", []))
            summary["total"] = summary["sql_injection"] + summary["xss"]
            
            # Calculate severity levels
            high = summary["sql_injection"]  # SQL injection is high severity
            medium = summary["xss"]  # XSS is medium severity
            summary["severity"] = {
                "high": high,
                "medium": medium,
                "low": 0
            }
        
        return summary
    
    def _get_recon_html_template(self) -> str:
        """Get HTML template for reconnaissance report."""
        return """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Reconnaissance Report - {{ target }}</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        h1, h2, h3 {
            color: #2c3e50;
        }
        .summary {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        th, td {
            padding: 12px 15px;
            border: 1px solid #ddd;
            text-align: left;
        }
        th {
            background-color: #4CAF50;
            color: white;
        }
        tr:nth-child(even) {
            background-color: #f2f2f2;
        }
        .vulnerable {
            color: #ff0000;
            font-weight: bold;
        }
        .evidence {
            font-family: monospace;
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
        }
        .footer {
            margin-top: 40px;
            text-align: center;
            color: #777;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Reconnaissance Report</h1>
        <p><strong>Target:</strong> {{ target }}</p>
        <p><strong>Date:</strong> {{ date }}</p>
        
        <div class="summary">
            <h2>Summary</h2>
            <p>Total subdomains found: {{ summary.subdomains }}</p>
            <p>Subdomain takeover vulnerabilities: {{ summary.takeover_vulnerable }}</p>
            <p>API endpoints discovered: {{ summary.apis }}</p>
            <p>JavaScript files found: {{ summary.js_files }}</p>
            <p>Secrets discovered: {{ summary.secrets }}</p>
            <p>Google dork searches: {{ summary.google_dorks }}</p>
            <p>GitHub dork searches: {{ summary.github_dorks }}</p>
        </div>
        
        {% if data.subdomains %}
        <h2>Subdomains</h2>
        <table>
            <tr>
                <th>Subdomain</th>
                <th>IP Address</th>
                <th>Status Code</th>
                <th>Server</th>
                <th>Takeover Vulnerable</th>
            </tr>
            {% for subdomain in data.subdomains %}
            <tr>
                <td>{{ subdomain.name }}</td>
                <td>{{ subdomain.ip }}</td>
                <td>{{ subdomain.status_code }}</td>
                <td>{{ subdomain.server }}</td>
                <td {% if subdomain.takeover_vulnerable %}class="vulnerable"{% endif %}>
                    {% if subdomain.takeover_vulnerable %}
                        Yes - {{ subdomain.takeover_details }}
                    {% else %}
                        No
                    {% endif %}
                </td>
            </tr>
            {% endfor %}
        </table>
        {% endif %}
        
        {% if data.apis %}
        <h2>API Endpoints</h2>
        <table>
            <tr>
                <th>URL</th>
                <th>Method</th>
            </tr>
            {% for api in data.apis %}
            <tr>
                <td>{{ api.url }}</td>
                <td>{{ api.method }}</td>
            </tr>
            {% endfor %}
        </table>
        {% endif %}
        
        {% if data.js_files %}
        <h2>JavaScript Files</h2>
        <ul>
            {% for js_file in data.js_files %}
            <li>{{ js_file }}</li>
            {% endfor %}
        </ul>
        {% endif %}
        
        {% if data.secrets %}
        <h2>Secrets Found</h2>
        <table>
            <tr>
                <th>Type</th>
                <th>Value</th>
                <th>File</th>
                <th>Line Number</th>
            </tr>
            {% for secret in data.secrets %}
            <tr>
                <td>{{ secret.type }}</td>
                <td>{{ secret.value }}</td>
                <td>{{ secret.file }}</td>
                <td>{{ secret.line_number }}</td>
            </tr>
            {% endfor %}
        </table>
        {% endif %}
        
        {% if data.google_dorks %}
        <h2>Google Dork Searches</h2>
        <table>
            <tr>
                <th>Dork Query</th>
                <th>Description</th>
                <th>Example URL</th>
            </tr>
            {% for dork in data.google_dorks %}
            <tr>
                <td>{{ dork.dork }}</td>
                <td>{{ dork.description }}</td>
                <td><a href="{{ dork.example_url }}" target="_blank">Search</a></td>
            </tr>
            {% endfor %}
        </table>
        {% endif %}
        
        {% if data.github_dorks %}
        <h2>GitHub Dork Searches</h2>
        <table>
            <tr>
                <th>Dork Query</th>
                <th>Description</th>
                <th>Example URL</th>
            </tr>
            {% for dork in data.github_dorks %}
            <tr>
                <td>{{ dork.dork }}</td>
                <td>{{ dork.description }}</td>
                <td><a href="{{ dork.example_url }}" target="_blank">Search</a></td>
            </tr>
            {% endfor %}
        </table>
        {% endif %}
        
        <div class="footer">
            <p>Generated by Hunters-Multitool</p>
        </div>
    </div>
</body>
</html>"""
    
    def _get_vulnerability_html_template(self) -> str:
        """Get HTML template for vulnerability report."""
        return """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Vulnerability Scan Report - {{ target }}</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        h1, h2, h3 {
            color: #2c3e50;
        }
        .summary {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .severity-gauge {
            display: flex;
            margin: 20px 0;
        }
        .severity-bar {
            height: 20px;
            flex: 1;
            margin-right: 5px;
        }
        .high {
            background-color: #ff4d4d;
        }
        .medium {
            background-color: #ffb84d;
        }
        .low {
            background-color: #4da6ff;
        }
        .severity-label {
            text-align: center;
            font-size: 12px;
            margin-top: 5px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        th, td {
            padding: 12px 15px;
            border: 1px solid #ddd;
            text-align: left;
        }
        th {
            background-color: #4CAF50;
            color: white;
        }
        tr:nth-child(even) {
            background-color: #f2f2f2;
        }
        .evidence {
            font-family: monospace;
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
            max-height: 200px;
            overflow-y: auto;
        }
        .footer {
            margin-top: 40px;
            text-align: center;
            color: #777;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Vulnerability Scan Report</h1>
        <p><strong>Target:</strong> {{ target }}</p>
        <p><strong>Date:</strong> {{ date }}</p>
        
        <div class="summary">
            <h2>Summary</h2>
            <p>Total vulnerabilities found: {{ summary.total }}</p>
            <p>SQL Injection vulnerabilities: {{ summary.sql_injection }}</p>
            <p>Cross-Site Scripting (XSS) vulnerabilities: {{ summary.xss }}</p>
            
            <h3>Severity Distribution</h3>
            <div class="severity-gauge">
                <div style="flex: {{ summary.severity.high }}">
                    <div class="severity-bar high"></div>
                    <div class="severity-label">High: {{ summary.severity.high }}</div>
                </div>
                <div style="flex: {{ summary.severity.medium }}">
                    <div class="severity-bar medium"></div>
                    <div class="severity-label">Medium: {{ summary.severity.medium }}</div>
                </div>
                <div style="flex: {{ summary.severity.low }}">
                    <div class="severity-bar low"></div>
                    <div class="severity-label">Low: {{ summary.severity.low }}</div>
                </div>
            </div>
        </div>
        
        {% if data.sql_injection %}
        <h2>SQL Injection Vulnerabilities</h2>
        {% for vuln in data.sql_injection %}
        <div class="vulnerability">
            <h3>URL: {{ vuln.url }}</h3>
            <p><strong>Form Action:</strong> {{ vuln.form_action }}</p>
            <p><strong>Method:</strong> {{ vuln.method|upper }}</p>
            <p><strong>Payload:</strong> <code>{{ vuln.payload }}</code></p>
            <p><strong>Error:</strong> {{ vuln.error }}</p>
            
            <h4>Evidence</h4>
            <pre class="evidence">{{ vuln.evidence }}</pre>
            
            <h4>Form Inputs</h4>
            <table>
                <tr>
                    <th>Name</th>
                    <th>Type</th>
                    <th>Default Value</th>
                </tr>
                {% for input in vuln.inputs %}
                <tr>
                    <td>{{ input.name }}</td>
                    <td>{{ input.type }}</td>
                    <td>{{ input.value }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
        <hr>
        {% endfor %}
        {% endif %}
        
        {% if data.xss %}
        <h2>Cross-Site Scripting (XSS) Vulnerabilities</h2>
        {% for vuln in data.xss %}
        <div class="vulnerability">
            <h3>URL: {{ vuln.url }}</h3>
            <p><strong>Form Action:</strong> {{ vuln.form_action }}</p>
            <p><strong>Method:</strong> {{ vuln.method|upper }}</p>
            <p><strong>Payload:</strong> <code>{{ vuln.payload }}</code></p>
            
            <h4>Evidence</h4>
            <pre class="evidence">{{ vuln.evidence }}</pre>
            
            <h4>Form Inputs</h4>
            <table>
                <tr>
                    <th>Name</th>
                    <th>Type</th>
                    <th>Default Value</th>
                </tr>
                {% for input in vuln.inputs %}
                <tr>
                    <td>{{ input.name }}</td>
                    <td>{{ input.type }}</td>
                    <td>{{ input.value }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
        <hr>
        {% endfor %}
        {% endif %}
        
        <div class="footer">
            <p>Generated by Hunters-Multitool</p>
        </div>
    </div>
</body>
</html>"""
    
    def _get_recon_markdown_template(self) -> str:
        """Get Markdown template for reconnaissance report."""
        return """# Reconnaissance Report

**Target:** {{ target }}  
**Date:** {{ date }}

## Summary

- Total subdomains found: {{ summary.subdomains }}
- Subdomain takeover vulnerabilities: {{ summary.takeover_vulnerable }}
- API endpoints discovered: {{ summary.apis }}
- JavaScript files found: {{ summary.js_files }}
- Secrets discovered: {{ summary.secrets }}
- Google dork searches: {{ summary.google_dorks }}
- GitHub dork searches: {{ summary.github_dorks }}

{% if data.subdomains %}
## Subdomains

| Subdomain | IP Address | Status Code | Server | Takeover Vulnerable |
|-----------|------------|-------------|--------|---------------------|
{% for subdomain in data.subdomains %}
| {{ subdomain.name }} | {{ subdomain.ip }} | {{ subdomain.status_code }} | {{ subdomain.server }} | {% if subdomain.takeover_vulnerable %}Yes - {{ subdomain.takeover_details }}{% else %}No{% endif %} |
{% endfor %}
{% endif %}

{% if data.apis %}
## API Endpoints

| URL | Method |
|-----|--------|
{% for api in data.apis %}
| {{ api.url }} | {{ api.method }} |
{% endfor %}
{% endif %}

{% if data.js_files %}
## JavaScript Files

{% for js_file in data.js_files %}
- {{ js_file }}
{% endfor %}
{% endif %}

{% if data.secrets %}
## Secrets Found

| Type | Value | File | Line Number |
|------|-------|------|-------------|
{% for secret in data.secrets %}
| {{ secret.type }} | {{ secret.value }} | {{ secret.file }} | {{ secret.line_number }} |
{% endfor %}
{% endif %}

{% if data.google_dorks %}
## Google Dork Searches

| Dork Query | Description | Example URL |
|------------|-------------|-------------|
{% for dork in data.google_dorks %}
| {{ dork.dork }} | {{ dork.description }} | [Search]({{ dork.example_url }}) |
{% endfor %}
{% endif %}

{% if data.github_dorks %}
## GitHub Dork Searches

| Dork Query | Description | Example URL |
|------------|-------------|-------------|
{% for dork in data.github_dorks %}
| {{ dork.dork }} | {{ dork.description }} | [Search]({{ dork.example_url }}) |
{% endfor %}
{% endif %}

---
*Generated by Hunters-Multitool*
"""
    
    def _get_vulnerability_markdown_template(self) -> str:
        """Get Markdown template for vulnerability report."""
        return """# Vulnerability Scan Report

**Target:** {{ target }}  
**Date:** {{ date }}

## Summary

- Total vulnerabilities found: {{ summary.total }}
- SQL Injection vulnerabilities: {{ summary.sql_injection }}
- Cross-Site Scripting (XSS) vulnerabilities: {{ summary.xss }}

### Severity Distribution

- High: {{ summary.severity.high }}
- Medium: {{ summary.severity.medium }}
- Low: {{ summary.severity.low }}

{% if data.sql_injection %}
## SQL Injection Vulnerabilities

{% for vuln in data.sql_injection %}
### URL: {{ vuln.url }}

- **Form Action:** {{ vuln.form_action }}
- **Method:** {{ vuln.method|upper }}
- **Payload:** `{{ vuln.payload }}`
- **Error:** {{ vuln.error }}

#### Evidence

```
{{ vuln.evidence }}
```

#### Form Inputs

| Name | Type | Default Value |
|------|------|---------------|
{% for input in vuln.inputs %}
| {{ input.name }} | {{ input.type }} | {{ input.value }} |
{% endfor %}

---
{% endfor %}
{% endif %}

{% if data.xss %}
## Cross-Site Scripting (XSS) Vulnerabilities

{% for vuln in data.xss %}
### URL: {{ vuln.url }}

- **Form Action:** {{ vuln.form_action }}
- **Method:** {{ vuln.method|upper }}
- **Payload:** `{{ vuln.payload }}`

#### Evidence

```
{{ vuln.evidence }}
```

#### Form Inputs

| Name | Type | Default Value |
|------|------|---------------|
{% for input in vuln.inputs %}
| {{ input.name }} | {{ input.type }} | {{ input.value }} |
{% endfor %}

---
{% endfor %}
{% endif %}

*Generated by Hunters-Multitool*
""" 