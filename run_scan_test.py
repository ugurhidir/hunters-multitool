#!/usr/bin/env python3

import sys
import os

# Add the project directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core.scanner import Scanner
from rich.console import Console

console = Console()

def test_sql_injection():
    console.print("\n=== SQL Injection Test ===\n", style="bold green")
    
    # Specific vulnerable URL for SQL injection testing
    target = "http://testphp.vulnweb.com/listproducts.php?cat=1"
    console.print(f"Starting SQL Injection scan on {target}")
    
    scanner = Scanner(target=target)
    results = scanner.scan_sql_injection()
    
    console.print(f"Found {len(results)} SQL Injection vulnerabilities:", style="bold")
    
    for vuln in results:
        console.print(f"  URL: {vuln.get('url', 'Unknown')}")
        console.print(f"  Form Action: {vuln.get('form_action', 'N/A')}")
        console.print(f"  Method: {vuln.get('method', 'N/A')}")
        console.print(f"  Payload: {vuln.get('payload', 'N/A')}")
        console.print(f"  Error: {vuln.get('error', 'N/A')}")
        console.print(f"  Evidence: {vuln.get('evidence', 'N/A')}")
        console.print("")

def test_xss():
    console.print("\n=== XSS Test ===\n", style="bold green")
    
    # Specific vulnerable URL for XSS testing
    target = "http://testphp.vulnweb.com/search.php?test=query"
    console.print(f"Starting XSS scan on {target}")
    
    scanner = Scanner(target=target)
    results = scanner.scan_xss()
    
    console.print(f"Found {len(results)} XSS vulnerabilities:", style="bold")
    
    for vuln in results:
        console.print(f"  URL: {vuln.get('url', 'Unknown')}")
        console.print(f"  Form Action: {vuln.get('form_action', 'N/A')}")
        console.print(f"  Method: {vuln.get('method', 'N/A')}")
        console.print(f"  Payload: {vuln.get('payload', 'N/A')}")
        console.print(f"  Evidence: {vuln.get('evidence', 'N/A')}")
        console.print("")

if __name__ == "__main__":
    console.print("Running Hunters-Multitool Scanner Test", style="bold blue")
    
    test_sql_injection()
    test_xss()
    
    console.print("Tests completed!", style="bold green") 