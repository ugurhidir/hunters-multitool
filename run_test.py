#!/usr/bin/env python3

import sys
import os

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.core.recon import Recon
from rich.console import Console

console = Console()

def test_subdomain_enumeration():
    target = "vulnweb.com"
    console.print(f"[bold green]Starting subdomain enumeration on {target}[/]")
    
    recon = Recon(target, threads=5)
    subdomains = recon.enumerate_subdomains()
    
    console.print(f"[bold blue]Found {len(subdomains)} subdomains:[/]")
    for subdomain in subdomains:
        console.print(f"  - {subdomain['name']} ({subdomain['ip']}) - Status: {subdomain['status_code']}")
        if subdomain['takeover_vulnerable']:
            console.print(f"    [bold red]Vulnerable to takeover: {subdomain['takeover_details']}[/]")
    
    return subdomains

def test_js_files():
    target = "testphp.vulnweb.com"
    console.print(f"[bold green]Finding JS files on {target}[/]")
    
    recon = Recon(target, threads=5)
    js_files = recon.find_js_files()
    
    console.print(f"[bold blue]Found {len(js_files)} JavaScript files:[/]")
    for js_file in js_files:
        console.print(f"  - {js_file}")
    
    console.print("[bold green]Scanning JS files for secrets...[/]")
    secrets = recon.scan_js_files_for_secrets(js_files)
    
    console.print(f"[bold blue]Found {len(secrets)} potential secrets:[/]")
    for secret in secrets:
        console.print(f"  - {secret['type']} in {secret['file']} (line {secret['line_number']})")
    
    return js_files, secrets

if __name__ == "__main__":
    console.print("[bold]Running Hunters-Multitool Test[/]")
    
    print("\n=== Subdomain Enumeration Test ===\n")
    subdomains = test_subdomain_enumeration()
    
    print("\n=== JavaScript File Finding and Secret Detection Test ===\n")
    js_files, secrets = test_js_files()
    
    console.print("[bold green]Tests completed![/]") 