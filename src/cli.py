#!/usr/bin/env python3

import click
from rich.console import Console
import os
import sys

# Fix the imports
try:
    from src.core.recon import Recon
    from src.core.scanner import Scanner
    from src.core.reports import Reports
    import src.config as config
except ImportError:
    # Try relative imports if running from within src directory
    from core.recon import Recon
    from core.scanner import Scanner
    from core.reports import Reports
    import config

console = Console()

@click.group()
@click.version_option(version="0.1.0")
def cli():
    """Hunters-Multitool: A comprehensive security reconnaissance and vulnerability scanning tool."""
    pass

@cli.command()
@click.option("--target", "-t", required=True, help="Target domain to scan")
@click.option("--subdomains", "-s", is_flag=True, help="Enable subdomain enumeration")
@click.option("--apis", "-a", is_flag=True, help="Discover API endpoints")
@click.option("--js-files", "-j", is_flag=True, help="Find JS files")
@click.option("--google-dorks", "-g", is_flag=True, help="Perform Google dork searches")
@click.option("--github-dorks", "-gh", is_flag=True, help="Perform GitHub dork searches")
@click.option("--output", "-o", default="recon_results", help="Output file name for results")
@click.option("--threads", "-th", default=5, help="Number of threads to use")
def recon(target, subdomains, apis, js_files, google_dorks, github_dorks, output, threads):
    """Perform reconnaissance on a target."""
    console.print(f"[bold green]Starting reconnaissance on target: {target}[/]")
    
    recon_instance = Recon(target, threads)
    results = {}
    
    if subdomains:
        console.print("[bold blue]Enumerating subdomains...[/]")
        subdomains_found = recon_instance.enumerate_subdomains()
        results["subdomains"] = subdomains_found
        
    if apis:
        console.print("[bold blue]Discovering API endpoints...[/]")
        apis_found = recon_instance.discover_api_endpoints()
        results["apis"] = apis_found
        
    if js_files:
        console.print("[bold blue]Finding JS files...[/]")
        js_files_found = recon_instance.find_js_files()
        results["js_files"] = js_files_found
        
        console.print("[bold blue]Scanning JS files for secrets...[/]")
        secrets_found = recon_instance.scan_js_files_for_secrets(js_files_found)
        results["secrets"] = secrets_found
        
    if google_dorks:
        console.print("[bold blue]Performing Google dork searches...[/]")
        google_results = recon_instance.google_dork_search()
        results["google_dorks"] = google_results
        
    if github_dorks:
        console.print("[bold blue]Performing GitHub dork searches...[/]")
        github_results = recon_instance.github_dork_search()
        results["github_dorks"] = github_results
    
    # Generate report
    if results:
        reports = Reports()
        report_file = reports.generate_report(results, target, output)
        console.print(f"[bold green]Reconnaissance completed! Report saved to: {report_file}[/]")
    else:
        console.print("[bold yellow]No reconnaissance tasks were performed.[/]")

@cli.command()
@click.option("--target", "-t", required=True, help="Target URL to scan")
@click.option("--sql", is_flag=True, help="Scan for SQL Injection vulnerabilities")
@click.option("--xss", is_flag=True, help="Scan for XSS vulnerabilities")
@click.option("--all", "-a", is_flag=True, help="Scan for all vulnerabilities")
@click.option("--output", "-o", default="scan_results", help="Output file name for results")
@click.option("--threads", "-th", default=3, help="Number of threads to use")
def scan(target, sql, xss, all, output, threads):
    """Perform vulnerability scanning on a target."""
    console.print(f"[bold green]Starting vulnerability scan on target: {target}[/]")
    
    scanner = Scanner(target, threads)
    results = {}
    
    if all:
        sql = xss = True
    
    if sql:
        console.print("[bold blue]Scanning for SQL Injection vulnerabilities...[/]")
        sql_results = scanner.scan_sql_injection()
        results["sql_injection"] = sql_results
    
    if xss:
        console.print("[bold blue]Scanning for XSS vulnerabilities...[/]")
        xss_results = scanner.scan_xss()
        results["xss"] = xss_results
    
    # Generate report
    if results:
        reports = Reports()
        report_file = reports.generate_report(results, target, output, report_type="vulnerability")
        console.print(f"[bold green]Scan completed! Report saved to: {report_file}[/]")
    else:
        console.print("[bold yellow]No scan tasks were performed.[/]")

@cli.command()
def interactive():
    """Launch interactive mode with menu options."""
    import inquirer
    from inquirer import themes
    
    console.print("[bold green]Launching Hunters-Multitool in interactive mode[/]")
    
    while True:
        questions = [
            inquirer.List(
                "action",
                message="What would you like to do?",
                choices=["Reconnaissance", "Vulnerability Scan", "Configure Settings", "Exit"],
            ),
        ]
        
        answers = inquirer.prompt(questions)
        
        if answers["action"] == "Reconnaissance":
            # Ask for recon options
            target = inquirer.prompt([
                inquirer.Text("target", message="Enter target domain")
            ])["target"]
            
            options = inquirer.prompt([
                inquirer.Checkbox(
                    "options",
                    message="Select reconnaissance options",
                    choices=[
                        ("Subdomain Enumeration", "subdomains"),
                        ("API Endpoint Discovery", "apis"),
                        ("JavaScript Files", "js_files"),
                        ("Google Dorks", "google_dorks"),
                        ("GitHub Dorks", "github_dorks")
                    ]
                ),
                inquirer.Text("output", message="Output file name", default="recon_results"),
                inquirer.Text("threads", message="Number of threads", default="5")
            ])
            
            # Convert to CLI args and call recon
            args = ["--target", target]
            for opt in options["options"]:
                args.append(f"--{opt}")
            args.extend(["--output", options["output"], "--threads", options["threads"]])
            
            # This would normally call the recon function directly, but for demo we'll just print
            console.print(f"[bold blue]Would run recon with args: {' '.join(args)}[/]")
            
        elif answers["action"] == "Vulnerability Scan":
            # Ask for scan options
            target = inquirer.prompt([
                inquirer.Text("target", message="Enter target URL")
            ])["target"]
            
            options = inquirer.prompt([
                inquirer.Checkbox(
                    "options",
                    message="Select vulnerability scan options",
                    choices=[
                        ("SQL Injection", "sql"),
                        ("Cross-Site Scripting (XSS)", "xss"),
                        ("All Vulnerabilities", "all")
                    ]
                ),
                inquirer.Text("output", message="Output file name", default="scan_results"),
                inquirer.Text("threads", message="Number of threads", default="3")
            ])
            
            # Convert to CLI args and call scan
            args = ["--target", target]
            for opt in options["options"]:
                args.append(f"--{opt}")
            args.extend(["--output", options["output"], "--threads", options["threads"]])
            
            # This would normally call the scan function directly, but for demo we'll just print
            console.print(f"[bold blue]Would run scan with args: {' '.join(args)}[/]")
            
        elif answers["action"] == "Configure Settings":
            console.print("[bold blue]Configuration options:[/]")
            # This would normally allow configuration of API keys and settings
            pass
            
        elif answers["action"] == "Exit":
            console.print("[bold green]Thank you for using Hunters-Multitool![/]")
            break

if __name__ == "__main__":
    cli() 