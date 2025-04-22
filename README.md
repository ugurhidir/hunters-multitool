# Hunters-Multitool

A comprehensive security reconnaissance and vulnerability scanning tool for ethical hackers and security researchers.

## Features

- **Reconnaissance Module**
  - Subdomain enumeration (DNS zone transfer, brute force, API queries)
  - API endpoint discovery (robots.txt, sitemap.xml, JS files analysis)
  - JavaScript file discovery and analysis
  - Secret key detection in JavaScript files
  - Google dork searches
  - GitHub dork searches
  - Subdomain takeover detection

- **Vulnerability Scanner**
  - SQL Injection detection
  - Cross-Site Scripting (XSS) detection
  - Form analysis and testing

- **Reporting**
  - HTML report generation
  - Markdown report generation
  - Detailed evidence tracking

## Installation

1. Clone the repository:

```bash
git clone https://github.com/ugurhidir/hunters-multitool.git
cd hunters-multitool
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

### Command Line Interface

```bash
# Run reconnaissance on a target
python src/main.py recon --target example.com --subdomains --apis --js-files

# Run vulnerability scan
python src/main.py scan --target https://example.com --sql --xss

# Launch interactive mode
python src/main.py interactive
```

### Available Commands

#### Reconnaissance

```bash
python src/main.py recon --target <domain> [options]
```

Options:
- `--subdomains` (`-s`): Enable subdomain enumeration
- `--apis` (`-a`): Discover API endpoints
- `--js-files` (`-j`): Find JS files and scan for secrets
- `--google-dorks` (`-g`): Perform Google dork searches
- `--github-dorks` (`-gh`): Perform GitHub dork searches
- `--output` (`-o`): Output file name for results (default: recon_results)
- `--threads` (`-th`): Number of threads to use (default: 5)

#### Vulnerability Scanning

```bash
python src/main.py scan --target <url> [options]
```

Options:
- `--sql`: Scan for SQL Injection vulnerabilities
- `--xss`: Scan for XSS vulnerabilities
- `--all` (`-a`): Scan for all vulnerabilities
- `--output` (`-o`): Output file name for results (default: scan_results)
- `--threads` (`-th`): Number of threads to use (default: 3)

#### Interactive Mode

```bash
python src/main.py interactive
```

This will launch an interactive menu-driven interface.

## Configuration

The tool uses a configuration file located at `~/.hunters_multitool/config.json`. You can add API keys for services like Shodan, VirusTotal, etc.

Example:
```json
{
    "api_keys": {
        "shodan": "your-shodan-api-key",
        "virustotal": "your-virustotal-api-key",
        "securitytrails": "your-securitytrails-api-key"
    },
    "settings": {
        "threads": 5,
        "timeout": 10,
        "user_agent": "Hunters-Multitool/0.1.0",
        "report_format": "html"
    }
}
```

## Legal Disclaimer

This tool is provided for educational and ethical security testing purposes only. Users are responsible for complying with all applicable laws and regulations in their jurisdiction. The developers assume no liability for misuse of this software.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 