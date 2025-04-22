#!/usr/bin/env python3

import re
import dns.resolver
import dns.zone
import dns.query
import requests
import threading
import queue
import tldextract
import os
import json
import time
from bs4 import BeautifulSoup
from typing import List, Dict, Any, Set, Optional
from concurrent.futures import ThreadPoolExecutor
from rich.progress import Progress

from src.config import get_api_key, get_setting, get_google_dorks, get_github_dorks

class Recon:
    def __init__(self, target: str, threads: int = 5):
        """Initialize the Recon module.
        
        Args:
            target: The target domain to perform reconnaissance on
            threads: Number of threads to use for concurrent operations
        """
        self.target = target
        self.threads = threads
        self.extract = tldextract.extract(target)
        self.root_domain = f"{self.extract.domain}.{self.extract.suffix}"
        self.subdomains = set()
        self.api_endpoints = set()
        self.js_files = set()
        self.user_agent = get_setting("user_agent") or "Hunters-Multitool/0.1.0"
        self.timeout = get_setting("timeout") or 10
        
        self.headers = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
        }
    
    def enumerate_subdomains(self) -> List[Dict[str, Any]]:
        """Perform subdomain enumeration using multiple techniques.
        
        Returns:
            List of subdomain information dictionaries
        """
        result = []
        
        # Combine results from different methods
        self._dns_zone_transfer()
        self._bruteforce_subdomains()
        self._query_apis_for_subdomains()
        
        # Check if subdomains are alive and gather additional info
        live_subdomains = self._check_alive_subdomains()
        
        # Check for subdomain takeover
        takeover_results = self._check_subdomain_takeover(live_subdomains)
        
        # Format results
        for subdomain, info in live_subdomains.items():
            subdomain_data = {
                "name": subdomain,
                "ip": info.get("ip", "Unknown"),
                "status_code": info.get("status_code", 0),
                "server": info.get("server", "Unknown"),
                "takeover_vulnerable": subdomain in takeover_results,
                "takeover_details": takeover_results.get(subdomain, "")
            }
            result.append(subdomain_data)
        
        return result
    
    def _dns_zone_transfer(self) -> None:
        """Attempt DNS zone transfer to discover subdomains."""
        try:
            ns_records = dns.resolver.resolve(self.root_domain, 'NS')
            nameservers = [ns.target.to_text() for ns in ns_records]
            
            for ns in nameservers:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns, self.root_domain))
                    for name, _ in zone.nodes.items():
                        subdomain = name.to_text() + "." + self.root_domain
                        if subdomain != self.root_domain:
                            self.subdomains.add(subdomain)
                except Exception:
                    # Zone transfer failed, which is expected for most domains
                    pass
        except Exception as e:
            print(f"DNS zone transfer error: {e}")
    
    def _bruteforce_subdomains(self) -> None:
        """Bruteforce subdomains using a wordlist."""
        # Load subdomain wordlist
        wordlist_file = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "wordlists", "subdomains.txt"
        )
        
        if not os.path.exists(wordlist_file):
            # Create default wordlist with common subdomains if not existing
            os.makedirs(os.path.dirname(wordlist_file), exist_ok=True)
            common_subdomains = ["www", "mail", "remote", "blog", "webmail", "server", "ns", "ns1", "ns2", 
                                 "smtp", "secure", "vpn", "m", "shop", "ftp", "api", "admin", "dev", "test"]
            
            with open(wordlist_file, "w") as f:
                f.write("\n".join(common_subdomains))
        
        with open(wordlist_file, "r") as f:
            subdomains_list = [line.strip() for line in f if line.strip()]
        
        # Use thread pool to check subdomains
        q = queue.Queue()
        for subdomain in subdomains_list:
            q.put(subdomain)
        
        def worker():
            while not q.empty():
                subdomain = q.get()
                try:
                    hostname = f"{subdomain}.{self.root_domain}"
                    # Try to resolve the hostname
                    dns.resolver.resolve(hostname, 'A')
                    self.subdomains.add(hostname)
                except Exception:
                    pass
                finally:
                    q.task_done()
        
        # Start worker threads
        for _ in range(min(self.threads, 20)):  # Limit to 20 threads max
            t = threading.Thread(target=worker)
            t.daemon = True
            t.start()
        
        # Wait for all tasks to complete
        q.join()
    
    def _query_apis_for_subdomains(self) -> None:
        """Query various APIs to find subdomains."""
        # SecurityTrails API (if API key available)
        securitytrails_api = get_api_key("securitytrails")
        if securitytrails_api:
            try:
                url = f"https://api.securitytrails.com/v1/domain/{self.root_domain}/subdomains"
                headers = {
                    "APIKEY": securitytrails_api,
                    "Content-Type": "application/json"
                }
                response = requests.get(url, headers=headers, timeout=self.timeout)
                if response.status_code == 200:
                    data = response.json()
                    for subdomain in data.get("subdomains", []):
                        self.subdomains.add(f"{subdomain}.{self.root_domain}")
            except Exception as e:
                print(f"SecurityTrails API error: {e}")
        
        # Shodan API (if API key available)
        shodan_api = get_api_key("shodan")
        if shodan_api:
            try:
                url = f"https://api.shodan.io/dns/domain/{self.root_domain}?key={shodan_api}"
                response = requests.get(url, timeout=self.timeout)
                if response.status_code == 200:
                    data = response.json()
                    for entry in data.get("data", []):
                        if "subdomain" in entry and entry["subdomain"]:
                            self.subdomains.add(f"{entry['subdomain']}.{self.root_domain}")
            except Exception as e:
                print(f"Shodan API error: {e}")
    
    def _check_alive_subdomains(self) -> Dict[str, Dict[str, Any]]:
        """Check if subdomains are alive and gather information.
        
        Returns:
            Dictionary mapping subdomains to their information
        """
        results = {}
        
        def check_subdomain(subdomain):
            try:
                url = f"http://{subdomain}"
                response = requests.head(url, headers=self.headers, timeout=self.timeout, allow_redirects=True)
                
                # Try HTTPS if HTTP failed
                if response.status_code >= 400:
                    url = f"https://{subdomain}"
                    response = requests.head(url, headers=self.headers, timeout=self.timeout, allow_redirects=True)
                
                if response.status_code < 500:  # Consider anything below 500 as "alive"
                    try:
                        ip = str(dns.resolver.resolve(subdomain, 'A')[0])
                    except Exception:
                        ip = "Unknown"
                    
                    results[subdomain] = {
                        "ip": ip,
                        "status_code": response.status_code,
                        "server": response.headers.get("Server", "Unknown")
                    }
            except Exception:
                pass
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            list(executor.map(check_subdomain, self.subdomains))
        
        return results
    
    def _check_subdomain_takeover(self, live_subdomains: Dict[str, Dict[str, Any]]) -> Dict[str, str]:
        """Check for potential subdomain takeover vulnerabilities.
        
        Args:
            live_subdomains: Dictionary of live subdomains with their information
            
        Returns:
            Dictionary mapping vulnerable subdomains to takeover details
        """
        takeover_results = {}
        
        # Common fingerprints for subdomain takeover
        takeover_fingerprints = {
            "AWS/S3": ["NoSuchBucket", "The specified bucket does not exist"],
            "GitHub": ["There isn't a GitHub Pages site here", "For root URLs (like http://example.com/) you must provide an index.html file"],
            "Heroku": ["No such app", "herokucdn.com/error-pages/no-such-app.html"],
            "Shopify": ["Sorry, this shop is currently unavailable"],
            "Fastly": ["Fastly error: unknown domain"],
            "Pantheon": ["The gods are wise", "404 error unknown site!"],
            "Tumblr": ["Whatever you were looking for doesn't currently exist at this address"],
            "WordPress": ["Do you want to register *.wordpress.com?"],
        }
        
        for subdomain in live_subdomains:
            try:
                response = requests.get(f"http://{subdomain}", headers=self.headers, timeout=self.timeout)
                content = response.text
                
                for service, patterns in takeover_fingerprints.items():
                    for pattern in patterns:
                        if pattern in content:
                            takeover_results[subdomain] = f"Potential {service} takeover"
                            break
            except Exception:
                pass
        
        return takeover_results
    
    def discover_api_endpoints(self) -> List[Dict[str, Any]]:
        """Discover API endpoints from robots.txt, sitemap.xml, and JS files.
        
        Returns:
            List of API endpoint information dictionaries
        """
        result = []
        
        # Check robots.txt
        self._check_robots_txt()
        
        # Check sitemap.xml
        self._check_sitemap_xml()
        
        # Find and analyze JS files
        js_files = self.find_js_files()
        self._extract_endpoints_from_js(js_files)
        
        # Format results
        for endpoint in self.api_endpoints:
            endpoint_data = {
                "url": endpoint,
                "method": "GET",  # Default assumption
                "parameters": []  # Would need deeper analysis to find parameters
            }
            result.append(endpoint_data)
        
        return result
    
    def _check_robots_txt(self) -> None:
        """Check robots.txt for API endpoints and paths."""
        try:
            response = requests.get(f"https://{self.root_domain}/robots.txt", headers=self.headers, timeout=self.timeout)
            if response.status_code == 200:
                lines = response.text.split('\n')
                for line in lines:
                    if line.lower().startswith("disallow:") or line.lower().startswith("allow:"):
                        path = line.split(':', 1)[1].strip()
                        if path:
                            # Look for API path patterns
                            if "/api/" in path or path.endswith("/api") or "v1/" in path or "v2/" in path:
                                full_url = f"https://{self.root_domain}{path}"
                                self.api_endpoints.add(full_url)
        except Exception as e:
            print(f"Error checking robots.txt: {e}")
    
    def _check_sitemap_xml(self) -> None:
        """Check sitemap.xml for API endpoints and paths."""
        try:
            response = requests.get(f"https://{self.root_domain}/sitemap.xml", headers=self.headers, timeout=self.timeout)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'lxml')
                urls = soup.find_all('loc')
                
                for url in urls:
                    url_text = url.text
                    # Look for API path patterns
                    if "/api/" in url_text or url_text.endswith("/api") or "v1/" in url_text or "v2/" in url_text:
                        self.api_endpoints.add(url_text)
        except Exception as e:
            print(f"Error checking sitemap.xml: {e}")
    
    def find_js_files(self) -> List[str]:
        """Find JavaScript files by crawling the website.
        
        Returns:
            List of JavaScript file URLs
        """
        js_files = []
        visited = set()
        to_visit = [f"https://{self.root_domain}"]
        
        while to_visit and len(js_files) < 100:  # Limit to 100 JS files
            url = to_visit.pop(0)
            if url in visited:
                continue
                
            visited.add(url)
            
            try:
                response = requests.get(url, headers=self.headers, timeout=self.timeout)
                if response.status_code != 200:
                    continue
                    
                # Find JS files
                soup = BeautifulSoup(response.content, 'html.parser')
                
                # Extract JS from script tags with src attribute
                for script in soup.find_all('script', src=True):
                    js_url = script['src']
                    
                    # Handle relative URLs
                    if js_url.startswith('//'):
                        js_url = f"https:{js_url}"
                    elif js_url.startswith('/'):
                        js_url = f"https://{self.root_domain}{js_url}"
                    elif not js_url.startswith(('http://', 'https://')):
                        js_url = f"{url.rstrip('/')}/{js_url.lstrip('/')}"
                    
                    if js_url.endswith('.js') and js_url not in self.js_files:
                        self.js_files.add(js_url)
                        js_files.append(js_url)
                
                # Find more pages to crawl
                for a_tag in soup.find_all('a', href=True):
                    href = a_tag['href']
                    
                    # Handle relative URLs
                    if href.startswith('//'):
                        href = f"https:{href}"
                    elif href.startswith('/'):
                        href = f"https://{self.root_domain}{href}"
                    elif not href.startswith(('http://', 'https://')):
                        href = f"{url.rstrip('/')}/{href.lstrip('/')}"
                    
                    # Only visit URLs on the same domain
                    extract = tldextract.extract(href)
                    href_domain = f"{extract.domain}.{extract.suffix}"
                    
                    if href_domain == self.root_domain and href not in visited and href not in to_visit:
                        to_visit.append(href)
            except Exception:
                pass
        
        return js_files
    
    def _extract_endpoints_from_js(self, js_files: List[str]) -> None:
        """Extract API endpoints from JavaScript files.
        
        Args:
            js_files: List of JavaScript file URLs
        """
        # Common patterns for API endpoints in JS files
        api_patterns = [
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](https?://[^"\']+/api/[^"\']+)["\']',
            r'["\']([^"\']+\.(json|xml))["\']',
            r'url\s*:\s*["\'](/[^"\']+)["\']',
            r'url\s*:\s*["\'](https?://[^"\']+)["\']'
        ]
        
        for js_url in js_files:
            try:
                response = requests.get(js_url, headers=self.headers, timeout=self.timeout)
                if response.status_code != 200:
                    continue
                
                js_content = response.text
                
                for pattern in api_patterns:
                    matches = re.findall(pattern, js_content)
                    for match in matches:
                        if isinstance(match, tuple):
                            match = match[0]
                        
                        # Handle relative URLs
                        if match.startswith('//'):
                            endpoint = f"https:{match}"
                        elif match.startswith('/'):
                            endpoint = f"https://{self.root_domain}{match}"
                        elif not match.startswith(('http://', 'https://')):
                            # This may be a path fragment, but let's ignore it as it's hard to resolve
                            continue
                        else:
                            endpoint = match
                        
                        self.api_endpoints.add(endpoint)
            except Exception:
                pass
    
    def scan_js_files_for_secrets(self, js_files: List[str]) -> List[Dict[str, Any]]:
        """Scan JavaScript files for secrets using regex patterns.
        
        Args:
            js_files: List of JavaScript file URLs
            
        Returns:
            List of secret information dictionaries
        """
        result = []
        
        # Regex patterns for common API keys and secrets
        secret_patterns = {
            "AWS Key": r"AKIA[0-9A-Z]{16}",
            "Google API": r"AIza[0-9A-Za-z\\-_]{35}",
            "GitHub Token": r"github[_\s]*(access)?[_\s]*token[_\s]*[=:][_\s]*[\'\"][0-9a-zA-Z]{35,40}[\'\"]",
            "Firebase URL": r"https?://[^/]*.firebaseio.com",
            "API Key Generic": r"['\"]?api[_\s]?key['\"]?[_\s]?[=:][_\s]?['\"]?[a-zA-Z0-9_\-]{10,}['\"]?",
            "Private Key": r"-----BEGIN PRIVATE KEY-----[^-]+-----END PRIVATE KEY-----",
            "Password Field": r"password['\"]?[_\s]?[=:][_\s]?['\"]?[a-zA-Z0-9_\-!@#$%^&*]{6,}['\"]?",
            "JWT Token": r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"
        }
        
        for js_url in js_files:
            try:
                response = requests.get(js_url, headers=self.headers, timeout=self.timeout)
                if response.status_code != 200:
                    continue
                
                js_content = response.text
                
                for key_type, pattern in secret_patterns.items():
                    matches = re.findall(pattern, js_content)
                    for match in matches:
                        result.append({
                            "type": key_type,
                            "value": match,
                            "file": js_url,
                            "line_number": self._find_line_number(js_content, match)
                        })
            except Exception:
                pass
        
        return result
    
    def _find_line_number(self, content: str, match: str) -> int:
        """Find line number of a matched string in content.
        
        Args:
            content: File content as string
            match: String to find
            
        Returns:
            Line number (1-based) or 0 if not found
        """
        lines = content.split('\n')
        for i, line in enumerate(lines, 1):
            if match in line:
                return i
        return 0
    
    def google_dork_search(self) -> List[Dict[str, Any]]:
        """Perform Google dork searches for the target domain.
        
        Returns:
            List of dork search result dictionaries
        """
        result = []
        
        # Get Google dorks from config
        dorks = get_google_dorks()
        if not dorks:
            return result
        
        # Disclaimer: Direct Google searching may get you blocked
        # This is a simplified implementation - in a real tool, consider
        # using a proper API or service instead of direct scraping
        
        # For demonstration purposes, we'll just return the dork queries that would be used
        for dork in dorks:
            formatted_dork = dork.replace("{domain}", self.root_domain)
            result.append({
                "dork": formatted_dork,
                "description": "Google search dork",
                "example_url": f"https://www.google.com/search?q={formatted_dork.replace(' ', '+')}"
            })
        
        return result
    
    def github_dork_search(self) -> List[Dict[str, Any]]:
        """Perform GitHub dork searches for the target domain.
        
        Returns:
            List of dork search result dictionaries
        """
        result = []
        
        # Get GitHub dorks from config
        dorks = get_github_dorks()
        if not dorks:
            return result
        
        # Disclaimer: Direct GitHub searching may get you blocked
        # This is a simplified implementation - in a real tool, consider
        # using the GitHub API with authentication
        
        # For demonstration purposes, we'll just return the dork queries that would be used
        for dork in dorks:
            formatted_dork = dork.replace("{domain}", self.root_domain)
            result.append({
                "dork": formatted_dork,
                "description": "GitHub search dork",
                "example_url": f"https://github.com/search?q={formatted_dork.replace(' ', '+')}&type=code"
            })
        
        return result 