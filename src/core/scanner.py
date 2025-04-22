#!/usr/bin/env python3

import re
import requests
import threading
import queue
import urllib.parse
from typing import List, Dict, Any, Set, Tuple
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from rich.progress import Progress

from src.config import get_setting

class Scanner:
    def __init__(self, target: str, threads: int = 3):
        """Initialize the Scanner module.
        
        Args:
            target: The target URL to scan
            threads: Number of threads to use for concurrent operations
        """
        self.target = target
        self.threads = threads
        self.user_agent = get_setting("user_agent") or "Hunters-Multitool/0.1.0"
        self.timeout = get_setting("timeout") or 10
        
        # Ensure target has protocol
        if not self.target.startswith(("http://", "https://")):
            self.target = "https://" + self.target
        
        self.headers = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
        }
        
        # Lists to store found vulnerabilities
        self.sql_vulns = []
        self.xss_vulns = []
        
        # List to store visited URLs
        self.visited_urls = set()
        
        # List to store found forms
        self.forms = []
    
    def scan_sql_injection(self) -> List[Dict[str, Any]]:
        """Scan for SQL Injection vulnerabilities.
        
        Returns:
            List of SQL Injection vulnerability dictionaries
        """
        # Crawl website to find forms
        self._crawl_website()
        
        # Process found forms for SQL injection
        for form_info in self.forms:
            self._test_form_for_sql_injection(form_info)
        
        return self.sql_vulns
    
    def scan_xss(self) -> List[Dict[str, Any]]:
        """Scan for XSS vulnerabilities.
        
        Returns:
            List of XSS vulnerability dictionaries
        """
        # Crawl website to find forms (if not already done)
        if not self.forms:
            self._crawl_website()
        
        # Process found forms for XSS
        for form_info in self.forms:
            self._test_form_for_xss(form_info)
        
        return self.xss_vulns
    
    def _crawl_website(self) -> None:
        """Crawl website to find URLs and forms."""
        to_visit = [self.target]
        
        while to_visit and len(self.visited_urls) < 50:  # Limit to 50 pages
            url = to_visit.pop(0)
            if url in self.visited_urls:
                continue
            
            self.visited_urls.add(url)
            
            try:
                response = requests.get(url, headers=self.headers, timeout=self.timeout)
                if response.status_code != 200:
                    continue
                
                # Extract forms
                self._extract_forms(url, response.text)
                
                # Find more links to crawl
                soup = BeautifulSoup(response.content, 'html.parser')
                for a_tag in soup.find_all('a', href=True):
                    href = a_tag['href']
                    
                    # Handle relative URLs
                    if href.startswith('//'):
                        href = "https:" + href
                    elif href.startswith('/'):
                        parsed_url = urllib.parse.urlparse(url)
                        base = f"{parsed_url.scheme}://{parsed_url.netloc}"
                        href = base + href
                    elif not href.startswith(('http://', 'https://')):
                        href = url.rstrip('/') + '/' + href.lstrip('/')
                    
                    # Only visit URLs on the same domain
                    if self._is_same_domain(url, href) and href not in self.visited_urls and href not in to_visit:
                        to_visit.append(href)
            except Exception:
                pass
    
    def _is_same_domain(self, url1: str, url2: str) -> bool:
        """Check if two URLs are on the same domain.
        
        Args:
            url1: First URL
            url2: Second URL
            
        Returns:
            True if same domain, False otherwise
        """
        try:
            domain1 = urllib.parse.urlparse(url1).netloc
            domain2 = urllib.parse.urlparse(url2).netloc
            return domain1 == domain2
        except Exception:
            return False
    
    def _extract_forms(self, url: str, html: str) -> None:
        """Extract forms from HTML.
        
        Args:
            url: URL of the page
            html: HTML content
        """
        soup = BeautifulSoup(html, 'html.parser')
        
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            
            # Handle relative URLs
            if action.startswith('//'):
                action = "https:" + action
            elif action.startswith('/'):
                parsed_url = urllib.parse.urlparse(url)
                base = f"{parsed_url.scheme}://{parsed_url.netloc}"
                action = base + action
            elif not action:
                action = url
            elif not action.startswith(('http://', 'https://')):
                action = url.rstrip('/') + '/' + action.lstrip('/')
            
            inputs = []
            for input_field in form.find_all(['input', 'textarea']):
                input_type = input_field.get('type', '')
                input_name = input_field.get('name', '')
                input_value = input_field.get('value', '')
                
                if input_name and input_type != 'submit' and input_type != 'hidden':
                    inputs.append({
                        "name": input_name,
                        "type": input_type,
                        "value": input_value
                    })
            
            if inputs:  # Only add forms with input fields
                self.forms.append({
                    "url": url,
                    "action": action,
                    "method": method,
                    "inputs": inputs
                })
    
    def _test_form_for_sql_injection(self, form_info: Dict[str, Any]) -> None:
        """Test a form for SQL Injection vulnerabilities.
        
        Args:
            form_info: Form information dictionary
        """
        # SQL injection payloads to test
        sql_payloads = [
            "' OR 1=1 --",
            "' OR '1'='1",
            "1' OR '1' = '1",
            "' OR 1 = 1 -- -",
            "\" OR 1=1 --",
            "admin' --",
            "' UNION SELECT 1,2,3 --",
            "' DROP TABLE users --",
            "1'; DROP TABLE users; --"
        ]
        
        # SQL error patterns to look for
        sql_errors = [
            "SQL syntax",
            "mysql_fetch_array",
            "mysql_fetch",
            "mysql_num_rows",
            "mysql_query",
            "mysql_result",
            "pg_query",
            "mysqli_fetch_array",
            "mysqli_",
            "sqlite_query",
            "ORA-",
            "Oracle error",
            "Microsoft SQL",
            "ODBC SQL",
            "Microsoft Access",
            "JDBC Driver",
            "MySQL server",
            "PostgreSQL",
            "SQL Server",
            "DB2",
            "database error",
            "syntax error",
            "Warning:"
        ]
        
        for payload in sql_payloads:
            # Prepare form data with payload
            data = {}
            for input_field in form_info["inputs"]:
                data[input_field["name"]] = payload
            
            try:
                # Send the request
                if form_info["method"] == "post":
                    response = requests.post(form_info["action"], headers=self.headers, data=data, timeout=self.timeout)
                else:
                    response = requests.get(form_info["action"], headers=self.headers, params=data, timeout=self.timeout)
                
                # Check for SQL errors in response
                for error in sql_errors:
                    if error.lower() in response.text.lower():
                        # Vulnerability found
                        self.sql_vulns.append({
                            "url": form_info["url"],
                            "form_action": form_info["action"],
                            "method": form_info["method"],
                            "payload": payload,
                            "error": error,
                            "inputs": form_info["inputs"],
                            "evidence": self._extract_evidence(response.text, error)
                        })
                        break
            except Exception:
                # Timeout or other error might also indicate vulnerability
                pass
    
    def _test_form_for_xss(self, form_info: Dict[str, Any]) -> None:
        """Test a form for XSS vulnerabilities.
        
        Args:
            form_info: Form information dictionary
        """
        # XSS payloads to test
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src='x' onerror='alert(\"XSS\")'>",
            "<svg onload='alert(\"XSS\")'>",
            "<body onload='alert(\"XSS\")'>",
            "<a href=\"javascript:alert('XSS')\">Click me</a>",
            "\"><script>alert('XSS')</script>",
            "\"><img src='x' onerror='alert(\"XSS\")'>"
        ]
        
        for payload in xss_payloads:
            # Prepare form data with payload
            data = {}
            for input_field in form_info["inputs"]:
                data[input_field["name"]] = payload
            
            try:
                # Send the request
                if form_info["method"] == "post":
                    response = requests.post(form_info["action"], headers=self.headers, data=data, timeout=self.timeout)
                else:
                    response = requests.get(form_info["action"], headers=self.headers, params=data, timeout=self.timeout)
                
                # Check if payload is reflected in response
                if payload in response.text:
                    # Vulnerability found
                    self.xss_vulns.append({
                        "url": form_info["url"],
                        "form_action": form_info["action"],
                        "method": form_info["method"],
                        "payload": payload,
                        "inputs": form_info["inputs"],
                        "evidence": self._extract_evidence(response.text, payload)
                    })
            except Exception:
                pass
    
    def _extract_evidence(self, text: str, pattern: str) -> str:
        """Extract evidence of vulnerability from response text.
        
        Args:
            text: Response text
            pattern: Pattern to search for
            
        Returns:
            Evidence string
        """
        try:
            # Find the pattern in text and extract some context
            index = text.lower().find(pattern.lower())
            if index == -1:
                return ""
            
            # Get some context around the pattern
            start = max(0, index - 50)
            end = min(len(text), index + len(pattern) + 50)
            
            return text[start:end].strip()
        except Exception:
            return ""
    
    def scan_all_vulnerabilities(self) -> Dict[str, List[Dict[str, Any]]]:
        """Scan for all supported vulnerabilities.
        
        Returns:
            Dictionary mapping vulnerability types to results
        """
        return {
            "sql_injection": self.scan_sql_injection(),
            "xss": self.scan_xss()
        } 