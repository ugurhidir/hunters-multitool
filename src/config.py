#!/usr/bin/env python3

import os
import json
from pathlib import Path
from typing import Dict, Any, Optional

# Default configuration path
DEFAULT_CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".hunters_multitool", "config.json")

# Default configuration
DEFAULT_CONFIG = {
    "api_keys": {
        "shodan": "",
        "virustotal": "",
        "securitytrails": ""
    },
    "settings": {
        "threads": 5,
        "timeout": 10,
        "user_agent": "Hunters-Multitool/0.1.0",
        "report_format": "html"
    },
    "google_dorks": [
        "site:{domain} ext:php",
        "site:{domain} intext:\"sql syntax near\"",
        "site:{domain} intext:\"error in your SQL syntax\"",
        "site:{domain} intitle:\"index of\"",
        "site:{domain} ext:log",
        "site:{domain} ext:sql | ext:txt | ext:conf | ext:cnf | ext:ini | ext:env | ext:zip | ext:tar | ext:db | ext:csv",
        "site:{domain} ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup"
    ],
    "github_dorks": [
        "\"api_key\" {domain}",
        "\"apikey\" {domain}",
        "\"password\" {domain}",
        "\"oauth\" {domain}",
        "\"auth\" {domain}",
        "\"FTP\" {domain}",
        "\"SMTP\" {domain}",
        "\"credential\" {domain}",
        "\"ssh\" {domain}"
    ]
}

def ensure_config_dir() -> None:
    """Ensure the configuration directory exists."""
    config_dir = os.path.dirname(DEFAULT_CONFIG_PATH)
    if not os.path.exists(config_dir):
        os.makedirs(config_dir)

def load_config() -> Dict[str, Any]:
    """Load configuration from file or create default if it doesn't exist."""
    ensure_config_dir()
    
    if not os.path.exists(DEFAULT_CONFIG_PATH):
        save_config(DEFAULT_CONFIG)
        return DEFAULT_CONFIG
    
    try:
        with open(DEFAULT_CONFIG_PATH, "r") as f:
            config = json.load(f)
        return config
    except Exception as e:
        print(f"Error loading configuration: {e}")
        return DEFAULT_CONFIG

def save_config(config: Dict[str, Any]) -> None:
    """Save configuration to file."""
    ensure_config_dir()
    
    try:
        with open(DEFAULT_CONFIG_PATH, "w") as f:
            json.dump(config, f, indent=4)
    except Exception as e:
        print(f"Error saving configuration: {e}")

def get_api_key(service: str) -> Optional[str]:
    """Get API key for a specific service."""
    config = load_config()
    return config.get("api_keys", {}).get(service)

def set_api_key(service: str, key: str) -> None:
    """Set API key for a specific service."""
    config = load_config()
    
    if "api_keys" not in config:
        config["api_keys"] = {}
    
    config["api_keys"][service] = key
    save_config(config)

def get_setting(setting: str) -> Any:
    """Get a specific setting value."""
    config = load_config()
    return config.get("settings", {}).get(setting)

def set_setting(setting: str, value: Any) -> None:
    """Set a specific setting value."""
    config = load_config()
    
    if "settings" not in config:
        config["settings"] = {}
    
    config["settings"][setting] = value
    save_config(config)

def get_google_dorks() -> list:
    """Get Google dork queries."""
    config = load_config()
    return config.get("google_dorks", [])

def get_github_dorks() -> list:
    """Get GitHub dork queries."""
    config = load_config()
    return config.get("github_dorks", []) 