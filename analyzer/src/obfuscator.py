"""Data obfuscation module for privacy-preserving analysis."""

import hashlib
import re
from typing import Any, Dict, Optional

from .config import ObfuscationLevel, settings


class Obfuscator:
    """Obfuscates sensitive data based on configured level."""
    
    # Patterns for sensitive data detection
    PATTERNS = {
        # IP addresses
        "ipv4": re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
        "ipv6": re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'),
        
        # Kubernetes resources
        "namespace": re.compile(r'namespace["\s:=]+([a-z0-9-]+)', re.IGNORECASE),
        "pod_name": re.compile(r'pod["\s:=]+([a-z0-9-]+)', re.IGNORECASE),
        "container_name": re.compile(r'container["\s:=]+([a-z0-9-]+)', re.IGNORECASE),
        "service_account": re.compile(r'serviceAccount["\s:=]+([a-z0-9-]+)', re.IGNORECASE),
        
        # Secrets and tokens
        "bearer_token": re.compile(r'Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+'),
        "base64_secret": re.compile(r'(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'),
        "api_key": re.compile(r'(?:api[_-]?key|apikey|token|secret)["\s:=]+([A-Za-z0-9\-_]+)', re.IGNORECASE),
        
        # User information
        "email": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        "username": re.compile(r'(?:user|username)["\s:=]+([a-zA-Z0-9_-]+)', re.IGNORECASE),
        
        # Paths and URLs
        "file_path": re.compile(r'(?:/[a-zA-Z0-9_.-]+)+'),
        "url": re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+'),
        
        # AWS/Cloud specific
        "aws_account": re.compile(r'\b\d{12}\b'),
        "aws_arn": re.compile(r'arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[a-zA-Z0-9/_-]+'),
    }
    
    # Fields that should always be preserved for analysis
    PRESERVE_FIELDS = {
        "rule", "priority", "output", "time", "source",
        "output_fields.evt.type", "output_fields.syscall.type",
        "output_fields.ka.verb", "output_fields.ka.target.resource",
    }
    
    def __init__(self, level: Optional[ObfuscationLevel] = None):
        """Initialize obfuscator with specified level."""
        self.level = level or settings.obfuscation_level
        self._hash_salt = self._generate_salt()
    
    def _generate_salt(self) -> str:
        """Generate a consistent salt for hashing."""
        # In production, this should be a persistent secret
        return "sib-k8s-obfuscator-salt"
    
    def _hash_value(self, value: str, prefix: str = "") -> str:
        """Create a consistent hash for a value."""
        hash_input = f"{self._hash_salt}:{value}"
        hash_value = hashlib.sha256(hash_input.encode()).hexdigest()[:12]
        return f"{prefix}{hash_value}"
    
    def _obfuscate_minimal(self, text: str) -> str:
        """Minimal obfuscation - only secrets and tokens."""
        # Remove bearer tokens
        text = self.PATTERNS["bearer_token"].sub("<BEARER_TOKEN>", text)
        
        # Remove API keys
        text = self.PATTERNS["api_key"].sub(
            lambda m: m.group(0).split('=')[0] + '=<REDACTED>' if '=' in m.group(0) 
            else m.group(0).split(':')[0] + ':<REDACTED>',
            text
        )
        
        return text
    
    def _obfuscate_standard(self, text: str) -> str:
        """Standard obfuscation - secrets, IPs, and identifiable info."""
        text = self._obfuscate_minimal(text)
        
        # Hash IP addresses
        text = self.PATTERNS["ipv4"].sub(
            lambda m: self._hash_value(m.group(0), "ip-"), text
        )
        text = self.PATTERNS["ipv6"].sub(
            lambda m: self._hash_value(m.group(0), "ip6-"), text
        )
        
        # Hash emails
        text = self.PATTERNS["email"].sub(
            lambda m: self._hash_value(m.group(0), "email-") + "@redacted.local", text
        )
        
        # Hash AWS ARNs but preserve structure
        def obfuscate_arn(match):
            arn = match.group(0)
            parts = arn.split(":")
            if len(parts) >= 6:
                parts[4] = self._hash_value(parts[4], "")[:12]  # Account ID
                parts[5] = self._hash_value(parts[5], "res-")  # Resource
            return ":".join(parts)
        
        text = self.PATTERNS["aws_arn"].sub(obfuscate_arn, text)
        
        return text
    
    def _obfuscate_paranoid(self, text: str) -> str:
        """Paranoid obfuscation - all identifiable information."""
        text = self._obfuscate_standard(text)
        
        # Hash namespaces (preserve system namespaces)
        def obfuscate_namespace(match):
            ns = match.group(1)
            if ns in ("kube-system", "kube-public", "default", "kube-node-lease"):
                return match.group(0)
            return match.group(0).replace(ns, self._hash_value(ns, "ns-"))
        
        text = self.PATTERNS["namespace"].sub(obfuscate_namespace, text)
        
        # Hash pod names
        text = self.PATTERNS["pod_name"].sub(
            lambda m: m.group(0).replace(m.group(1), self._hash_value(m.group(1), "pod-")), text
        )
        
        # Hash container names
        text = self.PATTERNS["container_name"].sub(
            lambda m: m.group(0).replace(m.group(1), self._hash_value(m.group(1), "ctr-")), text
        )
        
        # Hash usernames
        text = self.PATTERNS["username"].sub(
            lambda m: m.group(0).replace(m.group(1), self._hash_value(m.group(1), "user-")), text
        )
        
        # Obfuscate URLs (preserve protocol and structure)
        def obfuscate_url(match):
            url = match.group(0)
            if "://" in url:
                proto, rest = url.split("://", 1)
                return f"{proto}://{self._hash_value(rest, 'host-')}.local"
            return url
        
        text = self.PATTERNS["url"].sub(obfuscate_url, text)
        
        return text
    
    def obfuscate_text(self, text: str) -> str:
        """Obfuscate text based on configured level."""
        if self.level == ObfuscationLevel.MINIMAL:
            return self._obfuscate_minimal(text)
        elif self.level == ObfuscationLevel.STANDARD:
            return self._obfuscate_standard(text)
        elif self.level == ObfuscationLevel.PARANOID:
            return self._obfuscate_paranoid(text)
        return text
    
    def obfuscate_dict(self, data: Dict[str, Any], path: str = "") -> Dict[str, Any]:
        """Recursively obfuscate dictionary values."""
        result = {}
        
        for key, value in data.items():
            current_path = f"{path}.{key}" if path else key
            
            # Check if this field should be preserved
            if current_path in self.PRESERVE_FIELDS:
                result[key] = value
                continue
            
            if isinstance(value, str):
                result[key] = self.obfuscate_text(value)
            elif isinstance(value, dict):
                result[key] = self.obfuscate_dict(value, current_path)
            elif isinstance(value, list):
                result[key] = [
                    self.obfuscate_dict(item, current_path) if isinstance(item, dict)
                    else self.obfuscate_text(item) if isinstance(item, str)
                    else item
                    for item in value
                ]
            else:
                result[key] = value
        
        return result
    
    def obfuscate_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Obfuscate a Falco alert while preserving analysis-critical fields."""
        return self.obfuscate_dict(alert)


# Global obfuscator instance
obfuscator = Obfuscator()
