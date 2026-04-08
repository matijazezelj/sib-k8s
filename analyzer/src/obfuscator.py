"""Data obfuscation module for privacy-preserving analysis."""

import hashlib
import re
from typing import Any, Dict, Optional

from .config import ObfuscationLevel, settings


class Obfuscator:
    """Obfuscates sensitive data based on configured level."""

    # Compiled patterns for network identifiers and Kubernetes resources
    PATTERNS = {
        # IP addresses
        "ipv4": re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
        "ipv6": re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'),

        # Kubernetes resources
        "namespace": re.compile(r'namespace["\s:=]+([a-z0-9-]+)', re.IGNORECASE),
        "pod_name": re.compile(r'pod["\s:=]+([a-z0-9-]+)', re.IGNORECASE),
        "container_name": re.compile(r'container["\s:=]+([a-z0-9-]+)', re.IGNORECASE),
        "service_account": re.compile(r'serviceAccount["\s:=]+([a-z0-9-]+)', re.IGNORECASE),

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

    # Secret patterns ordered from most to least specific (avoids false-positive overlap).
    # Based on TruffleHog detectors: https://github.com/trufflesecurity/trufflehog/tree/main/pkg/detectors
    SECRET_PATTERNS = [
        # AWS — specific prefixes first
        ("aws_access_key",     r'\b(A3T[A-Z0-9]|AKIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|APKA|AROA|ASCA|ASIA)[A-Z0-9]{16}\b', "AWS-KEY"),
        ("aws_session_token",  r'\b(FwoGZXIvYXdzE|IQoJb3JpZ2lu)[A-Za-z0-9/+=]+\b', "AWS-SESSION"),
        ("aws_mws_key",        r'\bamzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', "AWS-MWS"),
        # GCP
        ("gcp_service_account", r'\b[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com\b', "GCP-SERVICE-ACCOUNT"),
        ("google_api_key",     r'\bAIza[0-9A-Za-z\-_]{35}\b', "GOOGLE-API"),
        ("google_oauth_id",    r'\b[0-9]+-[A-Za-z0-9_]{32}\.apps\.googleusercontent\.com\b', "GOOGLE-OAUTH"),
        ("google_oauth_secret", r'\bGOCspx-[A-Za-z0-9\-_]{28}\b', "GOOGLE-SECRET"),
        # Azure
        ("azure_storage_key",  r'\b[A-Za-z0-9+/]{86}==\b', "AZURE-STORAGE"),
        ("azure_sas_token",    r'\bsig=[A-Za-z0-9%]+&se=[0-9]+&[A-Za-z0-9&=%]+\b', "AZURE-SAS"),
        # GitHub
        ("github_fine_grained", r'\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b', "GITHUB-TOKEN"),
        ("github_pat",         r'\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b', "GITHUB-TOKEN"),
        # GitLab
        ("gitlab_pat",         r'\bglpat-[A-Za-z0-9\-_]{20,}\b', "GITLAB-TOKEN"),
        ("gitlab_pipeline",    r'\bglptt-[A-Za-z0-9]{40}\b', "GITLAB-PIPELINE"),
        ("gitlab_runner",      r'\bGR1348941[A-Za-z0-9\-_]{20,}\b', "GITLAB-RUNNER"),
        # Slack
        ("slack_webhook",      r'https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}', "SLACK-WEBHOOK"),
        ("slack_bot_token",    r'\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}\b', "SLACK-BOT"),
        ("slack_user_token",   r'\bxoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}\b', "SLACK-USER"),
        ("slack_app_token",    r'\bxapp-[0-9]-[A-Z0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{64}\b', "SLACK-APP"),
        # Discord
        ("discord_webhook",    r'https://discord(app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+', "DISCORD-WEBHOOK"),
        ("discord_bot_token",  r'\b(MTA|MTE|MTI|OT|Nj|Nz|OD)[A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}\b', "DISCORD-BOT"),
        # Stripe
        ("stripe_secret_key",  r'\b(sk|rk)_(test|live)_[A-Za-z0-9]{24,}\b', "STRIPE-SECRET"),
        ("stripe_pub_key",     r'\bpk_(test|live)_[A-Za-z0-9]{24,}\b', "STRIPE-KEY"),
        # Twilio
        ("twilio_api_key",     r'\bSK[a-f0-9]{32}\b', "TWILIO-KEY"),
        ("twilio_account_sid", r'\bAC[a-f0-9]{32}\b', "TWILIO-SID"),
        # Package managers
        ("npm_token",          r'\bnpm_[A-Za-z0-9]{36}\b', "NPM-TOKEN"),
        ("pypi_token",         r'\bpypi-[A-Za-z0-9\-_]{50,}\b', "PYPI-TOKEN"),
        # DigitalOcean
        ("digitalocean_pat",   r'\bdop_v1_[a-f0-9]{64}\b', "DO-TOKEN"),
        # Sendgrid
        ("sendgrid_api_key",   r'\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}\b', "SENDGRID-KEY"),
        # Sentry
        ("sentry_dsn",         r'https://[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io/[0-9]+', "SENTRY-DSN"),
        # Database URIs (contain embedded credentials)
        ("postgres_uri",       r'postgres(ql)?://[^:]+:[^@]+@[^/]+/\w+', "DB-POSTGRES"),
        ("mysql_uri",          r'mysql://[^:]+:[^@]+@[^/]+/\w+', "DB-MYSQL"),
        ("mongodb_uri",        r'mongodb(\+srv)?://[^:]+:[^@]+@[^/]+', "DB-MONGODB"),
        ("redis_uri",          r'redis://[^:]+:[^@]+@[^/]+', "DB-REDIS"),
        # Auth tokens
        ("jwt",                r'\beyJ[A-Za-z0-9-_]*\.eyJ[A-Za-z0-9-_]*\.[A-Za-z0-9-_.+/]*\b', "JWT"),
        ("bearer_token",       r'\bBearer\s+[A-Za-z0-9\-_\.]+\b', "BEARER-TOKEN"),
        ("basic_auth",         r'\bBasic\s+[A-Za-z0-9+/]+=*\b', "BASIC-AUTH"),
        # Private keys
        ("private_key_content", r'-----BEGIN[^-]+-----[A-Za-z0-9+/=\s]+-----END[^-]+-----', "PRIVATE-KEY"),
        ("private_key",        r'-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----', "PRIVATE-KEY"),
        # Password fields
        ("password_field",     r'(password|passwd|pwd|secret_key|auth_key|private_key|encryption_key)[=:]\s*["\']?[^\s"\']{8,}["\']?', "PASSWORD"),
        # Telegram
        ("telegram_bot_token", r'\b[0-9]{8,10}:[A-Za-z0-9_-]{35}\b', "TELEGRAM-BOT"),
    ]
    
    # Fields that should always be preserved for analysis (structural metadata, not content)
    PRESERVE_FIELDS = {
        "rule", "priority", "time", "source",
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

    def _obfuscate_secrets(self, text: str) -> str:
        """Redact secrets and credentials. Always applied regardless of level."""
        for _name, pattern, label in self.SECRET_PATTERNS:
            try:
                text = re.sub(pattern, f"[REDACTED-{label}]", text, flags=re.IGNORECASE)
            except re.error:
                pass
        return text

    def _obfuscate_minimal(self, text: str) -> str:
        """Minimal obfuscation - only secrets and tokens."""
        return self._obfuscate_secrets(text)
    
    def _obfuscate_standard(self, text: str) -> str:
        """Standard obfuscation - secrets, IPs, and identifiable info."""
        text = self._obfuscate_secrets(text)
        
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
