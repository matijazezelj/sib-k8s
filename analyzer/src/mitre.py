"""MITRE ATT&CK mapping for Kubernetes security events."""

from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class MITRETechnique:
    """Represents a MITRE ATT&CK technique."""
    id: str
    name: str
    tactic: str
    description: str
    url: str


# MITRE ATT&CK for Containers/Kubernetes mapping
MITRE_TECHNIQUES: Dict[str, MITRETechnique] = {
    # Initial Access
    "T1190": MITRETechnique(
        id="T1190",
        name="Exploit Public-Facing Application",
        tactic="Initial Access",
        description="Adversaries may attempt to exploit vulnerabilities in internet-facing applications.",
        url="https://attack.mitre.org/techniques/T1190/"
    ),
    "T1133": MITRETechnique(
        id="T1133",
        name="External Remote Services",
        tactic="Initial Access",
        description="Adversaries may leverage external-facing remote services to initially access a network.",
        url="https://attack.mitre.org/techniques/T1133/"
    ),
    
    # Execution
    "T1059": MITRETechnique(
        id="T1059",
        name="Command and Scripting Interpreter",
        tactic="Execution",
        description="Adversaries may abuse command and script interpreters to execute commands.",
        url="https://attack.mitre.org/techniques/T1059/"
    ),
    "T1609": MITRETechnique(
        id="T1609",
        name="Container Administration Command",
        tactic="Execution",
        description="Adversaries may abuse container administration commands to execute commands within a container.",
        url="https://attack.mitre.org/techniques/T1609/"
    ),
    "T1610": MITRETechnique(
        id="T1610",
        name="Deploy Container",
        tactic="Execution",
        description="Adversaries may deploy new containers to execute malicious code.",
        url="https://attack.mitre.org/techniques/T1610/"
    ),
    
    # Persistence
    "T1053": MITRETechnique(
        id="T1053",
        name="Scheduled Task/Job",
        tactic="Persistence",
        description="Adversaries may abuse task scheduling to execute malicious code at system startup.",
        url="https://attack.mitre.org/techniques/T1053/"
    ),
    "T1078": MITRETechnique(
        id="T1078",
        name="Valid Accounts",
        tactic="Persistence",
        description="Adversaries may obtain and abuse credentials of existing accounts.",
        url="https://attack.mitre.org/techniques/T1078/"
    ),
    
    # Privilege Escalation
    "T1611": MITRETechnique(
        id="T1611",
        name="Escape to Host",
        tactic="Privilege Escalation",
        description="Adversaries may break out of a container to gain access to the underlying host.",
        url="https://attack.mitre.org/techniques/T1611/"
    ),
    "T1548": MITRETechnique(
        id="T1548",
        name="Abuse Elevation Control Mechanism",
        tactic="Privilege Escalation",
        description="Adversaries may circumvent mechanisms designed to control elevated privileges.",
        url="https://attack.mitre.org/techniques/T1548/"
    ),
    
    # Defense Evasion
    "T1070": MITRETechnique(
        id="T1070",
        name="Indicator Removal",
        tactic="Defense Evasion",
        description="Adversaries may delete or modify artifacts generated within systems.",
        url="https://attack.mitre.org/techniques/T1070/"
    ),
    "T1036": MITRETechnique(
        id="T1036",
        name="Masquerading",
        tactic="Defense Evasion",
        description="Adversaries may attempt to manipulate features of artifacts to make them appear legitimate.",
        url="https://attack.mitre.org/techniques/T1036/"
    ),
    "T1612": MITRETechnique(
        id="T1612",
        name="Build Image on Host",
        tactic="Defense Evasion",
        description="Adversaries may build container images directly on a host to bypass defenses.",
        url="https://attack.mitre.org/techniques/T1612/"
    ),
    
    # Credential Access
    "T1552": MITRETechnique(
        id="T1552",
        name="Unsecured Credentials",
        tactic="Credential Access",
        description="Adversaries may search compromised systems for unsecured credentials.",
        url="https://attack.mitre.org/techniques/T1552/"
    ),
    "T1528": MITRETechnique(
        id="T1528",
        name="Steal Application Access Token",
        tactic="Credential Access",
        description="Adversaries can steal application access tokens as a means of acquiring credentials.",
        url="https://attack.mitre.org/techniques/T1528/"
    ),
    
    # Discovery
    "T1613": MITRETechnique(
        id="T1613",
        name="Container and Resource Discovery",
        tactic="Discovery",
        description="Adversaries may attempt to discover containers and resources available in a container environment.",
        url="https://attack.mitre.org/techniques/T1613/"
    ),
    "T1046": MITRETechnique(
        id="T1046",
        name="Network Service Discovery",
        tactic="Discovery",
        description="Adversaries may attempt to get a listing of services running on remote hosts.",
        url="https://attack.mitre.org/techniques/T1046/"
    ),
    
    # Lateral Movement
    "T1021": MITRETechnique(
        id="T1021",
        name="Remote Services",
        tactic="Lateral Movement",
        description="Adversaries may use remote services to move within an environment.",
        url="https://attack.mitre.org/techniques/T1021/"
    ),
    
    # Collection
    "T1560": MITRETechnique(
        id="T1560",
        name="Archive Collected Data",
        tactic="Collection",
        description="Adversaries may compress or encrypt data before exfiltration.",
        url="https://attack.mitre.org/techniques/T1560/"
    ),
    
    # Impact
    "T1485": MITRETechnique(
        id="T1485",
        name="Data Destruction",
        tactic="Impact",
        description="Adversaries may destroy data and files to disrupt availability.",
        url="https://attack.mitre.org/techniques/T1485/"
    ),
    "T1496": MITRETechnique(
        id="T1496",
        name="Resource Hijacking",
        tactic="Impact",
        description="Adversaries may leverage compute resources for cryptocurrency mining.",
        url="https://attack.mitre.org/techniques/T1496/"
    ),
}

# Falco rule to MITRE technique mapping
RULE_TO_MITRE: Dict[str, List[str]] = {
    # Execution
    "Terminal shell in container": ["T1059", "T1609"],
    "Attach/Exec Pod": ["T1609"],
    "Run shell untrusted": ["T1059"],
    "Contact K8S API Server From Container": ["T1613"],
    
    # Privilege Escalation
    "Launch Privileged Container": ["T1611"],
    "Launch Sensitive Mount Container": ["T1611"],
    "Container Drift Detected": ["T1610"],
    "Modify binary dirs": ["T1548"],
    "Set Setuid or Setgid bit": ["T1548"],
    
    # Defense Evasion
    "Clear Log Activities": ["T1070"],
    "Remove Bulk Data from Disk": ["T1070", "T1485"],
    "Tampering with History": ["T1070"],
    
    # Credential Access
    "Read sensitive file untrusted": ["T1552"],
    "Find AWS Credentials": ["T1552"],
    "Read sensitive file trusted after startup": ["T1552"],
    "Search Private Keys or Passwords": ["T1552"],
    "Read Shell Configuration File": ["T1552"],
    
    # Discovery
    "Netcat Remote Code Execution": ["T1046", "T1059"],
    "Network Connection to Metadata Service": ["T1552", "T1613"],
    "Contact cloud metadata service from container": ["T1552", "T1613"],
    
    # Lateral Movement
    "Outbound Connection to C2 Servers": ["T1021"],
    
    # Impact
    "Drop and execute new binary": ["T1059", "T1610"],
    "Write below etc": ["T1485"],
    "Packet socket created": ["T1046"],
    
    # K8s Audit specific
    "K8s Audit": ["T1078"],
    "Create Privileged Pod": ["T1611"],
    "Create HostNetwork Pod": ["T1021"],
    "Pod Created in Kube Namespace": ["T1610"],
    "Create NodePort Service": ["T1133"],
    "Attach to cluster-admin Role": ["T1078"],
    "ClusterRole With Pod Exec Created": ["T1609"],
    "ClusterRole With Wildcard": ["T1078"],
    "Secret Access Attempt": ["T1552"],
    "Configmap with Private Credentials": ["T1552"],
}


def get_mitre_techniques(rule_name: str) -> List[MITRETechnique]:
    """Get MITRE techniques associated with a Falco rule."""
    techniques = []
    
    # Direct mapping
    technique_ids = RULE_TO_MITRE.get(rule_name, [])
    
    # Fuzzy matching for partial rule names
    if not technique_ids:
        for pattern, ids in RULE_TO_MITRE.items():
            if pattern.lower() in rule_name.lower() or rule_name.lower() in pattern.lower():
                technique_ids.extend(ids)
                break
    
    for tech_id in set(technique_ids):
        if tech_id in MITRE_TECHNIQUES:
            techniques.append(MITRE_TECHNIQUES[tech_id])
    
    return techniques


def format_mitre_info(techniques: List[MITRETechnique]) -> str:
    """Format MITRE techniques for display."""
    if not techniques:
        return "No MITRE ATT&CK mapping available"
    
    lines = ["### MITRE ATT&CK Mapping\n"]
    for tech in techniques:
        lines.append(f"- **{tech.id}**: {tech.name}")
        lines.append(f"  - Tactic: {tech.tactic}")
        lines.append(f"  - [Reference]({tech.url})")
    
    return "\n".join(lines)
