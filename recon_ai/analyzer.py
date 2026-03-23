from dataclasses import dataclass, field

from core.llm_client import LLMClient
from .parser import ScanData, Host


# Ports that are inherently high-risk when open
HIGH_RISK_PORTS = {
    21: "FTP — often allows anonymous access or cleartext credentials",
    23: "Telnet — cleartext protocol, highly insecure",
    25: "SMTP — can be abused for email relay",
    445: "SMB — common target for ransomware and lateral movement",
    3389: "RDP — brute force target, frequent exploit vector",
    5900: "VNC — often weak authentication",
    6379: "Redis — commonly exposed without authentication",
    27017: "MongoDB — frequently exposed without auth",
}

MEDIUM_RISK_PORTS = {
    22: "SSH — secure but brute-forceable",
    80: "HTTP — check for web vulnerabilities",
    443: "HTTPS — check for TLS misconfigurations",
    3306: "MySQL — should not be publicly exposed",
    5432: "PostgreSQL — should not be publicly exposed",
    8080: "HTTP Proxy — often misconfigured",
    8443: "HTTPS Alt — check for web vulnerabilities",
}


@dataclass
class Finding:
    port: int
    service: str
    risk_level: str  # critical, high, medium, low, info
    description: str
    recommendation: str


@dataclass
class HostAnalysis:
    ip: str
    hostname: str
    risk_score: int  # 0-100
    findings: list[Finding] = field(default_factory=list)
    llm_analysis: str = ""


def analyze_scan(client: LLMClient, scan_data: ScanData) -> list[HostAnalysis]:
    results = []
    for host in scan_data.hosts:
        if host.state != "up":
            continue
        analysis = _analyze_host(client, host)
        results.append(analysis)
    return results


def _analyze_host(client: LLMClient, host: Host) -> HostAnalysis:
    # Heuristic findings
    findings = []
    risk_score = 0

    open_ports = [p for p in host.ports if p.state == "open"]

    for port in open_ports:
        if port.number in HIGH_RISK_PORTS:
            findings.append(Finding(
                port=port.number,
                service=port.service,
                risk_level="high",
                description=HIGH_RISK_PORTS[port.number],
                recommendation=f"Consider closing port {port.number} or restricting access via firewall.",
            ))
            risk_score += 20
        elif port.number in MEDIUM_RISK_PORTS:
            findings.append(Finding(
                port=port.number,
                service=port.service,
                risk_level="medium",
                description=MEDIUM_RISK_PORTS[port.number],
                recommendation=f"Ensure port {port.number} is properly configured and access-controlled.",
            ))
            risk_score += 10

    # LLM-based deep analysis
    scan_summary = _format_host_for_llm(host)
    llm_analysis = _llm_analyze(client, scan_summary)

    risk_score = min(100, risk_score)

    return HostAnalysis(
        ip=host.ip,
        hostname=host.hostname,
        risk_score=risk_score,
        findings=findings,
        llm_analysis=llm_analysis,
    )


def _format_host_for_llm(host: Host) -> str:
    lines = [f"Host: {host.ip} ({host.hostname or 'no hostname'})"]
    if host.os:
        lines.append(f"OS: {host.os}")
    lines.append("Open ports:")
    for p in host.ports:
        if p.state == "open":
            line = f"  {p.number}/{p.protocol} — {p.service}"
            if p.version:
                line += f" ({p.version})"
            lines.append(line)
            for script in p.scripts:
                lines.append(f"    Script: {script}")
    return "\n".join(lines)


def _llm_analyze(client: LLMClient, scan_summary: str) -> str:
    prompt = f"""Analyze this network scan result from a security perspective.
For each open port and service, identify:
1. Known vulnerabilities or misconfigurations for this service/version
2. Potential attack vectors
3. Risk level (critical/high/medium/low)
4. Specific remediation recommendations

Scan data:
{scan_summary}

Provide a concise security assessment."""

    return client.generate(
        prompt,
        system_prompt=(
            "You are a network security analyst performing a vulnerability assessment. "
            "Focus on actionable findings. Reference CVEs when applicable. "
            "Assume this is an authorized penetration test in a controlled environment."
        ),
        temperature=0.3,
    )
