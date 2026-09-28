"""Deterministic enrichment: IOCs, a rule-based baseline score, and redaction.

The baseline runs before any model so every alert gets a sane verdict even when
no AI backend is reachable, and so the model's answer can be sanity-checked.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
DOMAIN = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|ru|cn|xyz|top|info|biz)\b", re.I)

# Tactics that usually mean an attacker is already inside
HIGH_IMPACT_TACTICS = {
    "credential access", "lateral movement", "exfiltration", "impact",
    "command and control", "privilege escalation", "defense evasion",
}
SUSPICIOUS_TOKENS = (
    "mimikatz", "sekurlsa", "lsass", "-enc ", "encodedcommand", "invoke-expression",
    "iex(", "downloadstring", "certutil -urlcache", "vssadmin delete", "bcdedit",
    "nc -e", "/dev/tcp/", "base64 -d", "chmod +x /tmp", "wget http", "curl http",
)
SENSITIVE_PATHS = ("/etc/passwd", "/etc/shadow", "/etc/sudoers", "authorized_keys", "\\system32\\")


def _is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved)


def extract_iocs(alert: dict[str, Any]) -> dict[str, list[str]]:
    blob = " ".join(
        str(alert.get(k, "")) for k in ("full_log", "command_line", "src_ip", "dst_ip", "file_path")
    )
    ips = sorted({ip for ip in IPV4.findall(blob) if _is_public(ip)})
    sha = set(SHA256.findall(blob))
    if alert.get("hashes", {}).get("sha256"):
        sha.add(alert["hashes"]["sha256"])
    md5 = {h for h in MD5.findall(blob) if not any(h in s for s in sha)}
    if alert.get("hashes", {}).get("md5"):
        md5.add(alert["hashes"]["md5"])
    return {
        "public_ips": ips,
        "sha256": sorted(sha),
        "md5": sorted(md5),
        "domains": sorted({d.lower() for d in DOMAIN.findall(blob)}),
    }


def baseline(alert: dict[str, Any]) -> dict[str, Any]:
    """Score 0-100 from Wazuh level, MITRE tactic, repetition and red-flag strings."""
    score = min(alert.get("rule_level", 0), 15) * 5  # level 15 -> 75
    reasons: list[str] = [f"Wazuh rule level {alert.get('rule_level', 0)}"]

    tactics = {t.lower() for t in alert.get("mitre_tactics", [])}
    hit = tactics & HIGH_IMPACT_TACTICS
    if hit:
        score += 15
        reasons.append("high-impact MITRE tactic: " + ", ".join(sorted(hit)))

    text = f"{alert.get('command_line', '')} {alert.get('full_log', '')} {alert.get('process', '')}".lower()
    tokens = [t.strip() for t in SUSPICIOUS_TOKENS if t in text]
    if tokens:
        score += 20
        reasons.append("suspicious strings: " + ", ".join(tokens[:5]))

    if any(p in alert.get("file_path", "").lower() for p in SENSITIVE_PATHS):
        score += 15
        reasons.append(f"sensitive file touched: {alert['file_path']}")

    if alert.get("firedtimes", 1) >= 10:
        score += 10
        reasons.append(f"rule fired {alert['firedtimes']} times")

    if _is_public(alert.get("src_ip", "")):
        score += 5
        reasons.append(f"external source {alert['src_ip']}")

    score = max(0, min(score, 100))
    return {"score": score, "severity": severity_for(score), "reasons": reasons}


def severity_for(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "info"


def redact(alert: dict[str, Any]) -> dict[str, Any]:
    """Mask internal IPs, usernames and hostnames before sending to a hosted API.

    Public IPs and hashes are kept because they are the useful IOCs.
    """
    out = dict(alert)
    private_map: dict[str, str] = {}

    def mask_ip(match: re.Match[str]) -> str:
        ip = match.group(0)
        if _is_public(ip):
            return ip
        return private_map.setdefault(ip, f"10.x.x.{len(private_map) + 1}")

    for key in ("full_log", "command_line", "agent_ip", "src_ip", "dst_ip", "location"):
        if out.get(key):
            out[key] = IPV4.sub(mask_ip, str(out[key]))
    user = out.get("src_user")
    if user and len(user) >= 3:
        out["src_user"] = "<user>"
        for key in ("full_log", "command_line"):
            out[key] = str(out.get(key, "")).replace(user, "<user>")
    if out.get("agent_name"):
        name = out["agent_name"]
        out["agent_name"] = "<host>"
        for key in ("full_log", "location"):
            out[key] = str(out.get(key, "")).replace(name, "<host>")
    return out
