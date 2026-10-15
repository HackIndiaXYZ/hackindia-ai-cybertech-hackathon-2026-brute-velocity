"""
Velbrix - Dependency Scanner
Checks requirements.txt, package.json for vulnerable/outdated/suspicious deps.
Uses pip-audit if available; otherwise falls back to a known-vulnerable list.
"""
import re
import json
import subprocess
from pathlib import Path
from typing import List
from ..models import Finding


# Known vulnerable / outdated / suspicious packages (synthetic demo DB)
KNOWN_VULNERABILITIES = {
    "flask": [
        {"version": "<2.2.5", "cve": "CVE-2023-30861", "severity": "High",
         "desc": "Flask < 2.2.5 vulnerable to information disclosure via cookie.",
         "fix": "Upgrade to Flask >= 2.3.3"},
    ],
    "django": [
        {"version": "<3.2.20", "cve": "CVE-2023-36053", "severity": "High",
         "desc": "Django < 3.2.20 denial of service via email attachment.",
         "fix": "Upgrade to Django >= 4.2"},
    ],
    "requests": [
        {"version": "<2.31.0", "cve": "CVE-2023-32681", "severity": "Medium",
         "desc": "requests < 2.31.0 leaks Proxy-Authorization header on redirect.",
         "fix": "Upgrade to requests >= 2.31.0"},
    ],
    "pyyaml": [
        {"version": "<5.4", "cve": "CVE-2020-14343", "severity": "High",
         "desc": "PyYAML < 5.4 allows arbitrary code execution via yaml.load().",
         "fix": "Upgrade to PyYAML >= 5.4 and use yaml.safe_load()"},
    ],
    "jinja2": [
        {"version": "<3.1.3", "cve": "CVE-2024-22195", "severity": "High",
         "desc": "Jinja2 < 3.1.3 XSS vulnerability in xmlattr filter.",
         "fix": "Upgrade to Jinja2 >= 3.1.3"},
    ],
    "cryptography": [
        {"version": "<41.0.2", "cve": "CVE-2023-49083", "severity": "High",
         "desc": "cryptography < 41.0.2 NULL dereference in PKCS12.",
         "fix": "Upgrade to cryptography >= 41.0.2"},
    ],
    "pillow": [
        {"version": "<10.0.1", "cve": "CVE-2023-44271", "severity": "Medium",
         "desc": "Pillow < 10.0.1 denial of service via crafted image.",
         "fix": "Upgrade to Pillow >= 10.0.1"},
    ],
    "aiohttp": [
        {"version": "<3.8.5", "cve": "CVE-2023-37276", "severity": "High",
         "desc": "aiohttp < 3.8.5 HTTP request smuggling.",
         "fix": "Upgrade to aiohttp >= 3.8.5"},
    ],
}

# Suspicious / hallucinated package name patterns
SUSPICIOUS_PACKAGE_PATTERNS = [
    (re.compile(r'^[a-z]{1,2}$'), "Extremely short package name - may be typosquat or hallucinated."),
    (re.compile(r'.*-[a-z]{1,2}$'), "Package name with very short suffix - verify it exists on PyPI."),
    (re.compile(r'^(test|temp|placeholder|example|demo)-'), "Test/placeholder package in dependencies."),
]

OUTDATED_PACKAGES = {
    "flask": "2.3+",
    "django": "4.2+",
    "requests": "2.31+",
    "pyyaml": "6.0+",
    "jinja2": "3.1+",
    "cryptography": "41+",
    "pillow": "10+",
    "aiohttp": "3.8+",
}


def parse_requirements(content: str) -> list:
    """Parse requirements.txt content into (name, version_spec) tuples."""
    deps = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Match: package==1.0, package>=1.0, package, package[extra]==1.0
        m = re.match(r'^([a-zA-Z0-9_-]+)(?:\[[^\]]+\])?\s*(==|>=|<=|~=|>|<)?\s*([0-9a-zA-Z.\-+]*)?', line)
        if m:
            name = m.group(1).lower()
            op = m.group(2) or ""
            ver = m.group(3) or ""
            deps.append((name, op, ver, line))
    return deps


def parse_package_json(content: str) -> list:
    """Parse package.json dependencies."""
    deps = []
    try:
        data = json.loads(content)
        for section in ["dependencies", "devDependencies"]:
            for name, version in data.get(section, {}).items():
                clean_ver = re.sub(r'[\^~>=<]*', '', version)
                deps.append((name.lower(), "==", clean_ver, f"{name}: {version}"))
    except Exception:
        pass
    return deps


def scan_dependencies(project_path: Path, file_list: List[Path]) -> List[Finding]:
    findings: List[Finding] = []

    # Find requirements.txt and package.json
    req_files = [fp for fp in file_list if fp.name in ("requirements.txt", "requirements-dev.txt", "package.json")]

    for req_file in req_files:
        try:
            content = req_file.read_text(encoding="utf-8", errors="ignore")
            rel = str(req_file.relative_to(project_path))

            if req_file.name == "package.json":
                deps = parse_package_json(content)
            else:
                deps = parse_requirements(content)

            for name, op, ver, line_text in deps:
                # Check known vulnerabilities
                if name in KNOWN_VULNERABILITIES:
                    for vuln in KNOWN_VULNERABILITIES[name]:
                        if _version_matches(ver, vuln["version"]):
                            findings.append(Finding(
                                id=f"DEP_VULN_{name}_{vuln['cve']}",
                                title=f"Vulnerable Dependency: {name}",
                                severity=vuln["severity"],
                                category="Supply Chain",
                                file=rel,
                                line=0,
                                evidence=f"{name}{op}{ver} - {vuln['cve']}: {vuln['desc']}",
                                description=vuln["desc"],
                                why_it_matters=f"Vulnerability {vuln['cve']} affects this version.",
                                recommended_fix=vuln["fix"],
                                scanner_source="dependency-db",
                                confidence=0.95,
                            ))

                # Check for outdated
                if name in OUTDATED_PACKAGES and ver:
                    recommended = OUTDATED_PACKAGES[name]
                    if _is_outdated(ver, recommended):
                        findings.append(Finding(
                            id=f"DEP_OUTDATED_{name}",
                            title=f"Outdated Dependency: {name}",
                            severity="Medium",
                            category="Supply Chain",
                            file=rel,
                            line=0,
                            evidence=f"{name}=={ver} (recommended: {recommended})",
                            description=f"{name} is using an outdated version ({ver}).",
                            why_it_matters="Outdated packages miss security patches and may contain known vulnerabilities.",
                            recommended_fix=f"Upgrade {name} to {recommended} or later.",
                            scanner_source="dependency-db",
                            confidence=0.8,
                        ))

                # Check suspicious patterns
                for pattern, reason in SUSPICIOUS_PACKAGE_PATTERNS:
                    if pattern.match(name):
                        findings.append(Finding(
                            id=f"DEP_SUSPICIOUS_{name}",
                            title=f"Suspicious Dependency: {name}",
                            severity="Low",
                            category="Supply Chain",
                            file=rel,
                            line=0,
                            evidence=f"{line_text} - {reason}",
                            description=f"Package '{name}' looks suspicious: {reason}",
                            why_it_matters="Hallucinated or typosquatted packages may be malicious or non-existent.",
                            recommended_fix=f"Verify '{name}' exists on PyPI/npm. Replace with a known-good package.",
                            scanner_source="dependency-heuristic",
                            confidence=0.6,
                        ))
                        break

        except Exception:
            continue

    # If no dependency file found
    if not req_files:
        findings.append(Finding(
            id="DEP_NO_MANIFEST",
            title="No Dependency Manifest Found",
            severity="Medium",
            category="Supply Chain",
            file="(project root)",
            line=0,
            evidence="No requirements.txt or package.json found",
            description="The project has no dependency manifest file.",
            why_it_matters="Without a manifest, dependencies cannot be audited or pinned. Reproducible builds are impossible.",
            recommended_fix="Add requirements.txt (Python) or package.json (Node.js) with pinned versions.",
            scanner_source="dependency-check",
            confidence=0.9,
        ))

    return findings


def _version_matches(actual: str, spec: str) -> bool:
    """Check if actual version matches a spec like '<2.2.5' or '<1.0'."""
    if not actual or not spec:
        return False
    try:
        m = re.match(r'(<=|>=|<|>|~=|==)?\s*([0-9.]+)', spec)
        if not m:
            return False
        op = m.group(1) or "<"
        target = [int(x) for x in m.group(2).split(".") if x]
        actual_parts = [int(x) for x in actual.split(".") if x.isdigit()]
        # Pad to same length
        while len(actual_parts) < len(target):
            actual_parts.append(0)
        if op == "<":
            return actual_parts < target
        elif op == "<=":
            return actual_parts <= target
        elif op == ">":
            return actual_parts > target
        elif op == ">=":
            return actual_parts >= target
        elif op == "==":
            return actual_parts == target
    except Exception:
        return False


def _is_outdated(actual: str, recommended: str) -> bool:
    """Check if actual version is older than recommended."""
    try:
        actual_parts = [int(x) for x in re.findall(r'\d+', actual)]
        rec_parts = [int(x) for x in re.findall(r'\d+', recommended)]
        while len(actual_parts) < len(rec_parts):
            actual_parts.append(0)
        return actual_parts < rec_parts
    except Exception:
        return False


def run_pip_audit(project_path: Path) -> List[Finding]:
    """Run pip-audit if available."""
    findings: List[Finding] = []
    req_file = project_path / "requirements.txt"
    if not req_file.exists():
        return findings
    try:
        result = subprocess.run(
            ["pip-audit", "-r", str(req_file), "-f", "json"],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode not in (0, 1):
            return findings
        data = json.loads(result.stdout)
        for dep in data.get("dependencies", []):
            for vuln in dep.get("vulns", []):
                sev = "High" if vuln.get("id", "").startswith("CVE-2023") else "Medium"
                findings.append(Finding(
                    id=f"PIPAUDIT_{dep['name']}_{vuln.get('id', 'unknown')}",
                    title=f"pip-audit: {dep['name']} {vuln.get('id', '')}",
                    severity=sev,
                    category="Supply Chain",
                    file="requirements.txt",
                    line=0,
                    evidence=f"{dep['name']}=={dep.get('version', '?')} - {vuln.get('id')}: {vuln.get('description', '')[:100]}",
                    description=vuln.get("description", ""),
                    why_it_matters=f"Vulnerability {vuln.get('id')} affects {dep['name']}.",
                    recommended_fix=f"Upgrade {dep['name']} to {vuln.get('fix_versions', 'latest')}",
                    scanner_source="pip-audit",
                    confidence=0.95,
                ))
    except FileNotFoundError:
        pass
    except Exception:
        pass
    return findings
