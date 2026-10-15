"""
Velbrix - Secret Scanner
Gitleaks-style regex-based detection of hardcoded secrets.
"""
import re
import os
from pathlib import Path
from typing import List
from ..models import Finding

SECRET_RULES = [
    {
        "id": "SECRET_OPENAI_KEY",
        "title": "Hardcoded OpenAI API Key",
        "pattern": re.compile(r'sk-[a-zA-Z0-9]{20,}'),
        "severity": "Critical",
        "category": "Secrets",
        "description": "An OpenAI API key is hardcoded in source.",
        "why_it_matters": "Attackers can steal the key and run up charges or access your OpenAI account.",
        "fix": "Move to environment variable (os.environ.get('OPENAI_API_KEY')) and rotate the key immediately.",
    },
    {
        "id": "SECRET_AWS_KEY",
        "title": "Hardcoded AWS Access Key",
        "pattern": re.compile(r'AKIA[0-9A-Z]{16}'),
        "severity": "Critical",
        "category": "Secrets",
        "description": "An AWS access key ID is hardcoded in source.",
        "why_it_matters": "Attackers can access your AWS resources, steal data, or incur massive charges.",
        "fix": "Use IAM roles or AWS Secrets Manager. Rotate the key immediately.",
    },
    {
        "id": "SECRET_JWT",
        "title": "Hardcoded JWT Secret",
        "pattern": re.compile(r'(?i)(jwt[_-]?secret|jwt[_-]?key)\s*[=:]\s*["\']([a-zA-Z0-9]{8,})["\']'),
        "severity": "Critical",
        "category": "Secrets",
        "description": "A JWT signing secret is hardcoded.",
        "why_it_matters": "Anyone can forge authentication tokens and impersonate any user.",
        "fix": "Load JWT secret from environment variable. Rotate immediately if committed.",
    },
    {
        "id": "SECRET_PASSWORD",
        "title": "Hardcoded Password",
        "pattern": re.compile(r'(?i)^\s*(password|passwd|pwd)\s*=\s*["\']([^"\'\s]{4,})["\']'),
        "severity": "High",
        "category": "Secrets",
        "description": "A password is hardcoded in source code.",
        "why_it_matters": "Anyone with code access learns the password. Often reused across systems.",
        "fix": "Load from environment variable or secrets manager. Never commit credentials.",
    },
    {
        "id": "SECRET_DB_URL",
        "title": "Database URL with Credentials",
        "pattern": re.compile(r'(postgres(ql)?|mysql|mongodb(\+srv)?|redis)://[^:]+:[^@]+@'),
        "severity": "Critical",
        "category": "Secrets",
        "description": "A database connection string contains embedded credentials.",
        "why_it_matters": "Database credentials leak via the URL. Attackers can connect directly.",
        "fix": "Use environment variable for DATABASE_URL. Restrict DB to localhost or private network.",
    },
    {
        "id": "SECRET_GITHUB_TOKEN",
        "title": "Hardcoded GitHub Token",
        "pattern": re.compile(r'ghp_[a-zA-Z0-9]{36}'),
        "severity": "Critical",
        "category": "Secrets",
        "description": "A GitHub personal access token is hardcoded.",
        "why_it_matters": "Attackers can access your repositories, alter code, or steal IP.",
        "fix": "Move to environment variable. Revoke the token on GitHub immediately.",
    },
    {
        "id": "SECRET_GENERIC_API_KEY",
        "title": "Hardcoded API Key",
        "pattern": re.compile(r'(?i)(api[_-]?key|apikey|secret[_-]?key)\s*[=:]\s*["\']([a-zA-Z0-9]{16,})["\']'),
        "severity": "High",
        "category": "Secrets",
        "description": "A generic API key or secret is hardcoded.",
        "why_it_matters": "Keys in source are accessible to anyone with repo access.",
        "fix": "Move to environment variable. Rotate the key.",
    },
    {
        "id": "SECRET_STRIPE_KEY",
        "title": "Hardcoded Stripe Key",
        "pattern": re.compile(r'(sk|pk)_(live|test)_[a-zA-Z0-9]{20,}'),
        "severity": "Critical",
        "category": "Secrets",
        "description": "A Stripe API key is hardcoded.",
        "why_it_matters": "Attackers can charge cards, issue refunds, or access customer data.",
        "fix": "Move to environment variable. Rotate the key in Stripe dashboard.",
    },
]

# Files that should not be in the repo
SENSITIVE_FILES = [
    (".env", "Exposed .env File", "Critical",
     "A .env file is present in the project root and may be committed to version control.",
     ".env files typically contain live secrets. If committed, all secrets are exposed.",
     "Add .env to .gitignore. Never commit .env files. Rotate any exposed secrets."),
    (".env.local", "Exposed .env.local File", "Critical",
     "A .env.local file is present in the project.",
     "Local environment files contain secrets that should never be committed.",
     "Add to .gitignore. Rotate any exposed secrets."),
    (".env.production", "Exposed .env.production File", "Critical",
     "A production environment file is present in the project.",
     "Production secrets are now exposed in source code.",
     "Move secrets to a secrets manager. Add to .gitignore. Rotate immediately."),
]

BACKUP_FILES = [
    (r'.*\.bak$', "Exposed Backup File", "Medium",
     "A backup file (.bak) is present in the project.",
     "Backup files may contain old secrets or sensitive data and are often committed by mistake.",
     "Remove backup files from the repository. Add *.bak to .gitignore."),
    (r'.*\.orig$', "Exposed Merge Backup File", "Low",
     "A merge backup file (.orig) is present.",
     "Merge backups can contain sensitive data and should be cleaned up.",
     "Remove .orig files. Add to .gitignore."),
    (r'.*\.log$', "Exposed Log File", "Medium",
     "A log file (.log) is present in the project.",
     "Logs may contain secrets, tokens, or PII. They should not be committed.",
     "Remove log files. Add *.log to .gitignore. Implement proper log rotation."),
    (r'.*\.swp$', "Exposed Vim Swap File", "Low",
     "A Vim swap file (.swp) is present.",
     "Swap files can contain unsaved code or sensitive data.",
     "Remove swap files. Add *.swp to .gitignore."),
]


def scan_secrets(project_path: Path, file_list: List[Path]) -> List[Finding]:
    findings: List[Finding] = []

    for fp in file_list:
        try:
            rel = str(fp.relative_to(project_path))
            # Skip binary and very large files
            if fp.stat().st_size > 500_000:
                continue
            try:
                content = fp.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            lines = content.splitlines()

            # Skip files in .git, node_modules, venv
            if any(seg in rel for seg in [".git/", "node_modules/", "venv/", "__pycache__/"]):
                continue

            # Regex secret scan
            for rule in SECRET_RULES:
                for match in rule["pattern"].finditer(content):
                    line_no = content[:match.start()].count("\n") + 1
                    evidence_line = lines[line_no - 1].strip() if line_no <= len(lines) else match.group(0)
                    # Redact the actual secret in evidence
                    redacted = rule["pattern"].sub("***REDACTED***", evidence_line)
                    findings.append(Finding(
                        id=f"{rule['id']}_{fp.name}_{line_no}",
                        title=rule["title"],
                        severity=rule["severity"],
                        category=rule["category"],
                        file=rel,
                        line=line_no,
                        evidence=redacted[:200],
                        description=rule["description"],
                        why_it_matters=rule["why_it_matters"],
                        recommended_fix=rule["fix"],
                        scanner_source="secret-regex",
                        confidence=0.95,
                    ))
        except Exception:
            continue

    # Check for sensitive files
    for fp in file_list:
        try:
            rel = str(fp.relative_to(project_path))
            name = fp.name
            for fname, title, sev, desc, why, fix in SENSITIVE_FILES:
                if name == fname:
                    findings.append(Finding(
                        id=f"SENSITIVE_FILE_{fname}_{rel}",
                        title=title,
                        severity=sev,
                        category="Secrets",
                        file=rel,
                        line=1,
                        evidence=f"File present: {rel}",
                        description=desc,
                        why_it_matters=why,
                        recommended_fix=fix,
                        scanner_source="file-pattern",
                        confidence=0.99,
                    ))
            for pattern, title, sev, desc, why, fix in BACKUP_FILES:
                if re.match(pattern, name):
                    findings.append(Finding(
                        id=f"BACKUP_FILE_{rel}",
                        title=title,
                        severity=sev,
                        category="Secrets",
                        file=rel,
                        line=1,
                        evidence=f"Backup file present: {rel}",
                        description=desc,
                        why_it_matters=why,
                        recommended_fix=fix,
                        scanner_source="file-pattern",
                        confidence=0.9,
                    ))
        except Exception:
            continue

    return findings
