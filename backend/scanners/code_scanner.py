"""
Velbrix - Code Security Scanner
Custom AST/regex-based detection of injection, XSS, unsafe eval, shell, etc.
Optionally integrates Bandit for Python.
"""
import re
import subprocess
import json
import tempfile
from pathlib import Path
from typing import List
from ..models import Finding


# Custom code patterns
CODE_RULES = [
    {
        "id": "SQL_INJECTION",
        "title": "SQL Injection Vulnerability",
        "patterns": [
            re.compile(r'(?i)(execute|cursor\.execute|db\.execute)\s*\(\s*f["\']'),
            re.compile(r'(?i)(execute|query)\s*\(\s*["\'].*\+.*["\']'),
            re.compile(r'(?i)(execute|query)\s*\(\s*["\'].*%s.*["\'].*%'),
            re.compile(r'(?i)(execute|query)\s*\(\s*["\'].*\{.*\}.*["\'].*\.format'),
            re.compile(r'(?i)(query|sql)\s*=\s*f["\'].*(?:SELECT|INSERT|UPDATE|DELETE|DROP|WHERE|FROM)', re.DOTALL),
        ],
        "severity": "Critical",
        "category": "Injection",
        "description": "User input is concatenated into a SQL query string.",
        "why_it_matters": "Attackers can inject SQL to bypass auth, exfiltrate data, or drop tables.",
        "fix": "Use parameterized queries: cursor.execute('SELECT * FROM u WHERE email = ?', (email,))",
    },
    {
        "id": "XSS_REFLECTED",
        "title": "Reflected XSS Vulnerability",
        "patterns": [
            re.compile(r'(?i)return\s+f["\'].*<.*>\{.*\}.*</.*>["\']'),
            re.compile(r'(?i)innerHTML\s*=\s*.*\+'),
            re.compile(r'(?i)document\.write\s*\('),
            re.compile(r'(?i)render_template_string\s*\(\s*f["\']'),
        ],
        "severity": "High",
        "category": "XSS",
        "description": "User input is rendered into HTML without escaping.",
        "why_it_matters": "Attackers can inject JavaScript to steal cookies or perform actions as the user.",
        "fix": "Escape user input with html.escape() or use framework auto-escaping.",
    },
    {
        "id": "UNSAFE_EVAL",
        "title": "Unsafe eval() Usage",
        "patterns": [
            re.compile(r'\beval\s*\('),
        ],
        "severity": "Critical",
        "category": "Code Execution",
        "description": "The code uses eval() which executes arbitrary strings as code.",
        "why_it_matters": "If any input reaches eval/exec, attackers achieve remote code execution.",
        "fix": "Remove eval/exec entirely. Use ast.literal_eval() for literals or proper parsers.",
    },
    {
        "id": "UNSAFE_EXEC",
        "title": "Unsafe exec() Usage",
        "patterns": [
            re.compile(r'\bexec\s*\(\s*(?!os\.)'),
        ],
        "severity": "Critical",
        "category": "Code Execution",
        "description": "The code uses exec() which executes arbitrary strings as code.",
        "why_it_matters": "If any input reaches exec, attackers achieve remote code execution.",
        "fix": "Remove exec() entirely. Use ast.literal_eval() for literals or proper parsers.",
    },
    {
        "id": "SHELL_INJECTION",
        "title": "Shell Command Injection",
        "patterns": [
            re.compile(r'os\.system\s*\(\s*f'),
            re.compile(r'os\.system\s*\(\s*["\'].*\+'),
            re.compile(r'subprocess\.(call|run|Popen)\s*\(\s*shell\s*=\s*True'),
            re.compile(r'os\.popen\s*\(\s*f'),
        ],
        "severity": "Critical",
        "category": "Injection",
        "description": "User input is passed to a shell command.",
        "why_it_matters": "Attackers can chain commands to take over the server.",
        "fix": "Use subprocess.run(['cmd', arg], shell=False). Validate input strictly.",
    },
    {
        "id": "UNSAFE_DESERIALIZATION",
        "title": "Unsafe Deserialization",
        "patterns": [
            re.compile(r'pickle\.loads?\s*\('),
            re.compile(r'yaml\.load\s*\((?!.*Loader)'),
        ],
        "severity": "Critical",
        "category": "Code Execution",
        "description": "Unsafe deserialization of untrusted data.",
        "why_it_matters": "Attackers can craft payloads that execute arbitrary code on deserialization.",
        "fix": "Use json.loads() or yaml.safe_load(). Avoid pickle for untrusted data.",
    },
    {
        "id": "PATH_TRAVERSAL",
        "title": "Path Traversal Risk",
        "patterns": [
            re.compile(r'open\s*\(\s*(request\.|user|input|filename|path)'),
            re.compile(r'send_file\s*\(\s*request\.'),
        ],
        "severity": "High",
        "category": "Injection",
        "description": "User input is used in file operations without validation.",
        "why_it_matters": "Attackers can read arbitrary files like /etc/passwd or .env.",
        "fix": "Validate and sanitize file paths. Use a fixed base directory. Reject '..' in paths.",
    },
    {
        "id": "UNSAFE_FILE_UPLOAD",
        "title": "Unsafe File Upload",
        "patterns": [
            re.compile(r'(?i)save\s*\(\s*.*filename'),
            re.compile(r'(?i)uploaded_file\.save'),
            re.compile(r'(?i)file\.save\s*\(\s*os\.path\.join'),
        ],
        "severity": "High",
        "category": "Injection",
        "description": "File upload handling does not validate file type or name.",
        "why_it_matters": "Attackers can upload malicious files (e.g., .php, .py) to gain RCE.",
        "fix": "Validate file extension against allowlist. Generate random filenames. Store outside web root.",
    },
    {
        "id": "HARDCODED_CORS_WILDCARD",
        "title": "Wildcard CORS Configuration",
        "patterns": [
            re.compile(r'(?i)CORS_ORIGINS\s*["\']?\s*\]?\s*=\s*["\']\*["\']'),
            re.compile(r'(?i)Access-Control-Allow-Origin["\']?\s*[:=]\s*["\']\*["\']'),
            re.compile(r'(?i)cors\(.*origins\s*=\s*["\']\*["\']'),
            re.compile(r'(?i)allow[_-]origins\s*=\s*\[\s*["\']\*["\']'),
            re.compile(r'(?i)[\'"]\*["\'].*cors', ),
        ],
        "severity": "High",
        "category": "Access Control",
        "description": "CORS is configured to allow all origins (*) in what appears to be a production setting.",
        "why_it_matters": "Any website can make authenticated requests to your API.",
        "fix": "Specify explicit allowed origins: CORS_ORIGINS = ['https://yourapp.com']",
    },
    {
        "id": "DEBUG_MODE_ON",
        "title": "Debug Mode Enabled",
        "patterns": [
            re.compile(r'app\.run\s*\(\s*debug\s*=\s*True'),
            re.compile(r'FLASK_DEBUG\s*=\s*True'),
            re.compile(r'app\.debug\s*=\s*True'),
        ],
        "severity": "High",
        "category": "Configuration",
        "description": "The application runs with debug mode enabled.",
        "why_it_matters": "Debug mode exposes stack traces and an interactive debugger to attackers.",
        "fix": "Set debug=False in production. Use environment variable: debug=os.environ.get('DEBUG','false').lower()=='true'",
    },
    {
        "id": "MISSING_SECURITY_HEADERS",
        "title": "Missing Security Headers",
        "patterns": [
            re.compile(r'(?i)after_request'),
        ],
        "severity": "Medium",
        "category": "Configuration",
        "description": "No security headers (CSP, X-Frame-Options, HSTS) are set.",
        "why_it_matters": "Without security headers, the app is vulnerable to clickjacking, MIME sniffing, and downgrade attacks.",
        "fix": "Add headers: Content-Security-Policy, X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Strict-Transport-Security.",
    },
    {
        "id": "EXPOSED_ADMIN_ROUTE",
        "title": "Exposed Admin Route Without Auth",
        "patterns": [
            re.compile(r'(?i)@(app|router)\.(route|get|post)\s*\(\s*["\']/?admin'),
            re.compile(r'(?i)@(app|router)\.(route|get|post)\s*\(\s*["\']/?dashboard'),
        ],
        "severity": "High",
        "category": "Access Control",
        "description": "An admin or dashboard route is defined without visible authentication checks.",
        "why_it_matters": "Anyone can access admin functionality without authentication.",
        "fix": "Add authentication decorator: @login_required @admin_required before admin routes.",
    },
    {
        "id": "WEAK_PASSWORD_HASH",
        "title": "Weak Password Hashing",
        "patterns": [
            re.compile(r'(?i)hashlib\.(md5|sha1)\s*\('),
            re.compile(r'(?i)password\s*==\s*'),
        ],
        "severity": "High",
        "category": "Cryptography",
        "description": "Passwords are hashed with MD5/SHA1 or compared in plaintext.",
        "why_it_matters": "MD5/SHA1 are broken. Plaintext comparison means passwords are stored in plaintext.",
        "fix": "Use bcrypt or argon2: import bcrypt; hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())",
    },
    {
        "id": "INCOMPLETE_API_CALL",
        "title": "Incomplete/Fake API Call",
        "patterns": [
            re.compile(r'(?i)requests\.get\s*\(\s*["\']https?://example\.com'),
            re.compile(r'(?i)TODO.*api'),
            re.compile(r'(?i)fetch\s*\(\s*["\']placeholder'),
        ],
        "severity": "Low",
        "category": "Deploy Readiness",
        "description": "API call points to example.com or has a TODO marker.",
        "why_it_matters": "The app will not work in production. Indicates incomplete implementation.",
        "fix": "Replace placeholder URLs with real endpoints. Complete all TODO items before deploy.",
    },
    {
        "id": "MISSING_TESTS",
        "title": "No Test Files Found",
        "patterns": [],
        "severity": "Medium",
        "category": "Deploy Readiness",
        "description": "The project has no test files (test_*.py, *.test.js, etc.).",
        "why_it_matters": "Without tests, regressions are likely and CI/CD cannot catch issues.",
        "fix": "Add unit tests for critical paths. Aim for at least 70% coverage on core modules.",
    },
]


def scan_code(project_path: Path, file_list: List[Path]) -> List[Finding]:
    findings: List[Finding] = []

    # Track if we find any test files
    has_tests = False

    for fp in file_list:
        try:
            rel = str(fp.relative_to(project_path))
            if any(seg in rel for seg in [".git/", "node_modules/", "venv/", "__pycache__/"]):
                continue
            if fp.stat().st_size > 500_000:
                continue
            content = fp.read_text(encoding="utf-8", errors="ignore")
            lines = content.splitlines()

            # Check for test files
            if fp.name.startswith("test_") or fp.name.endswith(".test.js") or fp.name.endswith(".test.ts") or fp.name == "tests.py":
                has_tests = True

            for rule in CODE_RULES:
                if not rule["patterns"]:
                    continue
                for pattern in rule["patterns"]:
                    for match in pattern.finditer(content):
                        line_no = content[:match.start()].count("\n") + 1
                        evidence = lines[line_no - 1].strip() if line_no <= len(lines) else match.group(0)
                        findings.append(Finding(
                            id=f"{rule['id']}_{fp.name}_{line_no}",
                            title=rule["title"],
                            severity=rule["severity"],
                            category=rule["category"],
                            file=rel,
                            line=line_no,
                            evidence=evidence[:200],
                            description=rule["description"],
                            why_it_matters=rule["why_it_matters"],
                            recommended_fix=rule["fix"],
                            scanner_source="code-regex",
                            confidence=0.85,
                        ))
        except Exception:
            continue

    # Add missing tests finding if none found
    if not has_tests:
        findings.append(Finding(
            id="MISSING_TESTS_global",
            title="No Test Files Found",
            severity="Medium",
            category="Deploy Readiness",
            file="(project root)",
            line=0,
            evidence="No files matching test_*.py, *.test.js, *.test.ts found",
            description="The project has no test files.",
            why_it_matters="Without tests, regressions are likely and CI/CD cannot catch issues.",
            recommended_fix="Add unit tests for critical paths. Aim for at least 70% coverage on core modules.",
            scanner_source="code-regex",
            confidence=0.9,
        ))

    return findings


def run_bandit(project_path: Path) -> List[Finding]:
    """Run Bandit scanner if available."""
    findings: List[Finding] = []
    try:
        result = subprocess.run(
            ["bandit", "-r", str(project_path), "-f", "json", "-q"],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode not in (0, 1):
            return findings
        data = json.loads(result.stdout)
        for item in data.get("results", []):
            sev_map = {"HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"}
            severity = sev_map.get(item.get("issue_severity", "MEDIUM"), "Medium")
            findings.append(Finding(
                id=f"BANDIT_{item.get('test_id', 'UNKNOWN')}_{item.get('filename', '').split('/')[-1]}_{item.get('line_number', 0)}",
                title=f"Bandit: {item.get('test_name', 'Security Issue')}",
                severity=severity,
                category="Code Quality",
                file=item.get("filename", "").replace(str(project_path) + "/", ""),
                line=item.get("line_number", 0),
                evidence=item.get("issue_text", "")[:200],
                description=item.get("issue_text", ""),
                why_it_matters=f"Bandit rule {item.get('test_id')} flagged this pattern.",
                recommended_fix=item.get("issue_text", "") + " Review Bandit documentation for remediation.",
                scanner_source="bandit",
                confidence=float(item.get("issue_confidence", "MEDIUM").lower() == "high" and 0.9 or 0.7),
            ))
    except FileNotFoundError:
        # Bandit not installed - skip
        pass
    except Exception:
        pass
    return findings
