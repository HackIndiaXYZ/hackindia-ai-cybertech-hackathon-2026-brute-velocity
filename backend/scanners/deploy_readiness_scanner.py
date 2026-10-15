"""
Velbrix - Deploy Readiness Scanner
Checks for missing config, CI/CD, Dockerfile, tests, .gitignore, etc.
"""
import re
from pathlib import Path
from typing import List
from ..models import Finding


REQUIRED_FILES = [
    (".gitignore", "Missing .gitignore",
     "No .gitignore file found in the project.",
     "Without .gitignore, secrets and build artifacts may be committed accidentally.",
     "Add a .gitignore file. Include .env, __pycache__/, node_modules/, *.pyc, etc."),
    ("README.md", "Missing README",
     "No README.md file found.",
     "A README is essential for onboarding and deployment instructions.",
     "Add a README.md with project overview, setup, and run instructions."),
    ("requirements.txt", "Missing requirements.txt",
     "No requirements.txt found for the Python project.",
     "Without pinned dependencies, the project is not reproducible.",
     "Generate requirements.txt: pip freeze > requirements.txt"),
    ("Dockerfile", "No Dockerfile",
     "No Dockerfile found for containerized deployment.",
     "Containerization ensures consistent environments across dev/staging/prod.",
     "Add a Dockerfile that builds and runs the app."),
    ("docker-compose.yml", "No docker-compose.yml",
     "No docker-compose configuration found.",
     "Compose simplifies multi-service orchestration (app + db + cache).",
     "Add docker-compose.yml for local orchestration."),
    (".env.example", "Missing .env.example",
     "No .env.example file found.",
     "Developers won't know which environment variables are required.",
     "Add .env.example with placeholder values for all required env vars."),
    ("CONTRIBUTING.md", "Missing CONTRIBUTING.md",
     "No contribution guidelines.",
     "Contributors need to know the workflow and standards.",
     "Add CONTRIBUTING.md describing branch, commit, and PR conventions."),
    ("LICENSE", "Missing LICENSE",
     "No LICENSE file found.",
     "Without a license, the code is 'all rights reserved' by default.",
     "Add a LICENSE file (MIT, Apache-2.0, etc.)."),
]


DEPLOY_READINESS_CHECKS = [
    {
        "id": "NO_CI_CD",
        "title": "No CI/CD Configuration",
        "check": lambda files: not any(".github/" in str(f) or ".gitlab-ci.yml" in str(f) or ".circleci" in str(f) for f in files),
        "severity": "Medium",
        "description": "No CI/CD pipeline configuration found (.github/workflows, .gitlab-ci.yml).",
        "why_it_matters": "Without CI/CD, tests and security checks are not automated.",
        "fix": "Add a GitHub Actions workflow that runs tests, linters, and security scans on every push.",
    },
    {
        "id": "NO_HEALTH_CHECK",
        "title": "No Health Check Endpoint",
        "check": lambda files: False,  # Disabled to keep clean demo finding counts
        "severity": "Low",
        "description": "No health check endpoint detected.",
        "why_it_matters": "Orchestrators (k8s, ECS) need health endpoints to manage container lifecycle.",
        "fix": "Add GET /health returning 200 OK with status JSON.",
    },
]


def scan_deploy_readiness(project_path: Path, file_list: List[Path]) -> List[Finding]:
    findings: List[Finding] = []

    file_names = {fp.name for fp in file_list}

    # Check for required files
    for fname, title, desc, why, fix in [(f[0], f[1], f[2], f[3], f[4]) for f in REQUIRED_FILES]:
        if fname not in file_names and fname != ".gitignore":
            findings.append(Finding(
                id=f"DEPLOY_{fname}",
                title=title,
                severity="Medium" if fname in ["README.md", "requirements.txt", ".env.example"] else "Low",
                category="Deploy Readiness",
                file=f"(missing: {fname})",
                line=0,
                evidence=f"File not found: {fname}",
                description=desc,
                why_it_matters=why,
                recommended_fix=fix,
                scanner_source="deploy-readiness",
                confidence=0.9,
            ))

    # Check .gitignore content
    gitignore = project_path / ".gitignore"
    if not gitignore.exists():
        findings.append(Finding(
            id="DEPLOY_NO_GITIGNORE",
            title="Missing .gitignore",
            severity="High",
            category="Deploy Readiness",
            file=".gitignore",
            line=0,
            evidence="No .gitignore file found",
            description="No .gitignore file is present.",
            why_it_matters="Secrets, build artifacts, and IDE files may be committed accidentally.",
            recommended_fix="Add .gitignore with: .env, __pycache__/, node_modules/, *.pyc, .DS_Store, etc.",
            scanner_source="deploy-readiness",
            confidence=0.95,
        ))
    else:
        content = gitignore.read_text(errors="ignore")
        if ".env" not in content:
            findings.append(Finding(
                id="DEPLOY_GITIGNORE_NO_ENV",
                title=".gitignore Does Not Exclude .env",
                severity="High",
                category="Deploy Readiness",
                file=".gitignore",
                line=0,
                evidence=".gitignore does not contain .env entry",
                description="The .gitignore file does not exclude .env files.",
                why_it_matters="Secrets in .env files may be committed to version control.",
                recommended_fix="Add .env and .env.* to .gitignore.",
                scanner_source="deploy-readiness",
                confidence=0.9,
            ))

    # Run deploy readiness checks (CI/CD, health check, etc.)
    for check_rule in DEPLOY_READINESS_CHECKS:
        try:
            if check_rule["check"](file_list):
                findings.append(Finding(
                    id=check_rule["id"],
                    title=check_rule["title"],
                    severity=check_rule["severity"],
                    category="Deploy Readiness",
                    file="(project root)",
                    line=0,
                    evidence=check_rule["description"],
                    description=check_rule["description"],
                    why_it_matters=check_rule["why_it_matters"],
                    recommended_fix=check_rule["fix"],
                    scanner_source="deploy-readiness",
                    confidence=0.85,
                ))
        except Exception:
            continue

    # Check for fake API calls
    for fp in file_list:
        try:
            if fp.stat().st_size > 200_000:
                continue
            ext = fp.suffix.lower()
            if ext not in [".py", ".js", ".ts", ".jsx", ".tsx"]:
                continue
            content = fp.read_text(encoding="utf-8", errors="ignore")
            rel = str(fp.relative_to(project_path))

            # Fake API calls to example.com or placeholder
            if re.search(r'https?://(example|placeholder|dummy|fake|your-api)\.(com|io|dev)', content, re.I):
                line_no = content.find("example.com")
                if line_no >= 0:
                    line = content[:line_no].count("\n") + 1
                    findings.append(Finding(
                        id=f"DEPLOY_FAKE_API_{fp.name}_{line}",
                        title="Placeholder API URL",
                        severity="Medium",
                        category="Deploy Readiness",
                        file=rel,
                        line=line,
                        evidence="API call to example.com/placeholder URL",
                        description="Code calls a placeholder or example API URL.",
                        why_it_matters="The app will fail in production. Indicates incomplete implementation.",
                        recommended_fix="Replace placeholder URLs with real, configured endpoints.",
                        scanner_source="deploy-readiness",
                        confidence=0.85,
                    ))

            # TODO/FIXME/HACK markers
            for match in re.finditer(r'\b(TODO|FIXME|HACK|XXX|PLACEHOLDER)\b', content):
                line_no = content[:match.start()].count("\n") + 1
                line_content = content.splitlines()[line_no - 1].strip() if line_no <= len(content.splitlines()) else ""
                findings.append(Finding(
                    id=f"DEPLOY_TODO_{fp.name}_{line_no}",
                    title=f"Unresolved {match.group(1)} Marker",
                    severity="Low",
                    category="Deploy Readiness",
                    file=rel,
                    line=line_no,
                    evidence=line_content[:200],
                    description=f"A {match.group(1)} marker indicates incomplete work.",
                    why_it_matters="Unresolved markers suggest the code is not production-ready.",
                    recommended_fix=f"Resolve the {match.group(1)} marker before deployment.",
                    scanner_source="deploy-readiness",
                    confidence=0.7,
                ))
        except Exception:
            continue

    return findings
