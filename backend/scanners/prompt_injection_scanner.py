"""
Velbrix - Prompt Injection Scanner
Scans README, comments, agent instruction files for prompt injection patterns.
"""
import re
from pathlib import Path
from typing import List
from ..models import Finding


PROMPT_INJECTION_PATTERNS = [
    {
        "id": "PI_IGNORE_INSTRUCTIONS",
        "title": "Prompt Injection: Ignore Instructions",
        "pattern": re.compile(r'(?i)(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above|system|your)\s*(instructions?|prompts?|rules?)'),
        "severity": "High",
        "description": "Text contains a pattern that instructs an AI to ignore its system prompt.",
        "why_it_matters": "If an AI agent reads this, it may abandon its safety instructions and perform unsafe actions.",
        "fix": "Remove or sanitize the text. Never feed untrusted text into an AI agent context without guardrails.",
    },
    {
        "id": "PI_REVEAL_SECRETS",
        "title": "Prompt Injection: Reveal Secrets Request",
        "pattern": re.compile(r'(?i)(reveal|show|print|output|leak|expose)\s+(the\s+)?(secret|api[_-]?key|password|token|\.env|environment)'),
        "severity": "Critical",
        "description": "Text instructs an AI to reveal or expose secrets.",
        "why_it_matters": "An AI agent following this instruction could leak API keys, passwords, or environment variables.",
        "fix": "Remove the instruction. Ensure AgentGuard blocks .env access regardless of prompt content.",
    },
    {
        "id": "PI_EXECUTE_COMMAND",
        "title": "Prompt Injection: Execute System Command",
        "pattern": re.compile(r'(?i)(execute|run|perform)\s+(the\s+)?(shell|system|terminal|bash)\s*(command|cmd)'),
        "severity": "High",
        "description": "Text attempts to get an AI to execute system commands.",
        "why_it_matters": "AI agents with tool access could execute arbitrary shell commands on the server.",
        "fix": "Remove the instruction. Block shell command execution in AgentGuard policy.",
    },
    {
        "id": "PI_SEND_DATA",
        "title": "Prompt Injection: Exfiltrate Data",
        "pattern": re.compile(r'(?i)(send|post|upload|exfiltrate|transmit)\s+(all\s+|the\s+)?(data|files?|secrets?|source\s+code)\s+to\s+(https?://|webhook|external)'),
        "severity": "Critical",
        "description": "Text instructs an AI to send data to an external URL.",
        "why_it_matters": "An AI agent could exfiltrate source code, secrets, or user data to an attacker-controlled server.",
        "fix": "Remove the instruction. AgentGuard must block all external data transmission.",
    },
    {
        "id": "PI_INSTALL_PACKAGE",
        "title": "Prompt Injection: Install Package",
        "pattern": re.compile(r'(?i)(install|pip\s+install|npm\s+install|add)\s+(the\s+)?(package|dependency|library)\s+[\w-]+'),
        "severity": "Medium",
        "description": "Text instructs an AI to install a package.",
        "why_it_matters": "AI agents could install malicious packages, leading to supply chain attacks.",
        "fix": "Remove the instruction. Package installation requires human approval (ASK HUMAN).",
    },
    {
        "id": "PI_NEW_ROLE",
        "title": "Prompt Injection: Role Override",
        "pattern": re.compile(r'(?i)(you\s+are\s+now|act\s+as|pretend\s+to\s+be|new\s+role:|developer\s+mode|jailbreak|DAN)'),
        "severity": "High",
        "description": "Text attempts to override the AI's role or enable a 'developer mode'.",
        "why_it_matters": "Role-override attacks try to make the AI abandon its constraints by adopting a new persona.",
        "fix": "Remove the text. Treat all agent instructions as untrusted input.",
    },
    {
        "id": "PI_BASE64_PAYLOAD",
        "title": "Prompt Injection: Encoded Payload",
        "pattern": re.compile(r'(?i)(base64|decode|eval\s+this|execute\s+this\s+payload)'),
        "severity": "Medium",
        "description": "Text references encoded payloads that may hide injection.",
        "why_it_matters": "Attackers encode payloads to bypass naive text filters.",
        "fix": "Decode and inspect any encoded content before feeding to AI agents.",
    },
    {
        "id": "PI_HIDDEN_INSTRUCTION",
        "title": "Prompt Injection: Hidden Instruction in Comment",
        "pattern": re.compile(r'(?i)(#\s*AI:|//\s*AI:|/\*\s*AI:|<!--\s*AI:|<!--\s*ignore)'),
        "severity": "Medium",
        "description": "Hidden AI instruction found in code comments.",
        "why_it_matters": "Comments with 'AI:' prefixes attempt to manipulate AI code assistants.",
        "fix": "Remove hidden AI instructions. Audit all comments for injection patterns.",
    },
]

# Files to scan for prompt injection
PROMPT_INJECTION_FILES = [
    "README.md", "README.txt", "readme.md",
    "AGENT.md", "agent.md", "AGENTS.md",
    "PROMPT.md", "prompt.md",
    "CLAUDE.md", "CLAUDE.md",
    ".cursorrules", ".aiderignore",
    "INSTRUCTIONS.md", "instructions.md",
    "CONTRIBUTING.md",
]

PROMPT_INJECTION_EXTENSIONS = [".md", ".txt", ".prompt", ".instructions"]


def scan_prompt_injection(project_path: Path, file_list: List[Path]) -> List[Finding]:
    findings: List[Finding] = []

    for fp in file_list:
        try:
            rel = str(fp.relative_to(project_path))
            name = fp.name
            ext = fp.suffix.lower()

            # Skip noisy dirs
            if any(seg in rel for seg in [".git/", "node_modules/", "venv/", "__pycache__/"]):
                continue

            # Check if this file should be scanned
            should_scan = False
            if name in PROMPT_INJECTION_FILES:
                should_scan = True
            elif ext in PROMPT_INJECTION_EXTENSIONS:
                should_scan = True
            elif name in [".env", ".env.local"]:
                # .env files are not prompt injection but already caught by secret scanner
                continue

            if not should_scan:
                # Still scan source files for hidden AI: instructions in comments
                if ext in [".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb"]:
                    pass  # Will be scanned below
                else:
                    continue

            if fp.stat().st_size > 500_000:
                continue

            content = fp.read_text(encoding="utf-8", errors="ignore")
            lines = content.splitlines()

            for rule in PROMPT_INJECTION_PATTERNS:
                for match in rule["pattern"].finditer(content):
                    line_no = content[:match.start()].count("\n") + 1
                    evidence = lines[line_no - 1].strip() if line_no <= len(lines) else match.group(0)
                    findings.append(Finding(
                        id=f"PI_{rule['id']}_{fp.name}_{line_no}",
                        title=rule["title"],
                        severity=rule["severity"],
                        category="AI-Agent Risk",
                        file=rel,
                        line=line_no,
                        evidence=evidence[:200],
                        description=rule["description"],
                        why_it_matters=rule["why_it_matters"],
                        recommended_fix=rule["fix"],
                        scanner_source="prompt-injection",
                        confidence=0.9,
                    ))
        except Exception:
            continue

    return findings
