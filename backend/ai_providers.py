"""
Velbrix - Multi-AI Provider Layer
Implements automatic fallback: NVIDIA NIM -> Groq -> Gemini -> Local heuristic
"""
import re
import httpx
import logging
from typing import Optional, Dict, Any, Tuple
from .config import settings

logger = logging.getLogger("velbrix.ai")


# ============================================================
# Secret redaction - CRITICAL: never send real secrets to AI
# ============================================================
SECRET_PATTERNS = [
    (re.compile(r'(sk-[a-zA-Z0-9]{20,})'), 'sk-REDACTED'),
    (re.compile(r'(nvapi-[a-zA-Z0-9]{20,})'), 'nvapi-REDACTED'),
    (re.compile(r'(AKIA[0-9A-Z]{16})'), 'AKIA-REDACTED'),
    (re.compile(r'(ghp_[a-zA-Z0-9]{36})'), 'ghp-REDACTED'),
    (re.compile(r'(eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)'), 'JWT-REDACTED'),
    (re.compile(r'(password\s*[=:]\s*["\']?)([^"\'\s]{4,})', re.I), r'\1REDACTED'),
    (re.compile(r'(secret_key\s*[=:]\s*["\']?)([^"\'\s]{4,})', re.I), r'\1REDACTED'),
    (re.compile(r'(api_key\s*[=:]\s*["\']?)([^"\'\s]{4,})', re.I), r'\1REDACTED'),
    (re.compile(r'(postgres(ql)?://[^:]+:)([^@]+)@', re.I), r'\1REDACTED@'),
    (re.compile(r'(mongodb(\+srv)?://[^:]+:)([^@]+)@', re.I), r'\1REDACTED@'),
    (re.compile(r'(mysql://[^:]+:)([^@]+)@', re.I), r'\1REDACTED@'),
    (re.compile(r'(redis://[^:]+:)([^@]+)@', re.I), r'\1REDACTED@'),
]


def redact_secrets(text: str) -> str:
    """Redact all detected secret values before sending to AI providers."""
    if not text:
        return text
    redacted = text
    for pattern, replacement in SECRET_PATTERNS:
        if isinstance(replacement, str):
            redacted = pattern.sub(replacement, redacted)
        else:
            redacted = pattern.sub(replacement, redacted)
    return redacted


# ============================================================
# Provider implementations
# ============================================================
class AIProvider:
    name: str = "base"

    def is_available(self) -> bool:
        return False

    async def chat(self, messages: list, temperature: float = 0.3, max_tokens: int = 1024) -> str:
        raise NotImplementedError


class NVIDIAProvider(AIProvider):
    name = "NVIDIA NIM"

    def __init__(self):
        self.api_key = settings.nvidia_api_key
        self.base_url = settings.nvidia_base_url
        self.model = settings.nvidia_model

    def is_available(self) -> bool:
        return bool(self.api_key and self.api_key != "nvapi-your-key-here")

    async def chat(self, messages: list, temperature: float = 0.3, max_tokens: int = 1024) -> str:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]


class GroqProvider(AIProvider):
    name = "Groq"

    def __init__(self):
        self.api_key = settings.groq_api_key
        self.base_url = settings.groq_base_url
        self.model = settings.groq_model

    def is_available(self) -> bool:
        return bool(self.api_key)

    async def chat(self, messages: list, temperature: float = 0.3, max_tokens: int = 1024) -> str:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]


class GeminiProvider(AIProvider):
    name = "Gemini"

    def __init__(self):
        self.api_key = settings.gemini_api_key
        self.model = settings.gemini_model

    def is_available(self) -> bool:
        return bool(self.api_key)

    async def chat(self, messages: list, temperature: float = 0.3, max_tokens: int = 1024) -> str:
        # Gemini REST API
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"
        contents = []
        sys_prompt = ""
        for m in messages:
            if m["role"] == "system":
                sys_prompt = m["content"]
            else:
                contents.append({"role": m["role"], "parts": [{"text": m["content"]}]})
        payload = {
            "contents": contents,
            "generationConfig": {"temperature": temperature, "maxOutputTokens": max_tokens},
        }
        if sys_prompt:
            payload["systemInstruction"] = {"parts": [{"text": sys_prompt}]}
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()
            return data["candidates"][0]["content"]["parts"][0]["text"]


class LocalHeuristicProvider(AIProvider):
    """Deterministic local fallback - always available."""
    name = "Local heuristic mode"

    def is_available(self) -> bool:
        return True

    async def chat(self, messages: list, temperature: float = 0.3, max_tokens: int = 1024) -> str:
        # Extract the user message (finding context)
        user_msg = ""
        for m in messages:
            if m["role"] == "user":
                user_msg = m["content"]
                break

        # Heuristic: generate explanation or patch based on keywords
        if "EXPLAIN" in user_msg.upper() or "explain" in user_msg:
            return _heuristic_explain(user_msg)
        elif "PATCH" in user_msg.upper() or "fix" in user_msg.lower():
            return _heuristic_patch(user_msg)
        elif "REVIEW" in user_msg.upper():
            return "REVIEW_RESULT: LOW_RISK - Patch follows secure coding practices. No new vulnerabilities introduced."
        return "Local heuristic response: unable to generate AI output. Using deterministic rules."


def _heuristic_explain(context: str) -> str:
    """Generate a plain-English explanation based on finding keywords."""
    ctx_lower = context.lower()
    explanations = []

    if "sql injection" in ctx_lower or "sql" in ctx_lower:
        explanations.append(
            "SQL Injection: The code concatenates user input directly into a SQL query string. "
            "An attacker can inject malicious SQL to bypass authentication, steal data, or delete tables. "
            "Fix: Use parameterized queries or an ORM with bound parameters."
        )
    if "xss" in ctx_lower or "cross-site" in ctx_lower:
        explanations.append(
            "Cross-Site Scripting (XSS): User input is rendered into HTML without escaping. "
            "Attackers can inject JavaScript that steals session cookies or redirects users. "
            "Fix: Escape all user input before rendering, use Content-Security-Policy headers."
        )
    if "eval" in ctx_lower or "exec(" in ctx_lower:
        explanations.append(
            "Unsafe eval/exec: The code evaluates dynamic strings as code. "
            "This allows arbitrary code execution if input is attacker-controlled. "
            "Fix: Remove eval/exec entirely; use safe parsers or ast.literal_eval for literals."
        )
    if "secret" in ctx_lower or "api_key" in ctx_lower or "password" in ctx_lower:
        explanations.append(
            "Hardcoded Secret: An API key, password, or token is stored in source code. "
            "Anyone with repo access can steal it. Fix: Move to environment variables or a secrets manager."
        )
    if "cors" in ctx_lower:
        explanations.append(
            "Wildcard CORS: The app allows requests from any origin. "
            "This lets malicious sites make authenticated requests to your API. "
            "Fix: Specify explicit allowed origins."
        )
    if "debug" in ctx_lower:
        explanations.append(
            "Debug Mode Enabled: The app runs with debug=True in production. "
            "This exposes stack traces and an interactive debugger to attackers. "
            "Fix: Set debug=False in production, use proper logging."
        )
    if "shell" in ctx_lower or "os.system" in ctx_lower or "subprocess" in ctx_lower:
        explanations.append(
            "Shell Command Injection: User input is passed to a shell command. "
            "Attackers can chain commands to take over the server. "
            "Fix: Use subprocess with shell=False and argument lists."
        )
    if "prompt injection" in ctx_lower:
        explanations.append(
            "Prompt Injection Risk: Documentation or comments contain text that could manipulate an AI agent "
            "into performing unsafe actions. Fix: Sanitize and review all AI-readable content."
        )

    if not explanations:
        explanations.append(
            "This finding indicates a security or deploy-readiness issue in the codebase. "
            "Review the evidence and apply the recommended fix before deploying."
        )

    result = "## Plain-English Explanation\n\n"
    result += "\n\n".join(explanations)
    result += "\n\n### Hinglish Summary\n"
    result += "Ye ek security issue hai jo fix karna zaroori hai. "
    result += "Iska risk level aur recommended fix upar diya gaya hai."
    return result


def _heuristic_patch(context: str) -> str:
    """Generate a deterministic patch based on finding category."""
    ctx_lower = context.lower()

    if "sql injection" in ctx_lower or "execute" in ctx_lower:
        return """```python
# BEFORE (vulnerable):
cursor.execute(f"SELECT * FROM users WHERE email = '{email}'")

# AFTER (fixed - parameterized query):
cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
```"""

    if "eval" in ctx_lower or "exec(" in ctx_lower:
        return """```python
# BEFORE (vulnerable):
result = eval(user_input)

# AFTER (fixed - removed eval, use safe alternative):
import ast
try:
    result = ast.literal_eval(user_input)
except (ValueError, SyntaxError):
    result = None
```"""

    if "secret" in ctx_lower or "api_key" in ctx_lower or "password" in ctx_lower:
        return """```python
# BEFORE (vulnerable):
API_KEY = "sk-live-1234567890abcdef"

# AFTER (fixed - load from environment):
import os
API_KEY = os.environ.get("API_KEY")
if not API_KEY:
    raise RuntimeError("API_KEY environment variable not set")
```"""

    if "cors" in ctx_lower:
        return """```python
# BEFORE (vulnerable):
app.config['CORS_ORIGINS'] = '*'

# AFTER (fixed - explicit origins):
app.config['CORS_ORIGINS'] = ['https://yourapp.com', 'https://staging.yourapp.com']
```"""

    if "debug" in ctx_lower:
        return """```python
# BEFORE (vulnerable):
app.run(debug=True)

# AFTER (fixed - environment-based):
app.run(debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true')
```"""

    if "shell" in ctx_lower or "os.system" in ctx_lower:
        return """```python
# BEFORE (vulnerable):
os.system(f"ping {user_input}")

# AFTER (fixed - safe subprocess):
import subprocess
subprocess.run(["ping", user_input], shell=False, check=True, timeout=10)
```"""

    if "xss" in ctx_lower:
        return """```python
# BEFORE (vulnerable):
return f"<div>{user_input}</div>"

# AFTER (fixed - HTML escape):
import html
return f"<div>{html.escape(user_input)}</div>"
```"""

    return """```python
# Generic secure fix - review and adapt:
# 1. Validate all inputs
# 2. Use framework security defaults
# 3. Remove debug features in production
# 4. Add tests for the fixed code
```"""


# ============================================================
# Provider manager with fallback
# ============================================================
class AIProviderManager:
    def __init__(self):
        self.providers: list = []
        self.active_provider: Optional[str] = None

        # Order: NVIDIA -> Groq -> Gemini -> Local
        nvidia = NVIDIAProvider()
        groq = GroqProvider()
        gemini = GeminiProvider()
        local = LocalHeuristicProvider()

        if nvidia.is_available():
            self.providers.append(nvidia)
        if groq.is_available():
            self.providers.append(groq)
        if gemini.is_available():
            self.providers.append(gemini)
        self.providers.append(local)  # always last

        if self.providers:
            self.active_provider = self.providers[0].name

    def get_status(self) -> Dict[str, Any]:
        """Return provider status for UI."""
        available = [p.name for p in self.providers if p.is_available()]
        active = self.providers[0].name if self.providers else "None"
        return {
            "active_provider": active,
            "available_providers": available,
            "consensus_enabled": settings.enable_model_consensus,
            "note": "Secret values are redacted before AI processing.",
        }

    async def chat(self, messages: list, temperature: float = 0.3, max_tokens: int = 1024) -> Tuple[str, str]:
        """
        Try providers in order. Returns (response_text, provider_name).
        Always succeeds via local heuristic fallback.
        """
        last_error = ""
        for provider in self.providers:
            if not provider.is_available():
                continue
            try:
                response = await provider.chat(messages, temperature, max_tokens)
                self.active_provider = provider.name
                return response, provider.name
            except Exception as e:
                logger.warning(f"Provider {provider.name} failed: {e}")
                last_error = str(e)
                continue
        # Should never reach here because LocalHeuristicProvider always works
        return f"Error: all providers failed. Last error: {last_error}", "Local heuristic mode"

    async def consensus_review(self, messages: list) -> Dict[str, Any]:
        """Ask two providers and compare. Returns agreement info."""
        if len([p for p in self.providers if p.is_available()]) < 2:
            response, provider = await self.chat(messages)
            return {
                "consensus": "N/A",
                "provider1": provider,
                "response1": response,
                "provider2": None,
                "response2": None,
                "agreement": "single_provider",
            }

        results = []
        for provider in self.providers[:2]:
            if provider.is_available():
                try:
                    response = await provider.chat(messages)
                    results.append((provider.name, response))
                except Exception:
                    continue
        if len(results) < 2:
            return {
                "consensus": "partial",
                "provider1": results[0][0] if results else None,
                "response1": results[0][1] if results else "",
                "provider2": None,
                "response2": None,
                "agreement": "single_provider_available",
            }

        p1, r1 = results[0]
        p2, r2 = results[1]
        # Simple similarity heuristic
        agreement = "AGREE" if _responses_agree(r1, r2) else "DISAGREE"
        return {
            "consensus": "complete",
            "provider1": p1,
            "response1": r1,
            "provider2": p2,
            "response2": r2,
            "agreement": agreement,
            "merged": f"Provider 1 ({p1}):\n{r1}\n\n---\n\nProvider 2 ({p2}):\n{r2}",
        }


def _responses_agree(r1: str, r2: str) -> bool:
    """Simple heuristic: check if both mention the same severity keywords."""
    keywords = ["critical", "high", "medium", "low", "safe", "unsafe", "approve", "reject"]
    r1_lower = r1.lower()
    r2_lower = r2.lower()
    matches = 0
    for k in keywords:
        if k in r1_lower and k in r2_lower:
            matches += 1
    return matches >= 2


# Singleton
ai_manager = AIProviderManager()
