# Velbrix - Presentation Notes

> How each PPT claim is demonstrated in the live app.
> Team BruteVelocity — Yogesh Kumar, Ravi Kumar, Prarthana Bhardwaj

---

## Slide 1: Hook — "AI makes building easy. Security stays hard"

**PPT Claim:** AI can build an app in minutes, but would you trust it with your users' data?

**Demo Evidence:**
- VibeBank (the demo project) looks like a working banking app
- ShipScan finds 2 Critical + 5 High vulnerabilities in seconds
- The README contains prompt injection that no human reviewer caught

---

## Slide 2: Problem — Six categories of security blind spots

**PPT Claim:** Secrets, Injection & uploads, Access & sessions, Supply chain, AI-agent risk, Not deploy-ready

**Demo Evidence:**
- Dashboard shows findings across all categories
- VibeBank has hardcoded API key (Secrets), SQL injection + unsafe eval (Injection), wildcard CORS + debug mode (Access), flask CVE (Supply chain), prompt injection (AI-agent risk), no tests + no CI/CD (Not deploy-ready)

---

## Slide 3: Workflow — "From upload to a Deploy, Review or Block decision"

**PPT Claim:** Six-step workflow: Upload → Scan → Explain → Fix → Rescan → Decide

**Demo Evidence:**
- Sidebar shows all 7 steps (Upload, ShipScan, Finding Details, FixMe, AgentGuard, SessionGuard, Trust Report)
- Each step is navigable and functional
- Behind the scenes: Isolated worker, Scanners, Normalizer, AI engine, Trust Report

---

## Slide 4: Five Modules — "Five modules, one safe workflow"

**PPT Claim:** ShipScan, FixMe Space, SessionGuard, AgentGuard, Trust Report

**Demo Evidence:**
- Each module is a dedicated view in the sidebar
- FixMe Space: explain → diff → temp copy → test → rescan → approve/reject
- Human approves every patch; original stays safe; rollback available

---

## Slide 5: VibeBank Demo — "BLOCK to REVIEW"

**PPT Claim:** Before: 38/100 BLOCK. After: 81/100 REVIEW

**Demo Evidence (VERIFIED):**
- Before: Score 38/100, BLOCK, 2 Critical, 5 High, 1 exposed secret, PI risk High
- After 6 patches: Score 81/100, REVIEW, 0 Critical, 1 High, 0 exposed secrets, patch verification Passed
- AgentGuard log: ALLOW read source, BLOCK read .env, BLOCK send external, ASK HUMAN install package, BLOCK shell command

---

## Slide 6: Why Velbrix — Differentiators, Pricing, Roadmap

**PPT Claim:** Guided plain-English findings, AI-agent safety, verified before/after

**Demo Evidence:**
- Finding Details page shows plain-English explanation with Hinglish
- AgentGuard demonstrates agent instruction safety
- FixMe Space shows verified before/after score comparison
- Trust Report produces downloadable HTML + Markdown

---

## Q&A Preparation

**Q: How does the scoring engine work?**
A: Transparent, evidence-based. Start at 100, subtract by severity (Critical=11.5, High=5, Medium=3, Low=1). Findings deduplicated by title. Decision: <50 or any Critical = BLOCK, 50-84 = REVIEW, 85+ = DEPLOY.

**Q: What happens if NVIDIA NIM is down?**
A: Automatic fallback: NVIDIA → Groq → Gemini → Local heuristic. The app always works. If no AI key is set, it uses deterministic rule-based patches.

**Q: Are secrets sent to AI providers?**
A: Never. We use regex patterns to detect and redact all secret values before sending any code context to AI providers. The UI explicitly notes this.

**Q: Does Velbrix modify the original uploaded project?**
A: Never automatically. Every patch is applied to an isolated temporary copy. The original project is untouched. Human approval is required.

**Q: How does AgentGuard work without real execution?**
A: AgentGuard simulates AI-agent actions in a sandbox. The policy engine evaluates each action against 11 policy rules and returns ALLOW, BLOCK, or ASK HUMAN.

**Q: Is SessionGuard using real cookies?**
A: No. SessionGuard uses synthetic tokens against an authorized local test app. No real cookies, passwords, or browser profiles are used.

**Q: Can Velbrix scan public websites?**
A: No. Velbrix only analyzes user-uploaded ZIP projects or the bundled authorized demo project.
