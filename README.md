# AegisGate: Zero-Trust AI Pipeline Gatekeeper

AegisGate is a governed CI/CD supply-chain security auditor built to prevent automated scanner and AI-agent compromises modeled on the March 2026 Trivy/TeamPCP incident (`CVE-2026-33634`).

## Architecture & Safeguards
1. **Local Secret Redaction (`src/rules.py`):** Strips AWS keys (`AKIA...`), GitHub PATs (`ghp_...`), and API keys locally before any external LLM call.
2. **Deterministic Guardrails (`src/rules.py`):** Hard-coded checks enforce 40-character commit-SHA pinning on GitHub Actions, block `pull_request_target` secret exposure, detect known IOCs, and neutralize prompt-injection attempts.
3. **Sandboxed AI Risk Analysis (`src/ai_analyzer.py`):** Wraps sanitized YAML in `<untrusted_workflow_yaml>` isolation tags and enforces strict Pydantic JSON schemas (`openai/gpt-oss-120b` via Groq).
4. **Human-in-the-Loop Governance Gate (`src/app.py`):** Halts high-risk workflows (`PAUSED_FOR_HUMAN_REVIEW`) until an engineer explicitly clicks **Quarantine** or **Approve**, logging every decision to `audit_log.jsonl`.

## Quickstart
1. Create and activate a virtual environment:
   `python3 -m venv .venv && source .venv/bin/activate`
2. Install dependencies:
   `pip install -r requirements.txt`
3. Add your Groq API key:
   `echo "GROQ_API_KEY=your_groq_key_here" > .env`
4. Launch the interactive dashboard:
   `PYTHONPATH=. streamlit run src/app.py`
