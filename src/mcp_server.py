"""Uproot MCP server.

Exposes two tools to MCP clients (Claude Code, Claude Desktop, ...):
  - audit_github_workflow(workflow_yaml): audit raw GitHub Actions YAML
  - audit_fixture(name): audit a file from the fixtures/ directory

Pipeline for every audit:
  1. redact secrets            (rules.redact_secrets)       - before any AI sees the text
  2. deterministic checks      (rules.run_deterministic_checks)
  3. AI analysis (optional)    (ai_analyzer.analyze_workflow) - can only RAISE risk, never lower it
  4. append one line to audit_log.jsonl

Run from anywhere:  /path/to/.venv/bin/python /path/to/src/mcp_server.py
IMPORTANT: this is a stdio server - never print() to stdout; it corrupts the protocol.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

# --- Paths: everything is absolute, derived from this file's location, so the server
# works no matter which directory the MCP client launches it from.
SRC_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SRC_DIR.parent
FIXTURES_DIR = (PROJECT_ROOT / "fixtures").resolve()
# Overridable so tests never write into the real audit log.
AUDIT_LOG_PATH = Path(os.environ.get("AEGISGATE_AUDIT_LOG", PROJECT_ROOT / "audit_log.jsonl")).resolve()
ENV_PATH = PROJECT_ROOT / ".env"

# When run as a script, Python puts src/ on sys.path, not the project root.
# Adding the root lets us import the teammate's modules as the `src` package.
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from dotenv import load_dotenv  # noqa: E402
from pydantic import BaseModel, Field  # noqa: E402

from mcp.server import MCPServer  # noqa: E402
from mcp.server.mcpserver.exceptions import ToolError  # noqa: E402

load_dotenv(ENV_PATH)  # absolute path: does not depend on the current working directory

from src.rules import redact_secrets, run_deterministic_checks  # noqa: E402

# Logs go to stderr (stdout is reserved for the MCP protocol).
logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("uproot.mcp")

# The AI analyzer is optional: if it is missing, broken, or Groq is down, we fall back
# to the rules-only result. Import errors (e.g. missing API key at import) are tolerated.
try:
    from src import ai_analyzer
except Exception as exc:  # pragma: no cover - depends on teammate's module
    log.warning("Could not import ai_analyzer: %r", exc)
    ai_analyzer = None

MAX_INPUT_BYTES = 512 * 1024  # refuse absurdly large inputs
AI_RISK_THRESHOLD = 50        # AI risk_score at/above this pauses a workflow with no rule flags

Status = Literal["APPROVED", "PAUSED_FOR_HUMAN_REVIEW"]

# Rules-only risk weights, keyed by the flag prefix that rules.py emits.
FLAG_WEIGHTS = {
    "KNOWN_IOC_MATCH": 50,
    "PROMPT_INJECTION_DETECTED": 40,
    "REMOTE_CODE_EXECUTION": 35,
    "DANGEROUS_TRIGGER": 30,
    "UNPINNED_ACTION": 15,
}
DEFAULT_FLAG_WEIGHT = 20


class AuditReport(BaseModel):
    """Structured result returned to the MCP client."""

    status: Status = Field(description="APPROVED, or PAUSED_FOR_HUMAN_REVIEW if anything looked risky")
    risk_score: int = Field(ge=0, le=100, description="0 (safe) to 100 (critical)")
    flags: list[str] = Field(description="Deterministic rule findings; any flag forces human review")
    redaction_count: int = Field(description="Number of secrets redacted before analysis")
    ai_explanation: str | None = Field(description="AI analysis, or None if the AI was unavailable")
    ai_used: bool = Field(description="False means this is a rules-only result")
    ai_error: str | None = Field(default=None, description="Why the AI was skipped, if it was")
    requires_human_approval: bool


# ---------------------------------------------------------------------------
# Core logic (plain functions, so they can be unit-tested without MCP)
# ---------------------------------------------------------------------------

def rules_risk_score(flags: list[str]) -> int:
    score = 0
    for flag in flags:
        prefix = flag.split(":", 1)[0]
        score += FLAG_WEIGHTS.get(prefix, DEFAULT_FLAG_WEIGHT)
    return min(score, 100)


def call_ai(redacted_yaml: str, flags: list[str]) -> tuple[int | None, str | None, str | None]:
    """Call the teammate's analyzer. Returns (ai_risk_score, explanation, error).

    Teammate's contract (src/ai_analyzer.py):
        analyze_workflow(workflow_yaml: str) -> GovernedAuditReport
    It re-runs redaction and the rules itself, so `flags` is not passed; we still hand it
    the already-redacted text so raw secrets never leave this process.
    We use `ai_raw_risk_score` (the model's own opinion), NOT `final_risk_score`, which already
    has the analyzer's own governance floors baked in; our governance in audit() applies on top.
    Any exception or unexpected shape -> (None, None, error) and we fall back to rules-only.
    """
    analyze = getattr(ai_analyzer, "analyze_workflow", None) if ai_analyzer else None
    if analyze is None:
        return None, None, "ai_analyzer.analyze_workflow is not available"
    try:
        result = analyze(redacted_yaml)
        raw_score = getattr(result, "ai_raw_risk_score", None)
        if isinstance(raw_score, bool) or not isinstance(raw_score, int):
            raise TypeError(f"expected int ai_raw_risk_score, got {type(raw_score).__name__}")
        ai_score = max(0, min(100, raw_score))
        summary = str(getattr(result, "ai_summary", "") or "").strip()
        fix = str(getattr(result, "recommended_fix", "") or "").strip()
        explanation = " ".join(p for p in (summary, f"Recommended fix: {fix}" if fix else "") if p) or None
        return ai_score, explanation, None
    except Exception as exc:  # Groq outage, timeout, bad JSON, bug in analyzer...
        log.warning("AI analysis failed, falling back to rules-only: %r", exc)
        return None, None, f"AI analysis failed: {type(exc).__name__}"


def audit(workflow_yaml: str) -> AuditReport:
    # 1. Redact FIRST: nothing downstream (AI, logs) ever sees raw secrets.
    redacted, redaction_count = redact_secrets(workflow_yaml)

    # 2. Deterministic checks: these are the source of truth.
    flags = run_deterministic_checks(redacted)
    rules_score = rules_risk_score(flags)
    status: Status = "PAUSED_FOR_HUMAN_REVIEW" if flags else "APPROVED"

    # 3. AI is advisory and can only make things stricter.
    ai_score, explanation, ai_error = call_ai(redacted, flags)
    risk_score = max(rules_score, ai_score or 0)  # AI can raise the score, never lower it
    if ai_score is not None and ai_score >= AI_RISK_THRESHOLD:
        status = "PAUSED_FOR_HUMAN_REVIEW"       # AI can escalate, never de-escalate
    # Invariant: a deterministic flag always means human review, whatever the AI said.
    if flags:
        status = "PAUSED_FOR_HUMAN_REVIEW"

    return AuditReport(
        status=status,
        risk_score=risk_score,
        flags=flags,
        redaction_count=redaction_count,
        ai_explanation=explanation,
        ai_used=ai_error is None,
        ai_error=ai_error,
        requires_human_approval=status == "PAUSED_FOR_HUMAN_REVIEW",
    )


def append_audit_log(tool: str, source: str, original: str, report: AuditReport) -> None:
    """Append one JSON line. Opened in 'a' mode (O_APPEND): we only ever add, never rewrite.

    We store a SHA-256 of the input, not the input itself, so secrets never land on disk.
    If the log can't be written, the error propagates: an audit we can't record fails closed.
    """
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": tool,
        "source": source,
        "input_sha256": hashlib.sha256(original.encode("utf-8")).hexdigest(),
        "status": report.status,
        "risk_score": report.risk_score,
        "flags": report.flags,
        "redaction_count": report.redaction_count,
        "ai_used": report.ai_used,
        "ai_error": report.ai_error,
    }
    line = json.dumps(entry, ensure_ascii=False) + "\n"
    with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as fh:
        fh.write(line)
        fh.flush()
        os.fsync(fh.fileno())


def resolve_fixture(name: str) -> Path:
    """Map a user-supplied name to a file strictly inside fixtures/, or raise ToolError (shown to the client)."""
    if not name or "\x00" in name:
        raise ToolError("Invalid fixture name.")
    candidate = Path(name)
    if candidate.is_absolute():
        raise ToolError("Absolute paths are not allowed.")
    # resolve() collapses '..' and follows symlinks, so both tricks are caught here.
    path = (FIXTURES_DIR / candidate).resolve()
    if not path.is_relative_to(FIXTURES_DIR):
        raise ToolError("Path traversal blocked: fixture must be inside fixtures/.")
    if path.suffix.lower() not in {".yml", ".yaml"}:
        raise ToolError("Only .yml/.yaml fixtures can be audited.")
    if not path.is_file():
        raise ToolError(f"Fixture not found. Available: {', '.join(list_fixtures())}")
    return path


def list_fixtures() -> list[str]:
    return sorted(p.name for p in FIXTURES_DIR.iterdir() if p.suffix.lower() in {".yml", ".yaml"})


def check_size(text: str) -> None:
    if len(text.encode("utf-8")) > MAX_INPUT_BYTES:
        raise ToolError(f"Workflow too large (max {MAX_INPUT_BYTES} bytes).")


# ---------------------------------------------------------------------------
# MCP server: the decorators below register the functions as MCP tools.
# The type hints become the input schema; the docstring is what the AI client reads.
# ---------------------------------------------------------------------------

server = MCPServer(
    name="uproot",
    instructions=(
        "Uproot audits GitHub Actions workflows for supply-chain attacks. "
        "If status is PAUSED_FOR_HUMAN_REVIEW, do not run or merge the workflow; ask a human."
    ),
)


@server.tool()
def audit_github_workflow(workflow_yaml: str) -> AuditReport:
    """Audit a GitHub Actions workflow YAML for supply-chain and prompt-injection risks.

    Secrets are redacted before analysis. Deterministic rules always win: any rule flag
    forces status PAUSED_FOR_HUMAN_REVIEW regardless of the AI's opinion.
    """
    check_size(workflow_yaml)
    report = audit(workflow_yaml)
    append_audit_log("audit_github_workflow", "inline", workflow_yaml, report)
    return report


@server.tool()
def audit_fixture(name: str) -> AuditReport:
    """Audit a workflow file from the project's fixtures/ directory by file name
    (e.g. 'safe_workflow.yml'). Only files inside fixtures/ can be read."""
    path = resolve_fixture(name)
    text = path.read_text(encoding="utf-8")
    check_size(text)
    report = audit(text)
    append_audit_log("audit_fixture", f"fixtures/{path.name}", text, report)
    return report


if __name__ == "__main__":
    server.run("stdio")
