import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import src.mcp_server as server_module  # noqa: E402


@pytest.fixture
def anyio_backend():
    # Async tests (the stdio end-to-end ones) run on asyncio via anyio's pytest plugin.
    return "asyncio"


@pytest.fixture
def srv(monkeypatch, tmp_path):
    """The server module, isolated for one test:
    - audit log goes to a temp file, never the real audit_log.jsonl
    - no AI by default, so tests never call Groq (use `fake_ai` to plug one in)
    """
    monkeypatch.setattr(server_module, "AUDIT_LOG_PATH", tmp_path / "audit_log.jsonl")
    monkeypatch.setattr(server_module, "ai_analyzer", None)
    return server_module


@pytest.fixture
def fake_ai(srv, monkeypatch):
    """Install a fake ai_analyzer.analyze_workflow: fake_ai(lambda yaml: ai_report(...)).

    Mirrors the teammate's real signature: analyze_workflow(workflow_yaml) -> GovernedAuditReport.
    """
    import types

    def install(fn):
        monkeypatch.setattr(srv, "ai_analyzer", types.SimpleNamespace(analyze_workflow=fn))

    return install


@pytest.fixture
def ai_report():
    """Build an object shaped like ai_analyzer.GovernedAuditReport (only the fields call_ai reads)."""
    import types

    def make(score, summary="x", fix=""):
        return types.SimpleNamespace(ai_raw_risk_score=score, ai_summary=summary, recommended_fix=fix)

    return make


@pytest.fixture
def fixture_text():
    return lambda name: (PROJECT_ROOT / "fixtures" / name).read_text(encoding="utf-8")
