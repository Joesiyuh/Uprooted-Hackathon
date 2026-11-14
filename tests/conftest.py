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
    """Install a fake ai_analyzer.analyze_workflow: fake_ai(lambda yaml, flags: {...})."""
    import types

    def install(fn):
        monkeypatch.setattr(srv, "ai_analyzer", types.SimpleNamespace(analyze_workflow=fn))

    return install


@pytest.fixture
def fixture_text():
    return lambda name: (PROJECT_ROOT / "fixtures" / name).read_text(encoding="utf-8")
