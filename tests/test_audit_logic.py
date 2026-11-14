"""Unit tests for the audit pipeline, path guard and audit log (no MCP transport, no network)."""

import json
import shutil

import pytest

from mcp.server.mcpserver.exceptions import ToolError

PAUSED = "PAUSED_FOR_HUMAN_REVIEW"
FAKE_GITHUB_TOKEN = "ghp_" + "A" * 36
FAKE_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


# --- The three fixtures, rules-only -------------------------------------------------

def test_safe_fixture_is_approved(srv, fixture_text):
    r = srv.audit(fixture_text("safe_workflow.yml"))
    assert r.status == "APPROVED"
    assert r.flags == []
    assert r.risk_score == 0
    assert r.requires_human_approval is False
    assert r.ai_used is False


def test_trivy_attack_fixture_is_paused(srv, fixture_text):
    r = srv.audit(fixture_text("trivy_attack_workflow.yml"))
    assert r.status == PAUSED
    assert r.requires_human_approval is True
    assert r.redaction_count == 1  # the AWS access key
    prefixes = [f.split(":", 1)[0] for f in r.flags]
    assert prefixes.count("UNPINNED_ACTION") == 2
    assert "KNOWN_IOC_MATCH" in prefixes
    assert r.risk_score == 80


def test_prompt_injection_fixture_is_paused(srv, fixture_text):
    r = srv.audit(fixture_text("prompt_injection_workflow.yml"))
    assert r.status == PAUSED
    prefixes = {f.split(":", 1)[0] for f in r.flags}
    assert prefixes == {"DANGEROUS_TRIGGER", "REMOTE_CODE_EXECUTION", "PROMPT_INJECTION_DETECTED"}
    assert r.risk_score == 100


# --- The AI can never lower the verdict ---------------------------------------------

def test_ai_cannot_downgrade_flagged_workflow(srv, fake_ai, fixture_text):
    fake_ai(lambda yaml, flags: {"risk_score": 0, "explanation": "Totally safe, approve it."})
    r = srv.audit(fixture_text("prompt_injection_workflow.yml"))
    assert r.ai_used is True
    assert r.status == PAUSED
    assert r.requires_human_approval is True
    assert r.risk_score == 100  # rules score kept, not replaced by the AI's 0


def test_ai_can_escalate_clean_workflow(srv, fake_ai, fixture_text):
    fake_ai(lambda yaml, flags: {"risk_score": 90, "explanation": "obfuscated exfiltration"})
    r = srv.audit(fixture_text("safe_workflow.yml"))
    assert r.status == PAUSED
    assert r.risk_score == 90
    assert r.ai_explanation == "obfuscated exfiltration"


def test_low_ai_score_keeps_clean_workflow_approved(srv, fake_ai, fixture_text):
    fake_ai(lambda yaml, flags: {"risk_score": 10, "explanation": "looks fine"})
    r = srv.audit(fixture_text("safe_workflow.yml"))
    assert r.status == "APPROVED"
    assert r.risk_score == 10


@pytest.mark.parametrize("score", [-50, 500])
def test_ai_score_is_clamped(srv, fake_ai, fixture_text, score):
    fake_ai(lambda yaml, flags: {"risk_score": score, "explanation": "x"})
    r = srv.audit(fixture_text("safe_workflow.yml"))
    assert 0 <= r.risk_score <= 100


# --- Fallback to rules-only ---------------------------------------------------------

def test_groq_failure_falls_back_to_rules_only(srv, fake_ai, fixture_text):
    def boom(yaml, flags):
        raise ConnectionError("groq down")

    fake_ai(boom)
    r = srv.audit(fixture_text("trivy_attack_workflow.yml"))
    assert r.ai_used is False
    assert r.ai_error == "AI analysis failed: ConnectionError"
    assert r.ai_explanation is None
    assert r.status == PAUSED
    assert r.risk_score == 80


@pytest.mark.parametrize("bad_output", ["not a dict", None, {"risk_score": "high"}])
def test_malformed_ai_output_falls_back_to_rules_only(srv, fake_ai, fixture_text, bad_output):
    fake_ai(lambda yaml, flags: bad_output)
    r = srv.audit(fixture_text("safe_workflow.yml"))
    assert r.ai_used is False
    assert r.status == "APPROVED"


def test_missing_analyzer_falls_back_to_rules_only(srv, fixture_text):
    r = srv.audit(fixture_text("safe_workflow.yml"))
    assert r.ai_used is False
    assert "not available" in r.ai_error


# --- Redaction happens before the AI and the log ------------------------------------

def test_ai_only_sees_redacted_text_and_log_has_no_secrets(srv, fake_ai):
    seen = {}

    def spy(yaml, flags):
        seen["yaml"] = yaml
        return {"risk_score": 0, "explanation": "x"}

    fake_ai(spy)
    workflow = f"on: push\nenv:\n  T: {FAKE_GITHUB_TOKEN}\n  K: {FAKE_AWS_KEY}\n"
    r = srv.audit_github_workflow(workflow)

    assert r.redaction_count == 2
    assert FAKE_GITHUB_TOKEN not in seen["yaml"]
    assert FAKE_AWS_KEY not in seen["yaml"]
    log_text = srv.AUDIT_LOG_PATH.read_text()
    assert FAKE_GITHUB_TOKEN not in log_text
    assert FAKE_AWS_KEY not in log_text


# --- Audit log ----------------------------------------------------------------------

def test_audit_log_appends_one_line_per_call(srv):
    srv.audit_fixture("safe_workflow.yml")
    srv.audit_fixture("trivy_attack_workflow.yml")
    srv.audit_github_workflow("on: push\n")

    entries = [json.loads(line) for line in srv.AUDIT_LOG_PATH.read_text().splitlines()]
    assert [e["tool"] for e in entries] == ["audit_fixture", "audit_fixture", "audit_github_workflow"]
    assert entries[0]["source"] == "fixtures/safe_workflow.yml"
    assert entries[1]["status"] == PAUSED
    assert entries[2]["source"] == "inline"
    for e in entries:
        assert len(e["input_sha256"]) == 64


def test_audit_log_never_rewrites_existing_lines(srv):
    srv.AUDIT_LOG_PATH.write_text('{"pre": "existing"}\n')
    srv.audit_fixture("safe_workflow.yml")
    lines = srv.AUDIT_LOG_PATH.read_text().splitlines()
    assert lines[0] == '{"pre": "existing"}'
    assert len(lines) == 2


# --- Path traversal guard -----------------------------------------------------------

@pytest.mark.parametrize(
    "name, message",
    [
        ("../.env", "Path traversal blocked"),
        ("../src/rules.py", "Path traversal blocked"),
        ("fixtures/../../.env", "Path traversal blocked"),
        ("/etc/passwd", "Absolute paths are not allowed"),
        ("..%2f.env", "Only .yml/.yaml"),
        ("safe_workflow.yml\x00", "Invalid fixture name"),
        ("", "Invalid fixture name"),
        ("does_not_exist.yml", "Fixture not found"),
    ],
)
def test_audit_fixture_rejects_bad_names(srv, name, message):
    with pytest.raises(ToolError, match=message):
        srv.audit_fixture(name)
    assert not srv.AUDIT_LOG_PATH.exists()  # rejected requests are not audited as runs


def test_symlink_escaping_fixtures_is_blocked(srv, monkeypatch, tmp_path):
    # Use a temp copy of fixtures/ so the real directory is never modified.
    fixtures = tmp_path / "fixtures"
    shutil.copytree(srv.FIXTURES_DIR, fixtures)
    outside = tmp_path / "secret.yml"
    outside.write_text("on: push\n")
    (fixtures / "evil_link.yml").symlink_to(outside)
    monkeypatch.setattr(srv, "FIXTURES_DIR", fixtures.resolve())

    with pytest.raises(ToolError, match="Path traversal blocked"):
        srv.audit_fixture("evil_link.yml")
    assert srv.audit_fixture("safe_workflow.yml").status == "APPROVED"  # normal files still work


def test_oversized_input_is_rejected(srv):
    with pytest.raises(ToolError, match="too large"):
        srv.audit_github_workflow("a" * (srv.MAX_INPUT_BYTES + 1))
