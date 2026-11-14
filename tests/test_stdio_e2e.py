"""End-to-end: launch src/mcp_server.py as a real subprocess over stdio, like an MCP client would.

Runs from a temp working directory to prove the server works from anywhere, and points
AEGISGATE_AUDIT_LOG at a temp file so the real audit log is untouched.

Note: these tests use whatever ai_analyzer.py contains. Assertions only check what the
deterministic rules guarantee, so they hold with or without a working Groq connection.
"""

import json
import os
import sys
from pathlib import Path

import pytest

from mcp.client import Client
from mcp.client.stdio import StdioServerParameters

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SERVER = PROJECT_ROOT / "src" / "mcp_server.py"
PAUSED = "PAUSED_FOR_HUMAN_REVIEW"

pytestmark = pytest.mark.anyio


@pytest.fixture
def params(tmp_path):
    log = tmp_path / "audit_log.jsonl"
    workdir = tmp_path / "elsewhere"
    workdir.mkdir()
    return (
        StdioServerParameters(
            command=sys.executable,
            args=[str(SERVER)],
            cwd=str(workdir),
            env={**os.environ, "AEGISGATE_AUDIT_LOG": str(log)},
        ),
        log,
    )


async def test_lists_both_tools_with_output_schema(params):
    server_params, _ = params
    async with Client(server_params) as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
    assert set(tools) == {"audit_github_workflow", "audit_fixture"}
    for tool in tools.values():
        assert tool.output_schema is not None
        assert "status" in tool.output_schema["properties"]


@pytest.mark.parametrize(
    "fixture, expected_status, min_risk, expected_redactions",
    [
        ("safe_workflow.yml", None, 0, 0),  # status depends on the AI once it exists
        ("trivy_attack_workflow.yml", PAUSED, 80, 1),
        ("prompt_injection_workflow.yml", PAUSED, 100, 0),
    ],
)
async def test_audit_fixture_over_stdio(params, fixture, expected_status, min_risk, expected_redactions):
    server_params, log = params
    async with Client(server_params) as client:
        result = await client.call_tool("audit_fixture", {"name": fixture})

    assert not result.is_error
    report = result.structured_content
    assert report["risk_score"] >= min_risk
    assert report["redaction_count"] == expected_redactions
    if expected_status:
        assert report["status"] == expected_status
        assert report["requires_human_approval"] is True
    else:
        assert report["flags"] == []

    entries = [json.loads(line) for line in log.read_text().splitlines()]
    assert len(entries) == 1
    assert entries[0]["source"] == f"fixtures/{fixture}"


async def test_audit_github_workflow_over_stdio(params):
    server_params, _ = params
    workflow = (PROJECT_ROOT / "fixtures" / "prompt_injection_workflow.yml").read_text()
    async with Client(server_params) as client:
        result = await client.call_tool("audit_github_workflow", {"workflow_yaml": workflow})
    assert not result.is_error
    assert result.structured_content["status"] == PAUSED


@pytest.mark.parametrize("name", ["../.env", "/etc/passwd", "fixtures/../../.env"])
async def test_traversal_is_a_visible_tool_error(params, name):
    server_params, _ = params
    async with Client(server_params) as client:
        result = await client.call_tool("audit_fixture", {"name": name})
    assert result.is_error
    text = result.content[0].text
    assert "not allowed" in text or "traversal blocked" in text
    assert "GROQ_API_KEY" not in text  # no file contents leak back
