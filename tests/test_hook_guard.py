"""Tests for the Claude Code PreToolUse hook (src/hook_guard.py). No network: the AI is disabled."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import src.hook_guard as hook

PROJECT_ROOT = Path(__file__).resolve().parent.parent
HOOK_SCRIPT = PROJECT_ROOT / "src" / "hook_guard.py"


@pytest.fixture
def wf_dir(tmp_path):
    d = tmp_path / "repo" / ".github" / "workflows"
    d.mkdir(parents=True)
    return d


def payload(tool_name, **tool_input):
    return {"hook_event_name": "PreToolUse", "tool_name": tool_name, "tool_input": tool_input}


def read_log(srv):
    path = srv.AUDIT_LOG_PATH
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


# --- Which files are watched ----------------------------------------------------------

@pytest.mark.parametrize("path", [
    "/repo/.github/workflows/ci.yml",
    "/repo/.github/workflows/ci.yaml",
    "/repo/.github/workflows/nested/deploy.YML",
    "C:\\repo\\.github\\workflows\\ci.yml",
    "/repo/.GitHub/Workflows/ci.yml",
])
def test_workflow_paths_are_watched(path):
    assert hook.is_workflow_path(path)


@pytest.mark.parametrize("path", [
    "/repo/src/app.py",
    "/repo/.github/workflows/README.md",
    "/repo/.github/dependabot.yml",
    "/repo/fixtures/safe_workflow.yml",
    "/repo/workflows/ci.yml",
])
def test_other_paths_are_ignored(path):
    assert not hook.is_workflow_path(path)


def test_symlink_into_workflows_is_watched(tmp_path, wf_dir):
    target = wf_dir / "ci.yml"
    target.write_text("x", encoding="utf-8")
    link = tmp_path / "innocent.txt"
    link.symlink_to(target)
    assert hook.is_workflow_path(str(link))


# --- Working out the new content ------------------------------------------------------

def test_edit_applies_single_replacement(wf_dir):
    f = wf_dir / "ci.yml"
    f.write_text("a: 1\nb: 2\n", encoding="utf-8")
    out = hook.proposed_content("Edit", {"file_path": str(f), "old_string": "b: 2", "new_string": "b: 3"})
    assert out == "a: 1\nb: 3\n"


def test_edit_replace_all(wf_dir):
    f = wf_dir / "ci.yml"
    f.write_text("x x x", encoding="utf-8")
    out = hook.proposed_content(
        "Edit", {"file_path": str(f), "old_string": "x", "new_string": "y", "replace_all": True})
    assert out == "y y y"


def test_edit_ambiguous_without_replace_all_is_an_error(wf_dir):
    f = wf_dir / "ci.yml"
    f.write_text("x x", encoding="utf-8")
    with pytest.raises(hook.GuardError, match="2 times"):
        hook.proposed_content("Edit", {"file_path": str(f), "old_string": "x", "new_string": "y"})


def test_edit_missing_old_string_is_an_error(wf_dir):
    f = wf_dir / "ci.yml"
    f.write_text("a", encoding="utf-8")
    with pytest.raises(hook.GuardError, match="not found"):
        hook.proposed_content("Edit", {"file_path": str(f), "old_string": "zzz", "new_string": "y"})


def test_edit_creating_new_file(wf_dir):
    f = wf_dir / "new.yml"
    out = hook.proposed_content("Edit", {"file_path": str(f), "old_string": "", "new_string": "on: push\n"})
    assert out == "on: push\n"


# --- Decisions --------------------------------------------------------------------------

def test_non_workflow_write_is_allowed_without_audit(srv):
    code, msg = hook.run(json.dumps(payload("Write", file_path="/repo/src/x.py", content="curl x | sh")))
    assert (code, msg) == (0, "")
    assert read_log(srv) == []  # nothing audited, nothing logged


def test_other_tools_are_ignored(srv):
    code, _ = hook.run(json.dumps(payload("Bash", command="ls")))
    assert code == 0


def test_safe_write_is_allowed_and_logged(srv, wf_dir, fixture_text):
    content = fixture_text("safe_workflow.yml")
    code, msg = hook.run(json.dumps(payload("Write", file_path=str(wf_dir / "ci.yml"), content=content)))
    assert (code, msg) == (0, "")
    [entry] = read_log(srv)
    assert entry["tool"] == "claude_code_hook"
    assert entry["status"] == "APPROVED"
    assert entry["source"].startswith("Write:")


@pytest.mark.parametrize("fixture, expected_flag", [
    ("trivy_attack_workflow.yml", "KNOWN_IOC_MATCH"),
    ("prompt_injection_workflow.yml", "REMOTE_CODE_EXECUTION"),
])
def test_risky_write_is_blocked_with_flags_and_score(srv, wf_dir, fixture_text, fixture, expected_flag):
    content = fixture_text(fixture)
    code, msg = hook.run(json.dumps(payload("Write", file_path=str(wf_dir / "ci.yml"), content=content)))
    assert code == 2
    assert "PAUSED_FOR_HUMAN_REVIEW" in msg
    assert "risk score" in msg and "/100" in msg
    assert expected_flag in msg
    [entry] = read_log(srv)
    assert entry["status"] == "PAUSED_FOR_HUMAN_REVIEW"
    assert content not in json.dumps(entry)  # only a hash of the content is logged


def test_secret_is_not_echoed_in_block_reason(srv, wf_dir, fixture_text):
    content = fixture_text("trivy_attack_workflow.yml")
    _, msg = hook.run(json.dumps(payload("Write", file_path=str(wf_dir / "ci.yml"), content=content)))
    assert "AKIA" not in msg


def test_edit_that_introduces_risk_is_blocked(srv, wf_dir, fixture_text):
    f = wf_dir / "ci.yml"
    f.write_text(fixture_text("safe_workflow.yml"), encoding="utf-8")
    p = payload("Edit", file_path=str(f),
                old_string="trivy-action@b6643a29fcbd7f34b6697dc2148d0a00882a27a3",
                new_string="trivy-action@0.28.0")
    code, msg = hook.run(json.dumps(p))
    assert code == 2
    assert "UNPINNED_ACTION" in msg
    assert f.read_text(encoding="utf-8") == fixture_text("safe_workflow.yml")  # hook never writes the file


def test_ai_escalation_blocks_even_without_rule_flags(srv, fake_ai, ai_report, wf_dir, fixture_text):
    fake_ai(lambda yaml: ai_report(90, "suspicious"))
    content = fixture_text("safe_workflow.yml")
    code, msg = hook.run(json.dumps(payload("Write", file_path=str(wf_dir / "ci.yml"), content=content)))
    assert code == 2
    assert "90/100" in msg
    assert "suspicious" not in msg  # AI text is never relayed to the agent


# --- Fail closed ------------------------------------------------------------------------

def test_invalid_json_blocks(srv):
    code, msg = hook.run("not json")
    assert code == 2
    assert "fail closed" in msg


def test_missing_content_blocks(srv, wf_dir):
    code, msg = hook.run(json.dumps(payload("Write", file_path=str(wf_dir / "ci.yml"))))
    assert code == 2
    assert "content" in msg


def test_unappliable_edit_blocks_and_is_logged(srv, wf_dir):
    f = wf_dir / "ci.yml"
    f.write_text("a", encoding="utf-8")
    code, msg = hook.run(json.dumps(payload("Edit", file_path=str(f), old_string="zzz", new_string="y")))
    assert code == 2
    [entry] = read_log(srv)
    assert entry["status"] == "BLOCKED_HOOK_ERROR"


def test_audit_crash_blocks(srv, monkeypatch, wf_dir):
    def boom(_):
        raise RuntimeError("kaboom")
    monkeypatch.setattr(srv, "audit", boom)
    code, msg = hook.run(json.dumps(payload("Write", file_path=str(wf_dir / "ci.yml"), content="on: push")))
    assert code == 2
    assert "kaboom" in msg


def test_unwritable_audit_log_blocks(srv, monkeypatch, wf_dir, fixture_text, tmp_path):
    monkeypatch.setattr(srv, "AUDIT_LOG_PATH", tmp_path / "missing_dir" / "log.jsonl")
    content = fixture_text("safe_workflow.yml")
    code, _ = hook.run(json.dumps(payload("Write", file_path=str(wf_dir / "ci.yml"), content=content)))
    assert code == 2  # an approval we can't record is not an approval


def test_oversized_content_blocks(srv, wf_dir):
    big = "a" * (srv.MAX_INPUT_BYTES + 1)
    code, msg = hook.run(json.dumps(payload("Write", file_path=str(wf_dir / "ci.yml"), content=big)))
    assert code == 2
    assert "too large" in msg


def test_main_crash_outside_run_blocks(monkeypatch, capsys):
    def explode(_):
        raise SystemExit(0)  # even a "successful" exit from inside the pipeline must not allow
    monkeypatch.setattr(hook, "run", explode)
    monkeypatch.setattr(sys, "stdin", __import__("io").StringIO("{}"))
    assert hook.main() == 2
    assert "blocked to be safe" in capsys.readouterr().err


# --- End to end: run the script exactly the way Claude Code does ------------------------

def run_script(stdin_text, tmp_path):
    env = {**os.environ, "AEGISGATE_AUDIT_LOG": str(tmp_path / "audit_log.jsonl"), "GROQ_API_KEY": ""}
    return subprocess.run(
        [sys.executable, str(HOOK_SCRIPT)], input=stdin_text, capture_output=True,
        text=True, env=env, cwd=tmp_path, timeout=60,
    )


def test_script_blocks_risky_workflow_with_exit_2(tmp_path, wf_dir, fixture_text):
    content = fixture_text("prompt_injection_workflow.yml")
    proc = run_script(json.dumps(payload("Write", file_path=str(wf_dir / "ci.yml"), content=content)), tmp_path)
    assert proc.returncode == 2
    assert proc.stderr.startswith("AegisGate blocked this Write")  # only our message, no log noise
    assert proc.stdout == ""
    assert (tmp_path / "audit_log.jsonl").exists()


def test_script_allows_ordinary_file_silently(tmp_path):
    proc = run_script(json.dumps(payload("Write", file_path=str(tmp_path / "notes.md"), content="hi")), tmp_path)
    assert (proc.returncode, proc.stdout, proc.stderr) == (0, "", "")


def test_script_fails_closed_on_garbage(tmp_path):
    proc = run_script("{{{", tmp_path)
    assert proc.returncode == 2
    assert "fail closed" in proc.stderr


# --- Bash: any mention of .github/workflows is blocked ---------------------------------

# The exact command that bypassed the Write/Edit hook when scan.yml was first created.
HEREDOC_BYPASS = """mkdir -p /home/richa/Uprooted-Hackathon/.github/workflows && cat > /home/richa/Uprooted-Hackathon/.github/workflows/scan.yml <<'EOF'
name: Security Scan

on:
  push:

jobs:
  trivy:
    runs-on: ubuntu-latest
    steps:
      - uses: aquasecurity/trivy-action@0.28.0
EOF
cat /home/richa/Uprooted-Hackathon/.github/workflows/scan.yml"""

BLOCKED_BASH_COMMANDS = [
    HEREDOC_BYPASS,
    "cat > .github/workflows/ci.yml <<EOF\non: push\nEOF",
    "echo 'on: push' > .github/workflows/ci.yml",
    "echo 'on: push' >> .github/workflows/ci.yml",
    "printf 'x' | tee .github/workflows/ci.yml",
    "cp /tmp/evil.yml .github/workflows/ci.yml",
    "mv /tmp/evil.yml .github/workflows/",
    "sed -i 's/@[0-9a-f]\\{40\\}/@main/' .github/workflows/ci.yml",
    "python3 -c \"open('.github/workflows/ci.yml','w').write('x')\"",
    "rm .github/workflows/ci.yml",
    "ls .github/workflows",                               # any mention, even read-only
    "git add .github/workflows/scan.yml",
    "cd .github && cat > workflows/ci.yml",               # split across the command
    "cat > .GitHub/Workflows/ci.yml",                     # case
    "cat > '.github'/\"workflows\"/ci.yml",                # quoting
    "cat > .git\"\"hub/work''flows/ci.yml",               # empty quotes inside a word
    "cat > .github\\/workflows/ci.yml",                   # backslash escape
    "cat > .github//workflows/ci.yml",                    # doubled slash
    "cat > .github/./workflows/ci.yml",                   # dot segment
    "cat > .git*/work*/ci.yml",                           # glob
    "cp x .gith?b/workflow[s]/ci.yml",                    # glob with ? and []
    "cp x */workflows/ci.yml",                            # glob for .github
    "cp x .github/*/ci.yml",                              # glob for workflows
    "type nul > .github\\workflows\\ci.yml",              # Windows separators
]


@pytest.mark.parametrize("command", BLOCKED_BASH_COMMANDS)
def test_bash_mentioning_workflows_is_blocked(srv, command):
    code, msg = hook.run(json.dumps(payload("Bash", command=command)))
    assert code == 2
    assert msg == hook.BASH_BLOCK_MESSAGE
    assert msg == ("Workflow files can only be changed with the Write or Edit tool "
                   "so AegisGate can audit them.")


@pytest.mark.parametrize("command", [
    "ls",
    "cat README.md",
    ".venv/bin/python -m pytest -q",
    "git status",
    "cat > fixtures/new_workflow.yml <<EOF\non: push\nEOF",  # fixtures are not live workflows
    "ls .github",
    "echo workflows",
    "ls */*",
    "cp a.txt b.txt",
])
def test_bash_not_touching_workflows_is_allowed(srv, command):
    code, msg = hook.run(json.dumps(payload("Bash", command=command)))
    assert (code, msg) == (0, "")
    assert read_log(srv) == []


def test_heredoc_bypass_is_blocked_and_logged_without_command_text(srv):
    code, _ = hook.run(json.dumps(payload("Bash", command=HEREDOC_BYPASS)))
    assert code == 2
    [entry] = read_log(srv)
    assert entry["status"] == "BLOCKED_BASH_WORKFLOW"
    assert entry["source"] == "Bash:None"
    assert len(entry["input_sha256"]) == 64
    assert "trivy-action" not in json.dumps(entry)  # only a hash of the command is logged


def test_bash_without_command_fails_closed(srv):
    code, msg = hook.run(json.dumps(payload("Bash", description="no command")))
    assert code == 2
    assert "fail closed" in msg


def test_bash_block_still_applies_if_log_is_unwritable(srv, monkeypatch, tmp_path):
    monkeypatch.setattr(srv, "AUDIT_LOG_PATH", tmp_path / "missing_dir" / "log.jsonl")
    code, _ = hook.run(json.dumps(payload("Bash", command=HEREDOC_BYPASS)))
    assert code == 2


def test_settings_run_hook_on_write_edit_and_bash():
    settings = json.loads((PROJECT_ROOT / ".claude" / "settings.json").read_text(encoding="utf-8"))
    [entry] = settings["hooks"]["PreToolUse"]
    assert set(entry["matcher"].split("|")) == {"Write", "Edit", "Bash"}


def test_script_blocks_heredoc_bypass_with_exit_2(tmp_path):
    proc = run_script(json.dumps(payload("Bash", command=HEREDOC_BYPASS)), tmp_path)
    assert proc.returncode == 2
    assert proc.stderr.strip() == hook.BASH_BLOCK_MESSAGE
    assert proc.stdout == ""


def test_script_allows_ordinary_bash_silently(tmp_path):
    proc = run_script(json.dumps(payload("Bash", command="git status")), tmp_path)
    assert (proc.returncode, proc.stdout, proc.stderr) == (0, "", "")
