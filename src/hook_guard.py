"""Claude Code PreToolUse hook: AegisGate must approve any change to a GitHub Actions workflow.

Claude Code runs this script before every Write, Edit or Bash tool call (see .claude/settings.json).
It receives the tool call as JSON on stdin and answers with its exit code:

  exit 0 -> no objection; Claude Code carries on with its normal permission checks
  exit 2 -> BLOCK the tool call; whatever we print to stderr is shown to the agent as the reason

Bash: a shell command that mentions .github/workflows in any way is blocked outright. Shell
writes (cat > file, tee, cp, sed -i, python -c, ...) can't be audited reliably, so workflow
changes must go through Write/Edit, where the full new content is known and audited below.

Write/Edit flow:
  1. Ignore anything that is not a .yml/.yaml file under .github/workflows/ (exit 0, fast).
  2. Work out the full file content the agent is about to produce
     (Write: the new content; Edit: the current file with the replacement applied).
  3. Run the same audit() the MCP server uses and append the decision to audit_log.jsonl.
  4. PAUSED_FOR_HUMAN_REVIEW (or anything other than APPROVED) -> block. APPROVED -> exit 0.

Fail closed: if anything goes wrong (bad input, Edit that can't be applied, audit crash,
log can't be written), we block. Note that a plain crash of Python itself would normally be a
*non*-blocking error in Claude Code; `"onFailure": "block"` in settings.json covers that case.

We deliberately never return permissionDecision "allow": that would skip the user's normal
permission prompt. Approval here only means "AegisGate has no objection".
"""

from __future__ import annotations

import contextlib
import fnmatch
import hashlib
import io
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

SRC_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SRC_DIR.parent
if str(PROJECT_ROOT) not in sys.path:  # so `import src.mcp_server` works when run as a script
    sys.path.insert(0, str(PROJECT_ROOT))

WATCHED_TOOLS = {"Write", "Edit"}
SHELL_TOOLS = {"Bash"}
BASH_BLOCK_MESSAGE = (
    "Workflow files can only be changed with the Write or Edit tool so AegisGate can audit them."
)
WORKFLOW_SUFFIXES = {".yml", ".yaml"}
MAX_FLAG_CHARS = 300  # keep the reason shown to the agent short
BLOCK = 2
ALLOW = 0


class GuardError(Exception):
    """A problem we can describe to the agent (always results in a block)."""


# ---------------------------------------------------------------------------
# Step 1: is this file a GitHub Actions workflow?
# ---------------------------------------------------------------------------

def _looks_like_workflow(path_text: str) -> bool:
    p = PurePosixPath(path_text.replace("\\", "/"))  # Windows paths arrive with backslashes
    if p.suffix.lower() not in WORKFLOW_SUFFIXES:
        return False
    dirs = [part.lower() for part in p.parts[:-1]]
    return any(dirs[i] == ".github" and dirs[i + 1] == "workflows" for i in range(len(dirs) - 1))


def is_workflow_path(file_path: str) -> bool:
    """True for <anything>/.github/workflows/<...>.yml|.yaml.

    Checks both the path as given and the real path after following symlinks, so writing
    through a symlink that points into .github/workflows/ is still caught.
    """
    if _looks_like_workflow(file_path):
        return True
    try:
        return _looks_like_workflow(str(Path(file_path).resolve()))
    except (OSError, RuntimeError):
        return False


# ---------------------------------------------------------------------------
# Bash: does the command touch .github/workflows in any way?
# ---------------------------------------------------------------------------

_SHELL_QUOTING = re.compile(r"""['"`\\]""")  # quotes, backticks, backslashes
_GLOB_CHARS = set("*?[")
_PURE_WILDCARD = re.compile(r"^[*?]+$")


def _normalize_command(command: str) -> str:
    """Undo cheap shell obfuscation: case, quoting/escaping, `//` and `/./` path segments."""
    s = _SHELL_QUOTING.sub("", command.lower())
    s = re.sub(r"/+", "/", s)
    while "/./" in s:
        s = s.replace("/./", "/")
    return s


def _glob_reaches_workflows(normalized: str) -> bool:
    """True if a glob such as `.git*/work*` or `*/workflows/x.yml` could expand into the folder."""
    for token in re.split(r"[\s;&|<>()=,]+", normalized):
        if not _GLOB_CHARS & set(token):
            continue
        parts = token.split("/")
        for a, b in zip(parts, parts[1:]):
            if _PURE_WILDCARD.match(a) and _PURE_WILDCARD.match(b):
                continue  # `*/*` alone is too broad to call a mention
            if fnmatch.fnmatchcase(".github", a) and fnmatch.fnmatchcase("workflows", b):
                return True
    return False


def command_mentions_workflows(command: str) -> bool:
    """True if a shell command refers to .github/workflows, however it is spelled.

    Deliberately broad: `.github` and `workflows` anywhere in the same command count, so
    `cd .github && cat > workflows/x.yml` is caught too. This also blocks harmless commands
    such as `ls .github/workflows` or `git add .github/workflows/...` - that is the trade-off
    for not having to understand every way a shell can write a file.
    """
    s = _normalize_command(command)
    if ".github" in s and "workflows" in s:
        return True
    return _glob_reaches_workflows(s)


# ---------------------------------------------------------------------------
# Step 2: what will the file look like after this tool call?
# ---------------------------------------------------------------------------

def _require_str(tool_input: dict, key: str) -> str:
    value = tool_input.get(key)
    if not isinstance(value, str):
        raise GuardError(f"tool_input.{key} is missing or not a string")
    return value


def proposed_content(tool_name: str, tool_input: dict) -> str:
    """Return the full file content the agent is about to write."""
    if tool_name == "Write":
        return _require_str(tool_input, "content")

    # Edit: apply old_string -> new_string to the current file, the same way the Edit tool does.
    path = Path(_require_str(tool_input, "file_path"))
    old = _require_str(tool_input, "old_string")
    new = _require_str(tool_input, "new_string")
    replace_all = tool_input.get("replace_all") is True

    if not path.exists():
        if old == "":
            return new  # Edit with an empty old_string creates a new file
        raise GuardError(f"cannot apply Edit: {path.name} does not exist")
    current = path.read_text(encoding="utf-8")
    if old == "":
        raise GuardError("cannot apply Edit: old_string is empty but the file already exists")
    count = current.count(old)
    if count == 0:
        raise GuardError(
            "cannot apply Edit: old_string was not found exactly in the current file "
            "(use Write with the full file content instead)"
        )
    if count > 1 and not replace_all:
        raise GuardError(f"cannot apply Edit: old_string occurs {count} times and replace_all is false")
    return current.replace(old, new) if replace_all else current.replace(old, new, 1)


# ---------------------------------------------------------------------------
# Step 3 + 4: audit, log, decide
# ---------------------------------------------------------------------------

def _display_path(file_path: str) -> str:
    try:
        return Path(file_path).resolve().relative_to(PROJECT_ROOT).as_posix()
    except (ValueError, OSError, RuntimeError):
        return file_path


def block_reason(tool_name: str, shown_path: str, report) -> str:
    lines = [
        f"AegisGate blocked this {tool_name} to {shown_path}: "
        f"status {report.status}, risk score {report.risk_score}/100.",
    ]
    if report.flags:
        lines.append("Flags:")
        for flag in report.flags:
            text = flag if len(flag) <= MAX_FLAG_CHARS else flag[:MAX_FLAG_CHARS] + "..."
            lines.append(f"- {text}")
    else:
        lines.append("No rule flags; the AI review raised the risk score above the threshold.")
    # The AI explanation is not included on purpose: it is derived from the (possibly hostile)
    # workflow text and could carry prompt-injection back to the agent.
    lines.append("Do not work around this check. Fix the issues above or ask a human to review the workflow.")
    return "\n".join(lines)


def evaluate(payload: dict) -> tuple[int, str]:
    """Decide on one tool call. Returns (exit_code, message for the agent)."""
    if not isinstance(payload, dict):
        raise GuardError("hook input is not a JSON object")
    tool_name = payload.get("tool_name")
    if tool_name not in WATCHED_TOOLS and tool_name not in SHELL_TOOLS:
        return ALLOW, ""
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        raise GuardError("tool_input is missing or not an object")

    if tool_name in SHELL_TOOLS:
        command = _require_str(tool_input, "command")
        if not command_mentions_workflows(command):
            return ALLOW, ""
        log_block(payload, "BLOCKED_BASH_WORKFLOW", BASH_BLOCK_MESSAGE)
        return BLOCK, BASH_BLOCK_MESSAGE

    file_path = _require_str(tool_input, "file_path")
    if not is_workflow_path(file_path):
        return ALLOW, ""  # not a workflow: nothing to audit

    content = proposed_content(tool_name, tool_input)

    # Imported only now, so ordinary file edits stay fast and don't depend on the MCP stack.
    from src import mcp_server

    shown_path = _display_path(file_path)
    mcp_server.check_size(content)  # raises ToolError for oversized input -> blocked
    report = mcp_server.audit(content)
    mcp_server.append_audit_log("claude_code_hook", f"{tool_name}:{shown_path}", content, report)

    if report.status == "APPROVED":
        return ALLOW, ""
    return BLOCK, block_reason(tool_name, shown_path, report)


def log_block(payload: object, status: str, message: str) -> None:
    """Best-effort audit-log entry for a block decided without an audit report.

    The decision is a block whether or not this entry can be written. For Bash we log a
    hash of the command, never the command itself (it may contain secrets).
    """
    try:
        from src import mcp_server
        log_path = mcp_server.AUDIT_LOG_PATH
    except Exception:
        log_path = Path(os.environ.get("AEGISGATE_AUDIT_LOG", PROJECT_ROOT / "audit_log.jsonl"))
    tool_input = payload.get("tool_input") if isinstance(payload, dict) else None
    file_path = tool_input.get("file_path") if isinstance(tool_input, dict) else None
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    tool_name = payload.get("tool_name") if isinstance(payload, dict) else None
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": "claude_code_hook",
        "source": f"{tool_name}:{_display_path(file_path) if isinstance(file_path, str) else None}",
        "input_sha256": (
            hashlib.sha256(command.encode("utf-8")).hexdigest() if isinstance(command, str) else None
        ),
        "status": status,
        "error": message,
    }
    try:
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass


def run(stdin_text: str) -> tuple[int, str]:
    """Parse the hook input and decide. Never raises: any failure becomes a block."""
    payload: object = None
    try:
        payload = json.loads(stdin_text)
        return evaluate(payload)
    except Exception as exc:
        detail = str(exc) if isinstance(exc, GuardError) else f"{type(exc).__name__}: {exc}"
        message = (
            f"AegisGate hook could not audit this workflow change, so it was blocked to be safe "
            f"(fail closed). Reason: {detail}"
        )
        log_block(payload, "BLOCKED_HOOK_ERROR", message)
        return BLOCK, message


def main() -> int:
    real_stderr = sys.stderr
    stdin_text = sys.stdin.read()
    # Anything the audit pipeline prints or logs is captured here, so the agent only sees
    # our one clear message (stderr is what Claude Code shows it on a block).
    noise = io.StringIO()
    try:
        with contextlib.redirect_stdout(noise), contextlib.redirect_stderr(noise):
            code, message = run(stdin_text)
    except BaseException as exc:  # e.g. SystemExit/KeyboardInterrupt inside the pipeline
        code, message = BLOCK, f"AegisGate hook crashed ({type(exc).__name__}); blocked to be safe."
    if code != ALLOW and message:
        print(message, file=real_stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())
