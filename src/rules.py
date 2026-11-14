import re
from typing import List, Tuple

# Known indicators from the March 2026 Trivy / TeamPCP supply-chain breach
KNOWN_IOCS = [
    "aquasecurtiy",       # Typosquatted exfiltration domain (scan.aquasecurtiy.org)
    "tpcp-docs",          # Rogue GitHub repository created by TeamPCP malware
    "canisterworm",       # Payload family linked to the campaign
]

def redact_secrets(content: str) -> Tuple[str, int]:
    """
    Strips cloud keys and tokens BEFORE any AI model ever sees the file.
    Returns (redacted_text, redaction_count).
    """
    count = 0

    patterns = [
        (r"AKIA[0-9A-Z]{16}", "[REDACTED_AWS_ACCESS_KEY]"),
        (r"(?i)(aws_secret_access_key\s*[:=]\s*)['\"]?[A-Za-z0-9/+=]{40}['\"]?", r"\1[REDACTED_AWS_SECRET]"),
        (r"gh[pousr]_[A-Za-z0-9_]{36,}", "[REDACTED_GITHUB_TOKEN]"),
        (r"gsk_[A-Za-z0-9]{48,}", "[REDACTED_GROQ_KEY]"),
        (r"sk-[A-Za-z0-9\-_]{32,}", "[REDACTED_API_KEY]"),
    ]

    redacted = content
    for pattern, replacement in patterns:
        redacted, n = re.subn(pattern, replacement, redacted)
        count += n

    return redacted, count


def run_deterministic_checks(yaml_text: str) -> List[str]:
    """
    Hard-coded supply-chain and prompt-injection checks.
    These rules act as a deterministic override over the LLM.
    """
    flags: List[str] = []

    # 1. Unpinned GitHub Actions (Exact Trivy CVE-2026-33634 tag-hijacking vector)
    uses_matches = re.findall(r"uses:\s*([^\s@]+)@([^\s#]+)", yaml_text)
    for action, ref in uses_matches:
        if not re.fullmatch(r"[0-9a-f]{40}", ref):
            flags.append(
                f"UNPINNED_ACTION: '{action}@{ref}' uses a mutable tag/branch instead of a 40-char commit SHA."
            )

    # 2. Dangerous PR trigger that exposes repository secrets to untrusted pull requests
    if re.search(r"\bpull_request_target\b", yaml_text):
        flags.append(
            "DANGEROUS_TRIGGER: 'pull_request_target' grants write permissions and secret access to untrusted PRs."
        )

    # 3. Direct indicators of compromise from the Trivy / TeamPCP campaign
    lower_text = yaml_text.lower()
    for ioc in KNOWN_IOCS:
        if ioc in lower_text:
            flags.append(
                f"KNOWN_IOC_MATCH: Detected '{ioc}', matching known TeamPCP/Trivy supply-chain exfiltration infrastructure."
            )

    # 4. Suspicious curl/wget pipe-to-shell or outbound IP exfiltration
    if re.search(r"(curl|wget)\s+[^\n]*\|\s*(sh|bash)", yaml_text):
        flags.append(
            "REMOTE_CODE_EXECUTION: Piping remote script directly into shell (curl/wget | sh)."
        )

    # 5. Prompt injection attempts trying to manipulate the AI auditor
    injection_patterns = [
        r"ignore\s+(all\s+)?previous\s+instructions",
        r"mark\s+this\s+(workflow|file|code)\s+as\s+safe",
        r"system\s+override",
    ]
    for pat in injection_patterns:
        if re.search(pat, lower_text):
            flags.append(
                "PROMPT_INJECTION_DETECTED: Workflow contains instructions attempting to manipulate AI safety evaluation."
            )
            break

    return flags
