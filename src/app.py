import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import pandas as pd
import streamlit as st
from src.ai_analyzer import analyze_workflow

st.set_page_config(
    page_title="Uproot | Zero-Trust AI Pipeline Gatekeeper",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    /* Global spacing & typography */
    .block-container {
        padding-top: 1.5rem;
        padding-bottom: 2.5rem;
        max-width: 1320px;
    }
    /* Hero Header Banner */
    .hero-banner {
        background: linear-gradient(135deg, #0F172A 0%, #112240 60%, #0A2E46 100%);
        border: 1px solid rgba(0, 188, 235, 0.35);
        border-radius: 14px;
        padding: 1.5rem 1.8rem;
        margin-bottom: 1.4rem;
        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.35);
    }
    .hero-badge {
        display: inline-block;
        background: rgba(0, 188, 235, 0.15);
        color: #38BDF8;
        border: 1px solid rgba(56, 189, 248, 0.4);
        font-size: 0.75rem;
        font-weight: 700;
        letter-spacing: 0.08em;
        padding: 0.22rem 0.65rem;
        border-radius: 999px;
        text-transform: uppercase;
        margin-bottom: 0.55rem;
    }
    .hero-title {
        font-size: 2.05rem;
        font-weight: 800;
        color: #F8FAFC;
        margin: 0;
        line-height: 1.2;
    }
    .hero-sub {
        color: #94A3B8;
        font-size: 0.98rem;
        margin-top: 0.4rem;
        margin-bottom: 0;
    }
    /* KPI Cards */
    .kpi-card {
        background: #0F172A;
        border: 1px solid #1E293B;
        border-radius: 12px;
        padding: 1.1rem 1.25rem;
        height: 100%;
    }
    .kpi-label {
        font-size: 0.78rem;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        color: #94A3B8;
        font-weight: 600;
        margin-bottom: 0.35rem;
    }
    .kpi-value {
        font-size: 1.55rem;
        font-weight: 800;
        color: #F8FAFC;
        line-height: 1.2;
    }
    .kpi-sub {
        font-size: 0.8rem;
        color: #64748B;
        margin-top: 0.25rem;
    }
    /* Status Pills */
    .pill-paused {
        background: rgba(239, 68, 68, 0.16);
        color: #FCA5A5;
        border: 1px solid rgba(239, 68, 68, 0.45);
        padding: 0.3rem 0.75rem;
        border-radius: 8px;
        font-weight: 700;
        display: inline-block;
    }
    .pill-approved {
        background: rgba(16, 185, 129, 0.16);
        color: #6EE7B7;
        border: 1px solid rgba(16, 185, 129, 0.45);
        padding: 0.3rem 0.75rem;
        border-radius: 8px;
        font-weight: 700;
        display: inline-block;
    }
    /* Finding Cards */
    .finding-box {
        background: #0F172A;
        border-left: 4px solid #F59E0B;
        border-top: 1px solid #1E293B;
        border-right: 1px solid #1E293B;
        border-bottom: 1px solid #1E293B;
        border-radius: 8px;
        padding: 0.75rem 1rem;
        margin-bottom: 0.55rem;
        font-size: 0.9rem;
    }
    .finding-critical {
        border-left-color: #EF4444;
    }
    /* Primary CTA Button */
    div.stButton > button[kind="primary"] {
        background: linear-gradient(90deg, #0284C7 0%, #00BCEB 100%);
        color: #04101E;
        font-weight: 700;
        border: none;
        border-radius: 8px;
        padding: 0.6rem 1.2rem;
    }
    div.stButton > button[kind="primary"]:hover {
        filter: brightness(1.08);
    }
</style>
""", unsafe_allow_html=True)

AUDIT_LOG_PATH = ROOT_DIR / "audit_log.jsonl"

SCENARIOS = {
    "1. Simulated Cisco/Trivy Breach (CVE-2026-33634)": ROOT_DIR / "fixtures" / "trivy_attack_workflow.yml",
    "2. Adversarial Prompt Injection Attack": ROOT_DIR / "fixtures" / "prompt_injection_workflow.yml",
    "3. Hardened & SHA-Pinned Safe Workflow": ROOT_DIR / "fixtures" / "safe_workflow.yml",
}


def _extract_findings(res) -> list[str]:
    for attr in ("rule_findings", "deterministic_findings", "findings", "rule_violations", "violations"):
        val = getattr(res, attr, None)
        if val is not None:
            return [str(x) for x in val]
    return []

def load_fixture(path: Path) -> str:
    if path.exists():
        return path.read_text(encoding="utf-8")
    return "name: Sample Workflow\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n"


def append_audit_log(entry: dict) -> None:
    with AUDIT_LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def read_audit_log() -> list[dict]:
    if not AUDIT_LOG_PATH.exists():
        return []
    rows = []
    for line in AUDIT_LOG_PATH.read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return list(reversed(rows))


# --- Sidebar Controls ---
with st.sidebar:
    st.markdown("### 🛡️ Uproot Control Plane")
    st.caption("Zero-Trust CI/CD & AI Agent Governance")
    st.divider()

    selected_scenario = st.selectbox(
        "Select Attack / Benchmark Scenario",
        list(SCENARIOS.keys()),
    )

    st.markdown("**Active Defense Layers**")
    st.markdown(
        "- 🔒 **Pre-AI Secret Scrubber** (`AKIA`, `ghp_`, keys)\n"
        "- 🧱 **Deterministic Guardrails** (SHA-pin & IOCs)\n"
        "- 🧬 **Sandboxed LLM** (`gpt-oss-120b` strict JSON)\n"
        "- 🧑‍⚖️ **Human-in-the-Loop Gate** (Quarantine / Approve)"
    )
    st.divider()
    st.caption("Modeled on the March 2026 Trivy / TeamPCP supply-chain compromise (`CVE-2026-33634`).")

# --- Hero Header ---
st.markdown("""
<div class="hero-banner">
    <div class="hero-badge">Zero-Trust Supply Chain &amp; AI Governance</div>
    <h1 class="hero-title">🛡️ Uproot Pipeline Gatekeeper</h1>
    <p class="hero-sub">
        Local secret redaction, deterministic CI/CD policy enforcement, sandboxed LLM risk scoring, and human-in-the-loop approval gates.
    </p>
</div>
""", unsafe_allow_html=True)

# --- Step 1: Workflow Inspector ---
st.markdown("#### 1. Untrusted CI/CD Workflow Payload")
default_yaml = load_fixture(SCENARIOS[selected_scenario])
workflow_yaml = st.text_area(
    "Inspect or edit raw GitHub Actions YAML before running the governed audit:",
    value=default_yaml,
    height=225,
    label_visibility="collapsed",
)

col_run, col_hint = st.columns([1.3, 2.7])
with col_run:
    run_clicked = st.button("🚀 Run Governed Security Audit", type="primary", width="stretch")
with col_hint:
    st.caption("Secrets are stripped locally in memory **before** any text leaves your environment to Groq.")

if run_clicked:
    with st.spinner("Running local secret scrubber, deterministic rule engine, and sandboxed AI audit..."):
        try:
            result = analyze_workflow(workflow_yaml)
            st.session_state["last_result"] = result
            st.session_state["last_raw_yaml"] = workflow_yaml
            st.session_state["last_scenario"] = selected_scenario
            if result.status == "APPROVED":
                append_audit_log({
                    "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "scenario": selected_scenario,
                    "risk_score": result.final_risk_score,
                    "secrets_redacted": result.secrets_redacted_count,
                    "decision": "AUTO_APPROVED_LOW_RISK",
                    "reviewer": "Uproot Policy Engine",
                })
        except Exception as exc:
            st.error(f"Audit failed: {exc}")

# --- Step 2 & 3: Audit Results + Human Governance Gate ---
if "last_result" in st.session_state:
    res = st.session_state["last_result"]
    is_paused = res.status != "APPROVED"
    score = res.final_risk_score

    st.divider()
    st.markdown("#### 2. Real-Time Security & Privacy Telemetry")

    k1, k2, k3, k4 = st.columns(4)
    with k1:
        pill_html = (
            '<span class="pill-paused">⛔ PAUSED (REVIEW)</span>'
            if is_paused
            else '<span class="pill-approved">✅ APPROVED</span>'
        )
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-label">Gatekeeper Status</div>
            <div style="margin-top:0.35rem;">{pill_html}</div>
            <div class="kpi-sub">Execution state</div>
        </div>
        """, unsafe_allow_html=True)

    with k2:
        score_color = "#EF4444" if score >= 70 else ("#F59E0B" if score >= 40 else "#10B981")
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-label">Composite Risk Score</div>
            <div class="kpi-value" style="color:{score_color};">{score} <span style="font-size:1rem;color:#64748B;">/ 100</span></div>
            <div class="kpi-sub">Max(Deterministic, AI)</div>
        </div>
        """, unsafe_allow_html=True)

    with k3:
        sec_color = "#38BDF8" if res.secrets_redacted_count > 0 else "#F8FAFC"
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-label">Secrets Redacted Pre-AI</div>
            <div class="kpi-value" style="color:{sec_color};">{res.secrets_redacted_count}</div>
            <div class="kpi-sub">Never sent to external LLM</div>
        </div>
        """, unsafe_allow_html=True)

    with k4:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-label">Deterministic Rule Hits</div>
            <div class="kpi-value">{len(_extract_findings(res))}</div>
            <div class="kpi-sub">Hard-coded policy checks</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("")
    left_col, right_col = st.columns([1.15, 1.0], gap="large")

    with left_col:
        st.markdown("##### 🧠 AI Risk Assessment & Deterministic Findings")
        if is_paused:
            st.error(f"**Executive Verdict:** {res.ai_summary}")
        else:
            st.success(f"**Executive Verdict:** {res.ai_summary}")

        findings = _extract_findings(res)
        if findings:
            st.markdown("**Triggered Hard-Coded Guardrails:**")
            for finding in findings:
                crit_cls = "finding-critical" if any(
                    tag in finding for tag in ["IOC", "INJECTION", "EXFIL", "REMOTE_CODE", "SECRET"]
                ) else ""
                st.markdown(f'<div class="finding-box {crit_cls}">⚠️ {finding}</div>', unsafe_allow_html=True)
        else:
            st.info("No hard-coded policy violations detected.")

    with right_col:
        st.markdown("##### 🔒 Pre-AI Sanitized Payload (Sent to Groq)")
        st.caption("Compare raw input vs. zero-trust scrubbed YAML transmitted over API:")
        tab_sanitized, tab_raw = st.tabs(["Sanitized YAML (Sent to LLM)", "Original Raw YAML"])
        with tab_sanitized:
            st.code(res.sanitized_yaml, language="yaml")
        with tab_raw:
            st.code(st.session_state.get("last_raw_yaml", ""), language="yaml")

    # --- Step 3: Human-in-the-Loop Gate ---
    st.divider()
    st.markdown("#### 3. Human-in-the-Loop Governance Gate")
    if is_paused:
        st.warning(
            "**Pipeline Halted:** High-risk supply-chain indicators or prompt-injection attempts require explicit human sign-off before execution."
        )
        g1, g2, g3 = st.columns([1.2, 1.2, 1.6])
        with g1:
            reviewer_name = st.text_input("Approver / Security Lead", value="Josiah (SecOps Lead)", label_visibility="collapsed")
        with g2:
            if st.button("🛑 Quarantine & Block Pipeline", type="primary", width="stretch"):
                append_audit_log({
                    "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "scenario": st.session_state.get("last_scenario", selected_scenario),
                    "risk_score": score,
                    "secrets_redacted": res.secrets_redacted_count,
                    "decision": "QUARANTINED_BLOCKED",
                    "reviewer": reviewer_name,
                })
                st.toast("Pipeline quarantined and logged to audit trail!", icon="🛑")
        with g3:
            if st.button("⚠️ Override & Approve Execution", width="stretch"):
                append_audit_log({
                    "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "scenario": st.session_state.get("last_scenario", selected_scenario),
                    "risk_score": score,
                    "secrets_redacted": res.secrets_redacted_count,
                    "decision": "HUMAN_OVERRIDE_APPROVED",
                    "reviewer": reviewer_name,
                })
                st.toast("Human override recorded in audit trail.", icon="⚠️")
    else:
        st.success("All deterministic guardrails and AI checks passed. Pipeline cleared for automated execution.")

# --- Step 4: Audit Trail ---
st.divider()
st.markdown("#### 4. Tamper-Evident Governance Audit Trail (`audit_log.jsonl`)")
logs = read_audit_log()
if logs:
    df = pd.DataFrame(logs)
    st.dataframe(df, width="stretch", hide_index=True)
else:
    st.caption("No governance events logged yet. Run an audit above to populate the immutable ledger.")
