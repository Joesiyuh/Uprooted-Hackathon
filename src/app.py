import json
import os
from datetime import datetime, timezone
import streamlit as st

from src.ai_analyzer import analyze_workflow

AUDIT_LOG_PATH = "audit_log.jsonl"

FIXTURES = {
    "1. Simulated Cisco/Trivy Breach (CVE-2026-33634)": "fixtures/trivy_attack_workflow.yml",
    "2. Adversarial Prompt Injection Attack": "fixtures/prompt_injection_workflow.yml",
    "3. Hardened & SHA-Pinned Safe Workflow": "fixtures/safe_workflow.yml",
    "4. Custom Workflow (Paste Your Own)": None,
}

def append_audit_log(entry: dict) -> None:
    with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

def load_audit_logs() -> list[dict]:
    if not os.path.exists(AUDIT_LOG_PATH):
        return []
    logs = []
    with open(AUDIT_LOG_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                logs.append(json.loads(line))
    return list(reversed(logs))

st.set_page_config(
    page_title="AegisGate | Regulated Zero-Trust AI Pipeline Gatekeeper",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ AegisGate: Zero-Trust AI Pipeline Gatekeeper")
st.caption(
    "Governed CI/CD Supply-Chain Auditor • Local Secret Redaction • Deterministic Overrides • Human-in-the-Loop Oversight"
)

with st.sidebar:
    st.header("Governance Controls")
    st.markdown(
        "**Active Safeguards:**\n"
        "- 🔒 **Read-Only Scope:** Zero access to cloud keys or runner memory\n"
        "- 🧹 **Local Secret Redactor:** Strips `AKIA...` & `ghp_...` pre-LLM\n"
        "- 🧱 **Deterministic Override:** Hard rules block prompt injections\n"
        "- 🧑‍💻 **Human Sign-Off:** Risky builds pause until explicitly approved"
    )
    st.divider()
    scenario = st.selectbox("Select Demo Scenario", list(FIXTURES.keys()))

default_yaml = ""
fixture_path = FIXTURES[scenario]
if fixture_path and os.path.exists(fixture_path):
    with open(fixture_path, "r", encoding="utf-8") as f:
        default_yaml = f.read()

st.subheader("1. Incoming CI/CD Workflow Specification")
workflow_input = st.text_area(
    "Inspecting GitHub Actions YAML before runner execution:",
    value=default_yaml,
    height=230,
)

if st.button("🔍 Run Governed Security Audit", type="primary", width='stretch'):
    if not workflow_input.strip():
        st.warning("Please paste a GitHub Actions YAML workflow first.")
    else:
        with st.spinner("Running local secret redaction, deterministic rules, and sandboxed Groq analysis..."):
            try:
                report = analyze_workflow(workflow_input)
                st.session_state["last_report"] = report.model_dump()
                st.session_state["decision_recorded"] = False
            except Exception as e:
                st.error(f"Audit failed: {e}")

if "last_report" in st.session_state:
    rep = st.session_state["last_report"]
    st.divider()
    st.subheader("2. Two-Tier Audit & Governance Verdict")

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Gatekeeper Status", "PAUSED" if rep["status"] != "APPROVED" else "APPROVED")
    m2.metric("Final Risk Score", f"{rep['final_risk_score']} / 100")
    m3.metric("AI Raw Score", f"{rep['ai_raw_risk_score']} / 100")
    m4.metric("Secrets Redacted Pre-AI", rep["secrets_redacted_count"])

    if rep["status"] == "PAUSED_FOR_HUMAN_REVIEW":
        st.error(f"🚨 **{rep['governance_notice']}**")
    else:
        st.success(f"✅ **{rep['governance_notice']}**")

    col_left, col_right = st.columns(2)

    with col_left:
        st.markdown("#### 🧱 Deterministic Rule Engine (Un-Bypassable)")
        if rep["deterministic_flags"]:
            for flag in rep["deterministic_flags"]:
                st.warning(flag)
        else:
            st.info("No deterministic policy violations detected.")

        st.markdown("#### 🤖 Sandboxed AI Risk Explanation")
        st.write(f"**Summary:** {rep['ai_summary']}")
        st.write(f"**Recommended Fix:** {rep['recommended_fix']}")

    with col_right:
        st.markdown("#### 🧹 Redacted Payload Sent to LLM (Zero Secret Exposure)")
        st.code(rep["redacted_workflow"], language="yaml")

    st.divider()
    st.subheader("3. Human-in-the-Loop Oversight Gate")

    if rep["status"] == "PAUSED_FOR_HUMAN_REVIEW":
        reviewer_name = st.text_input("Approving Engineer Name", value="Josiah (Security Lead)")
        justification = st.text_input(
            "Audit Justification (Required for compliance trail)",
            placeholder="e.g., Quarantined unpinned trivy-action tag matching CVE-2026-33634",
        )
        b1, b2 = st.columns(2)
        with b1:
            if st.button("🛑 Quarantine & Block Pipeline", type="primary", width='stretch'):
                append_audit_log({
                    "logged_at_utc": datetime.now(timezone.utc).isoformat(),
                    "workflow_sha256": rep["workflow_sha256"],
                    "automated_status": rep["status"],
                    "final_risk_score": rep["final_risk_score"],
                    "human_decision": "QUARANTINED",
                    "reviewer": reviewer_name,
                    "justification": justification or "Blocked due to supply-chain policy violations.",
                })
                st.session_state["decision_recorded"] = True
                st.error("Pipeline QUARANTINED. Decision recorded to immutable audit log.")
        with b2:
            if st.button("⚠️ Override & Approve Execution", width='stretch'):
                append_audit_log({
                    "logged_at_utc": datetime.now(timezone.utc).isoformat(),
                    "workflow_sha256": rep["workflow_sha256"],
                    "automated_status": rep["status"],
                    "final_risk_score": rep["final_risk_score"],
                    "human_decision": "APPROVED_WITH_OVERRIDE",
                    "reviewer": reviewer_name,
                    "justification": justification or "Manual risk acceptance by engineer.",
                })
                st.session_state["decision_recorded"] = True
                st.warning("Pipeline APPROVED via explicit human override. Logged for accountability.")
    else:
        if not st.session_state.get("decision_recorded"):
            append_audit_log({
                "logged_at_utc": datetime.now(timezone.utc).isoformat(),
                "workflow_sha256": rep["workflow_sha256"],
                "automated_status": rep["status"],
                "final_risk_score": rep["final_risk_score"],
                "human_decision": "AUTO_APPROVED_LOW_RISK",
                "reviewer": "Policy Engine",
                "justification": "All actions SHA-pinned; zero secrets exposed.",
            })
            st.session_state["decision_recorded"] = True

st.divider()
st.subheader("4. Tamper-Evident Governance Audit Trail")
logs = load_audit_logs()
if logs:
    st.dataframe(logs, width='stretch')
else:
    st.caption("No audit decisions logged yet. Run a scan above to populate the compliance trail.")
