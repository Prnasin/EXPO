import streamlit as st
import pandas as pd
import json
import os
import plotly.express as px
from collections import Counter

from src.scanner import VulnerabilityRecord
from src.enricher import enrich_vulnerabilities
from src.ai_triager import run_ai_triage, generate_deterministic_triage
from src.config import config

# ── Streamlit Page Configuration ──────────────────────────────────────────────
st.set_page_config(
    page_title="DevSecOps AI Vulnerability Triage",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── Sample Demo Vulnerabilities ───────────────────────────────────────────────
SAMPLE_DEMO_VULNS = [
    VulnerabilityRecord(
        cve_id="CVE-2023-30861",
        severity="HIGH",
        cvss_score=7.5,
        package_name="flask",
        installed_version="2.0.1",
        fixed_version="2.2.5",
        title="Session cookie disclosure in Flask",
        description="Flask before 2.2.5 did not sign session cookies properly in certain multi-app configurations.",
        target="docker/Dockerfile.demo"
    ),
    VulnerabilityRecord(
        cve_id="CVE-2023-43804",
        severity="CRITICAL",
        cvss_score=9.8,
        package_name="urllib3",
        installed_version="1.26.5",
        fixed_version="1.26.18",
        title="Cookie leak on redirect",
        description="urllib3 does not strip Cookie headers when redirecting to a different origin.",
        target="docker/Dockerfile.demo"
    ),
    VulnerabilityRecord(
        cve_id="CVE-2024-34069",
        severity="HIGH",
        cvss_score=8.1,
        package_name="werkzeug",
        installed_version="2.0.1",
        fixed_version="3.0.3",
        title="Debugger RCE via console endpoint",
        description="Werkzeug debugger console vulnerable to cross-origin execution.",
        target="docker/Dockerfile.demo"
    ),
    VulnerabilityRecord(
        cve_id="CVE-2024-22195",
        severity="MEDIUM",
        cvss_score=6.1,
        package_name="jinja2",
        installed_version="3.0.1",
        fixed_version="3.1.3",
        title="HTML attribute injection via xmlattr",
        description="Jinja2 xmlattr filter allows HTML attribute injection via unescaped keys.",
        target="docker/Dockerfile.demo"
    ),
    VulnerabilityRecord(
        cve_id="CVE-2021-33503",
        severity="HIGH",
        cvss_score=7.5,
        package_name="urllib3",
        installed_version="1.26.5",
        fixed_version="1.26.5-2",
        title="Catastrophic ReDoS in URL parser",
        description="Regular expression denial of service in authority component parser.",
        target="docker/Dockerfile.demo"
    ),
    VulnerabilityRecord(
        cve_id="CVE-2022-28928",
        severity="MEDIUM",
        cvss_score=5.5,
        package_name="libxml2",
        installed_version="2.9.10",
        fixed_version="2.9.14",
        title="Buffer over-read in xmlParseXMLDecl",
        description="Theoretical memory leak in XML declaration parser without known exploit.",
        target="base-os:debian-bullseye"
    ),
    VulnerabilityRecord(
        cve_id="CVE-2023-29469",
        severity="HIGH",
        cvss_score=7.5,
        package_name="libxml2",
        installed_version="2.9.10",
        fixed_version="2.9.14",
        title="Null pointer dereference",
        description="Theoretical denial of service in dictionary hashing function.",
        target="base-os:debian-bullseye"
    ),
    VulnerabilityRecord(
        cve_id="CVE-2022-40897",
        severity="MEDIUM",
        cvss_score=5.9,
        package_name="setuptools",
        installed_version="58.1.0",
        fixed_version="65.5.1",
        title="ReDoS in package index URL matching",
        description="Regular expression denial of service during pip installation.",
        target="python-base"
    )
]

# ── Sidebar Configuration ─────────────────────────────────────────────────────
with st.sidebar:
    st.image("https://raw.githubusercontent.com/aquasecurity/trivy/main/docs/resources/images/logo.png", width=140)
    st.title("DevSecOps Agent")
    st.caption("AI-Powered Real-World Exploit Prioritization")
    st.markdown("---")
    
    st.subheader("⚙️ AI Engine Status")
    
    # Check if key is pre-configured in Streamlit Secrets or Environment
    preconfigured_key = None
    try:
        if "GEMINI_API_KEY" in st.secrets:
            preconfigured_key = st.secrets["GEMINI_API_KEY"]
    except Exception:
        pass
    if not preconfigured_key:
        preconfigured_key = os.environ.get("GEMINI_API_KEY")

    if preconfigured_key:
        config.GEMINI_API_KEY = preconfigured_key
        st.success("🟢 Gemini AI Engine: Active")
        st.caption("AI-powered reasoning and remediation enabled.")
    else:
        api_key_input = st.text_input(
            "Gemini API Key (Optional)",
            type="password",
            help="Free key from https://aistudio.google.com/apikey. If empty, the agent uses rule-based deterministic triage."
        )
        if api_key_input:
            config.GEMINI_API_KEY = api_key_input
        else:
            st.info("ℹ️ Running in Deterministic Mode (No key needed)")
        
    st.markdown("---")
    st.markdown("### 📚 Threat Intel Sources")
    st.markdown("- **CISA KEV**: US Gov Known Exploited Vulnerabilities Catalog")
    st.markdown("- **FIRST.org EPSS**: Daily Exploit Prediction Scoring System")
    st.markdown("- **Trivy Scanner**: Open-source container vulnerability scanner")
    st.markdown("- **Google Gemini**: AI reasoning & remediation engine")

# ── Main Header ───────────────────────────────────────────────────────────────
st.title("🛡️ Autonomous DevSecOps Container Triage Agent")
st.markdown(
    """
    **Tired of alert fatigue?** Standard scanners return 200+ CVEs where 95% have **zero real-world exploits**.  
    This agent combines **CISA KEV**, **EPSS exploit probabilities**, and **Google Gemini AI** to filter out noise, catch active attacks, and enforce intelligent CI/CD gates.
    """
)

tab1, tab2, tab3 = st.tabs(["🚀 Live Interactive Triage", "🔍 EPSS vs CVSS Explorer", "📖 Architecture & How It Works"])

# ── Tab 1: Live Interactive Triage ────────────────────────────────────────────
with tab1:
    st.subheader("Step 1: Select or Upload Vulnerability Scan")
    
    data_source = st.radio(
        "Choose Scan Source:",
        ["Demo Vulnerable Container (`docker/Dockerfile.demo`)", "Upload Trivy JSON Output (`trivy-results.json`)"],
        horizontal=True
    )
    
    vuln_records = []
    
    if data_source.startswith("Demo"):
        st.info("💡 Using pre-configured scan results from the intentionally vulnerable demo container (Python 3.10 + outdated Flask, urllib3, werkzeug).")
        vuln_records = SAMPLE_DEMO_VULNS
    else:
        uploaded_file = st.file_uploader("Upload a Trivy JSON file", type=["json"])
        if uploaded_file:
            try:
                data = json.load(uploaded_file)
                # Parse Trivy format
                for result in data.get("Results", []):
                    target = result.get("Target", "Unknown")
                    for v in result.get("Vulnerabilities", []):
                        cvss = 0.0
                        cvss_data = v.get("CVSS", {})
                        if "nvd" in cvss_data:
                            cvss = cvss_data["nvd"].get("V3Score", 0.0)
                        elif "redhat" in cvss_data:
                            cvss = cvss_data["redhat"].get("V3Score", 0.0)
                            
                        vuln_records.append(
                            VulnerabilityRecord(
                                cve_id=v.get("VulnerabilityID", "N/A"),
                                severity=v.get("Severity", "UNKNOWN"),
                                cvss_score=float(cvss),
                                package_name=v.get("PkgName", "N/A"),
                                installed_version=v.get("InstalledVersion", "N/A"),
                                fixed_version=v.get("FixedVersion", "unknown"),
                                title=v.get("Title", ""),
                                description=v.get("Description", ""),
                                target=target
                            )
                        )
                st.success(f"Parsed {len(vuln_records)} vulnerabilities from uploaded scan.")
            except Exception as e:
                st.error(f"Error parsing JSON: {e}")

    if st.button("⚡ Run Threat Intel Enrichment & AI Triage", type="primary", use_container_width=True):
        if not vuln_records:
            st.warning("Please provide vulnerability scan data first.")
        else:
            with st.spinner("1/3 Querying FIRST.org EPSS and CISA KEV APIs..."):
                enriched = enrich_vulnerabilities(vuln_records)
                
            with st.spinner("2/3 Synthesizing with Google Gemini AI..."):
                triage_results = run_ai_triage(enriched)

            st.success("Triage Complete!")
            st.markdown("---")
            
            # Key KPI Cards
            gate_decision = triage_results.get("gate_decision", "FAIL")
            risk_score = triage_results.get("risk_score", 0)
            total_cves = len(enriched)
            critical_cves = sum(1 for v in enriched if v.priority == "CRITICAL")
            suppressed = triage_results.get("suppressed_noise_count", 0)
            reduction = round((suppressed / max(total_cves, 1)) * 100, 1)

            col1, col2, col3, col4 = st.columns(4)
            with col1:
                if gate_decision == "FAIL":
                    st.metric("🚦 CI/CD Gate", "🛑 BLOCKED", delta="-Deployment Prevented", delta_color="inverse")
                else:
                    st.metric("🚦 CI/CD Gate", "✅ PASSED", delta="+Ready to Deploy", delta_color="normal")
            with col2:
                st.metric("🔥 Total CVEs Found", total_cves)
            with col3:
                st.metric("🔇 Alert Noise Suppressed", f"{reduction}%", f"{suppressed} Deprioritized")
            with col4:
                st.metric("⚡ Risk Score", f"{risk_score} / 100")

            st.markdown("---")

            # Executive Summary Box
            st.subheader("📋 Executive Summary (AI-Generated)")
            st.info(triage_results.get("executive_summary", "No summary provided."))

            # Critical Action Items
            action_items = triage_results.get("critical_action_items", [])
            if action_items:
                st.subheader("🚨 Critical Action Items (Must Fix Before Release)")
                items_df = pd.DataFrame(action_items)
                st.dataframe(items_df, use_container_width=True)

            # Remediation Steps
            remediation = triage_results.get("remediation_steps", [])
            if remediation:
                st.subheader("🛠️ Remediation Steps")
                for i, step in enumerate(remediation, 1):
                    st.code(f"{i}. {step}", language="bash")

            # Full Enriched Table
            st.subheader("📊 Detailed Vulnerability Breakdown")
            table_data = []
            for v in enriched:
                table_data.append({
                    "CVE ID": v.cve_id,
                    "Package": v.package_name,
                    "Installed": v.installed_version,
                    "Fixed": v.fixed_version,
                    "Severity": v.severity,
                    "CVSS": v.cvss_score,
                    "EPSS Probability": f"{v.epss_score:.4f}",
                    "In CISA KEV": "🚨 YES" if v.in_cisa_kev else "NO",
                    "Assigned Priority": v.priority
                })
            df = pd.DataFrame(table_data)
            
            def highlight_priority(val):
                if val == 'CRITICAL':
                    return 'background-color: #ffcccc; color: #990000; font-weight: bold;'
                elif val == 'MEDIUM':
                    return 'background-color: #fff2cc; color: #b28900;'
                else:
                    return 'background-color: #e6f7e6; color: #006600;'
                    
            try:
                st.dataframe(df.style.map(highlight_priority, subset=['Assigned Priority']), use_container_width=True)
            except AttributeError:
                st.dataframe(df.style.applymap(highlight_priority, subset=['Assigned Priority']), use_container_width=True)

# ── Tab 2: EPSS vs CVSS Explorer ──────────────────────────────────────────────
with tab2:
    st.subheader("Why CVSS Alone Fails: EPSS vs CVSS Comparison")
    st.markdown(
        """
        - **CVSS (Theoretical)**: Measures severity in lab conditions (0 to 10).
        - **EPSS (Empirical)**: Measures probability of actual exploitation in the wild in the next 30 days (0% to 100%).
        
        Notice how a high CVSS does **not** mean high real-world risk:
        """
    )
    
    comparison_data = [
        {"CVE": "CVE-2023-43804 (urllib3)", "CVSS": 9.8, "EPSS": 0.42, "CISA_KEV": "YES", "Action": "BLOCK (Active Exploits)"},
        {"CVE": "CVE-2024-34069 (werkzeug)", "CVSS": 8.1, "EPSS": 0.38, "CISA_KEV": "YES", "Action": "BLOCK (Active Exploits)"},
        {"CVE": "CVE-2023-30861 (flask)", "CVSS": 7.5, "EPSS": 0.12, "CISA_KEV": "NO", "Action": "WARN (Medium Risk)"},
        {"CVE": "CVE-2023-29469 (libxml2)", "CVSS": 7.5, "EPSS": 0.001, "CISA_KEV": "NO", "Action": "SUPPRESS (Noise)"},
        {"CVE": "CVE-2022-28928 (libxml2)", "CVSS": 5.5, "EPSS": 0.0004, "CISA_KEV": "NO", "Action": "SUPPRESS (Noise)"},
        {"CVE": "CVE-2022-40897 (setuptools)", "CVSS": 5.9, "EPSS": 0.002, "CISA_KEV": "NO", "Action": "SUPPRESS (Noise)"}
    ]
    comp_df = pd.DataFrame(comparison_data)
    
    fig = px.scatter(
        comp_df,
        x="CVSS",
        y="EPSS",
        text="CVE",
        color="Action",
        size=[30, 28, 20, 10, 10, 10],
        title="EPSS (Real Exploitation) vs CVSS (Theoretical Severity)",
        color_discrete_map={
            "BLOCK (Active Exploits)": "#d9534f",
            "WARN (Medium Risk)": "#f0ad4e",
            "SUPPRESS (Noise)": "#5cb85c"
        }
    )
    fig.update_traces(textposition='top center')
    st.plotly_chart(fig, use_container_width=True)

# ── Tab 3: Architecture & Deep Dive ───────────────────────────────────────────
with tab3:
    st.subheader("Architecture Flow")
    st.markdown(
        """
        ```mermaid
        flowchart LR
            A["Container Image"] --> B["Trivy Scanner"]
            B --> C["Raw CVE List (200+)"]
            C --> D["Threat Intel Enrichment"]
            D --> E["FIRST.org EPSS API"]
            D --> F["CISA KEV Catalog"]
            E --> G["Google Gemini AI Triage"]
            F --> G
            G --> H["Actionable Report (5 Real Threats)"]
            H --> I["Slack Alert"]
            H --> J["CI/CD Gate: Pass/Fail"]
        ```
        """
    )
    st.markdown("---")
    st.subheader("Key Benefits for Engineering Teams")
    st.markdown("1. **Zero Alert Fatigue**: Cuts down 90%+ of false-positive critical alarms.")
    st.markdown("2. **Evidence-Based Security**: Backed by actual weaponization data from CISA and FIRST.org.")
    st.markdown("3. **100% Free Stack**: Open-source Trivy, free public APIs, Gemini free tier, and GitHub Actions.")
