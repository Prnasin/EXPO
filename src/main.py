import argparse
import json
import os
import sys
import logging
from collections import Counter
from typing import Optional

from src.config import validate_config
from src.scanner import run_trivy_scan, parse_trivy_json
from src.enricher import enrich_vulnerabilities
from src.ai_triager import run_ai_triage
from src.notifier import send_slack_notification

logger = logging.getLogger(__name__)

BANNER = r"""
╔══════════════════════════════════════════════════════════════╗
║   🛡️  Autonomous DevSecOps Container Vulnerability Triage   ║
╚══════════════════════════════════════════════════════════════╝
"""


def run_pipeline(trivy_json_path: Optional[str] = None, image_name: Optional[str] = None) -> int:
    """
    Run the complete DevSecOps triage pipeline.

    Args:
        trivy_json_path: Path to an existing Trivy JSON results file.
        image_name: Name of the image to scan if trivy_json_path is not provided.

    Returns:
        Exit code: 0 for PASS, 1 for FAIL.
    """
    try:
        try:
            print(BANNER)
        except UnicodeEncodeError:
            print("\n" + "=" * 62)
            print("  Autonomous DevSecOps Container Vulnerability Triage Agent")
            print("=" * 62 + "\n")
        validate_config()

        # ── Step 1/5: Scan / Parse ──────────────────────────────────────
        logger.info("[Step 1/5] 📋 Parsing Trivy scan results...")
        if not trivy_json_path and image_name:
            trivy_json_path = "trivy-results.json"
            run_trivy_scan(image_name, trivy_json_path)
        elif not trivy_json_path:
            logger.error("Either --trivy-json or --image must be provided.")
            return 1

        vulns = parse_trivy_json(trivy_json_path)
        total_cves = len(vulns)

        severity_counts = Counter(v.severity for v in vulns)
        logger.info(f"  → Found {total_cves} total vulnerabilities")
        logger.info(
            f"  → Severity breakdown: CRITICAL={severity_counts.get('CRITICAL', 0)}, "
            f"HIGH={severity_counts.get('HIGH', 0)}, "
            f"MEDIUM={severity_counts.get('MEDIUM', 0)}, "
            f"LOW={severity_counts.get('LOW', 0)}"
        )

        if total_cves == 0:
            logger.info("No vulnerabilities found. Pipeline PASS.")
            return 0

        # ── Step 2/5: Enrich ────────────────────────────────────────────
        logger.info("[Step 2/5] 🔍 Enriching with threat intelligence...")
        enriched = enrich_vulnerabilities(vulns)

        critical_count = sum(1 for v in enriched if v.priority == "CRITICAL")
        medium_count = sum(1 for v in enriched if v.priority == "MEDIUM")
        low_count = sum(1 for v in enriched if v.priority == "LOW")
        logger.info(f"  → Priority breakdown: CRITICAL={critical_count}, MEDIUM={medium_count}, LOW={low_count}")

        # ── Step 3/5: AI Triage ─────────────────────────────────────────
        actionable = critical_count + medium_count
        logger.info(f"[Step 3/5] 🤖 Running AI-powered triage...")
        logger.info(f"  → Analyzing {actionable} high-priority CVEs (skipping {low_count} noise CVEs)")
        triage_results = run_ai_triage(enriched)
        logger.info("  → AI triage complete")

        # ── Step 4/5: Report ────────────────────────────────────────────
        logger.info("[Step 4/5] 📊 Triage Results:")
        logger.info(f"  → Executive Summary: {triage_results.get('executive_summary', 'N/A')}")
        logger.info(f"  → Risk Score: {triage_results.get('risk_score', 'N/A')}/100")
        logger.info(f"  → Suppressed Noise: {triage_results.get('suppressed_noise_count', 0)} CVEs")

        action_items = triage_results.get("critical_action_items", [])
        if action_items:
            logger.info(f"  → Critical Action Items ({len(action_items)}):")
            for item in action_items[:5]:
                logger.info(f"    • {item.get('cve_id')} in {item.get('package')}: {item.get('reason', '')}")

        remediation = triage_results.get("remediation_steps", [])
        if remediation:
            logger.info(f"  → Remediation Steps:")
            for i, step in enumerate(remediation, 1):
                logger.info(f"    {i}. {step}")

        # Save triage results to JSON report
        try:
            with open("triage-report.json", "w", encoding="utf-8") as f:
                json.dump(triage_results, f, indent=2)
            logger.info("  → Triage report saved to triage-report.json")
        except Exception as e:
            logger.warning(f"Failed to save triage-report.json: {e}")

        # Render GitHub Step Summary if running in CI
        summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary_path:
            try:
                decision = triage_results.get("gate_decision", "FAIL")
                gate_icon = "🛑 BLOCKED (Deployment Prevented)" if decision == "FAIL" else "✅ PASSED (Ready to Deploy)"
                suppressed = triage_results.get("suppressed_noise_count", 0)
                reduction_pct = round((suppressed / max(total_cves, 1)) * 100, 1)
                
                with open(summary_path, "a", encoding="utf-8") as sf:
                    sf.write("## 🛡️ DevSecOps Container Vulnerability Triage Report\n\n")
                    sf.write(f"| Metric | Result |\n|---|---|\n")
                    sf.write(f"| **Gate Decision** | **{gate_icon}** |\n")
                    sf.write(f"| **Overall Risk Score** | **{triage_results.get('risk_score', 'N/A')}/100** |\n")
                    sf.write(f"| **Total CVEs Scanned** | {total_cves} |\n")
                    sf.write(f"| **Noise Suppressed** | {suppressed} ({reduction_pct}% reduction) |\n")
                    sf.write(f"| **Active Exploited CVEs** | {critical_count} |\n\n")
                    sf.write(f"### 📋 Executive Summary\n{triage_results.get('executive_summary', 'N/A')}\n\n")
                    if action_items:
                        sf.write("### 🚨 Critical Action Items\n| CVE | Package | Installed | Fixed | Reason |\n|---|---|---|---|---|\n")
                        for item in action_items:
                            sf.write(f"| `{item.get('cve_id')}` | `{item.get('package')}` | `{item.get('current_version', '-')}` | `{item.get('fixed_version', '-')}` | {item.get('reason', '')} |\n")
                        sf.write("\n")
                    if remediation:
                        sf.write("### 🛠️ Remediation Steps\n")
                        for i, step in enumerate(remediation, 1):
                            sf.write(f"{i}. {step}\n")
                        sf.write("\n")
            except Exception as e:
                logger.warning(f"Failed to write GITHUB_STEP_SUMMARY: {e}")

        # ── Step 5/5: Notify & Gate ─────────────────────────────────────
        logger.info("[Step 5/5] 📨 Sending Slack notification...")
        slack_sent = send_slack_notification(triage_results, total_cves, enriched)
        if slack_sent:
            logger.info("  → Slack alert sent successfully")
        else:
            logger.info("  → Slack notification skipped or failed")

        decision = triage_results.get("gate_decision", "FAIL")
        if decision == "FAIL":
            logger.error(f"🚦 Gate Decision: FAIL ({critical_count} actively exploited CVEs found)")
            logger.error("  → Exit code: 1")
            return 1
        else:
            logger.info("🚦 Gate Decision: PASS — No critical issues blocking deployment")
            logger.info("  → Exit code: 0")
            return 0

    except Exception as e:
        logger.error(f"Pipeline failed with unexpected error: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Autonomous DevSecOps Container Vulnerability Triage Agent"
    )
    parser.add_argument("--trivy-json", type=str, help="Path to existing Trivy JSON results file")
    parser.add_argument("--image", type=str, help="Container image to scan (runs Trivy)")

    args = parser.parse_args()

    exit_code = run_pipeline(trivy_json_path=args.trivy_json, image_name=args.image)
    sys.exit(exit_code)

