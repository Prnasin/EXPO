import logging
import requests
import datetime
from typing import Dict, List, Any

from src.config import config

logger = logging.getLogger(__name__)

def build_slack_payload(triage_result: Dict[str, Any], total_cves: int, enriched_vulns: List) -> Dict[str, Any]:
    """
    Build a Slack Block Kit payload from triage results.
    
    Args:
        triage_result: Dictionary containing AI triage output.
        total_cves: Total number of CVEs found originally.
        enriched_vulns: List of enriched vulnerabilities.
        
    Returns:
        Dictionary representing Slack Block Kit payload.
    """
    decision = triage_result.get('gate_decision', 'FAIL')
    emoji = "✅ PASS" if decision == 'PASS' else "🚨 FAIL"
    
    suppressed = triage_result.get('suppressed_noise_count', 0)
    noise_reduction = 0
    if total_cves > 0:
        noise_reduction = round((suppressed / total_cves) * 100, 1)

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "🛡️ Container Vulnerability Triage Report",
                "emoji": True
            }
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Gate Decision:* {emoji}\n*Risk Score:* {triage_result.get('risk_score', 'N/A')}/100"
            }
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Stats:*\n• Total CVEs Found: {total_cves}\n• Noise Suppressed: {suppressed} ({noise_reduction}% reduction)"
            }
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Executive Summary:*\n{triage_result.get('executive_summary', 'No summary provided.')}"
            }
        }
    ]

    action_items = triage_result.get('critical_action_items', [])
    if action_items:
        blocks.append({"type": "divider"})
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Top Critical Action Items:*"
            }
        })
        
        for item in action_items[:3]:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"• *{item.get('cve_id')}* in `{item.get('package')}`\n  _Reason:_ {item.get('reason')}"
                }
            })

    remediation = triage_result.get('remediation_steps', [])
    if remediation:
        blocks.append({"type": "divider"})
        remediation_text = "*Remediation Steps:*\n"
        for i, step in enumerate(remediation, 1):
            remediation_text += f"{i}. {step}\n"
            
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": remediation_text
            }
        })

    blocks.append({"type": "divider"})
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    blocks.append({
        "type": "context",
        "elements": [
            {
                "type": "mrkdwn",
                "text": f"Generated at {timestamp} | Powered by Autonomous DevSecOps Triage Agent"
            }
        ]
    })

    return {"blocks": blocks}

def send_slack_notification(triage_result: Dict[str, Any], total_cves: int, enriched_vulns: List) -> bool:
    """
    Send formatted Slack notification via Webhook.
    
    Args:
        triage_result: Dictionary containing AI triage output.
        total_cves: Total number of CVEs found originally.
        enriched_vulns: List of enriched vulnerabilities.
        
    Returns:
        True if successful, False otherwise.
    """
    if not config.SLACK_WEBHOOK_URL:
        logger.warning("SLACK_WEBHOOK_URL not configured. Skipping Slack notification.")
        return False
        
    logger.info("Building Slack notification payload.")
    payload = build_slack_payload(triage_result, total_cves, enriched_vulns)
    
    try:
        response = requests.post(config.SLACK_WEBHOOK_URL, json=payload, timeout=10)
        response.raise_for_status()
        logger.info("Successfully sent Slack notification.")
        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to send Slack notification: {e}")
        return False
