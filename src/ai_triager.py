import json
import logging
import time
from typing import List, Dict

try:
    import google.genai as genai
    from google.genai import types
except ImportError:
    genai = None

from src.config import config
from src.enricher import EnrichedVulnerability

logger = logging.getLogger(__name__)

def build_triage_prompt(enriched_vulns: List[EnrichedVulnerability]) -> str:
    """
    Build a structured prompt for the LLM based on enriched vulnerabilities.
    
    Args:
        enriched_vulns: List of enriched vulnerabilities.
        
    Returns:
        Formatted prompt string.
    """
    filtered_vulns = [v for v in enriched_vulns if v.priority in ['CRITICAL', 'MEDIUM']]
    noise_count = len(enriched_vulns) - len(filtered_vulns)
    
    prompt = (
        f"You are a Principal DevSecOps Engineer triaging container vulnerabilities.\n"
        f"Total noise/LOW vulnerabilities filtered out: {noise_count}\n\n"
        f"Actionable Vulnerabilities to Triage:\n"
        f"| CVE ID | Package | Installed | Fixed | CVSS | EPSS | KEV | Priority |\n"
        f"|---|---|---|---|---|---|---|---|\n"
    )
    
    for v in filtered_vulns:
        kev_str = "YES" if v.in_cisa_kev else "NO"
        prompt += f"| {v.cve_id} | {v.package_name} | {v.installed_version} | {v.fixed_version} | {v.cvss_score} | {v.epss_score:.4f} | {kev_str} | {v.priority} |\n"
        
    return prompt

def generate_deterministic_triage(enriched_vulns: List[EnrichedVulnerability]) -> Dict:
    """
    Fallback deterministic triage when LLM is unavailable.
    """
    logger.info("Using deterministic triage fallback.")
    filtered_vulns = [v for v in enriched_vulns if v.priority in ['CRITICAL', 'MEDIUM']]
    noise_count = len(enriched_vulns) - len(filtered_vulns)
    
    critical_vulns = [v for v in filtered_vulns if v.priority == 'CRITICAL']
    gate_decision = 'FAIL' if critical_vulns else 'PASS'
    
    risk_score = min(100, len(critical_vulns) * 20 + len(filtered_vulns) * 5)
    
    action_items = []
    remediation_steps = []
    
    for v in critical_vulns[:5]:
        action_items.append({
            "cve_id": v.cve_id,
            "package": v.package_name,
            "current_version": v.installed_version,
            "fixed_version": v.fixed_version,
            "reason": "Known exploited vulnerability or high exploitation probability."
        })
        if v.fixed_version != 'unknown':
            remediation_steps.append(f"Update {v.package_name} from {v.installed_version} to {v.fixed_version}")
            
    if not remediation_steps:
        remediation_steps = ["Review critical and medium vulnerabilities and patch accordingly.", "Update base image."]
        
    summary = f"Triage identified {len(critical_vulns)} critical vulnerabilities and {noise_count} noise alerts suppressed. Immediate action required to address high-risk components." if critical_vulns else "No critical vulnerabilities identified. Posture is generally acceptable but monitor medium risks."

    return {
        "executive_summary": summary,
        "critical_action_items": action_items,
        "suppressed_noise_count": noise_count,
        "remediation_steps": remediation_steps,
        "gate_decision": gate_decision,
        "risk_score": risk_score
    }

def run_ai_triage(enriched_vulns: List[EnrichedVulnerability]) -> Dict:
    """
    Run AI triage on enriched vulnerabilities using Gemini.
    
    Args:
        enriched_vulns: List of enriched vulnerabilities.
        
    Returns:
        Dictionary containing triage results.
    """
    if not config.GEMINI_API_KEY or genai is None:
        logger.warning("GEMINI_API_KEY missing or google-genai not installed. Falling back to deterministic triage.")
        return generate_deterministic_triage(enriched_vulns)
        
    prompt = build_triage_prompt(enriched_vulns)
    
    system_instruction = (
        "Act as a Principal DevSecOps Engineer. Return ONLY valid JSON (no markdown fences) with these exact keys:\n"
        "- executive_summary: str (2-sentence summary of actual security posture)\n"
        "- critical_action_items: list[dict] with keys: cve_id, package, current_version, fixed_version, reason\n"
        "- suppressed_noise_count: int (number of high-CVSS CVEs deprioritized)\n"
        "- remediation_steps: list[str] (concrete commands like 'apt-get upgrade libcurl4' or 'Update base image to python:3.12-slim')\n"
        "- gate_decision: str ('FAIL' if any CISA KEV or EPSS > 0.35 exists, 'PASS' otherwise)\n"
        "- risk_score: int (0-100 overall risk)\n"
    )

    try:
        client = genai.Client(api_key=config.GEMINI_API_KEY)
        
        # Handle rate limiting with simple retry
        for attempt in range(2):
            try:
                logger.info(f"Calling Gemini API (Attempt {attempt + 1})")
                response = client.models.generate_content(
                    model=config.GEMINI_MODEL,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        system_instruction=system_instruction,
                        temperature=0.2,
                    )
                )
                
                # Parse JSON response, strip markdown
                text = response.text.strip()
                if text.startswith("```json"):
                    text = text[7:]
                if text.startswith("```"):
                    text = text[3:]
                if text.endswith("```"):
                    text = text[:-3]
                    
                result = json.loads(text.strip())
                logger.info("AI triage successful.")
                return result
                
            except Exception as e:
                error_str = str(e)
                if '429' in error_str and attempt == 0:
                    logger.warning("Rate limit hit (429). Retrying after 60 seconds...")
                    time.sleep(60)
                    continue
                else:
                    raise
                    
    except Exception as e:
        logger.error(f"AI Triage failed: {e}. Falling back to deterministic triage.")
        return generate_deterministic_triage(enriched_vulns)
