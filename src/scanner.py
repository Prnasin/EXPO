import json
import logging
import subprocess
from dataclasses import dataclass
from typing import Optional, List

logger = logging.getLogger(__name__)

@dataclass
class VulnerabilityRecord:
    cve_id: str
    severity: str
    cvss_score: float
    package_name: str
    installed_version: str
    fixed_version: str
    title: str
    description: str
    target: str

def run_trivy_scan(image_name: str, output_path: str) -> str:
    """
    Run Trivy vulnerability scanner on a given container image.
    
    Args:
        image_name: Name of the container image to scan.
        output_path: Path to save the JSON output.
        
    Returns:
        The output path if successful.
        
    Raises:
        subprocess.CalledProcessError: If the Trivy command fails.
    """
    cmd = ['trivy', 'image', '--format', 'json', '--output', output_path, image_name]
    logger.info(f"Running Trivy scan on {image_name}. Command: {' '.join(cmd)}")
    
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        logger.info(f"Trivy scan completed successfully. Results saved to {output_path}")
        return output_path
    except subprocess.CalledProcessError as e:
        logger.error(f"Trivy scan failed with exit code {e.returncode}")
        logger.error(f"Stdout: {e.stdout}")
        logger.error(f"Stderr: {e.stderr}")
        raise

def parse_trivy_json(file_path: str) -> List[VulnerabilityRecord]:
    """
    Parse Trivy JSON output and extract vulnerabilities.
    
    Args:
        file_path: Path to the Trivy JSON results file.
        
    Returns:
        List of VulnerabilityRecord objects.
    """
    logger.info(f"Parsing Trivy JSON results from {file_path}")
    vulns = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        logger.error(f"Trivy JSON file not found: {file_path}")
        raise
    except json.JSONDecodeError as e:
        logger.error(f"Failed to decode JSON from {file_path}: {e}")
        raise
        
    results = data.get('Results', [])
    for result in results:
        target = result.get('Target', 'unknown')
        vulnerabilities = result.get('Vulnerabilities', [])
        
        for v in vulnerabilities:
            cve_id = v.get('VulnerabilityID', 'UNKNOWN')
            severity = v.get('Severity', 'UNKNOWN')
            
            # Extract CVSS score. Prioritize NVD v3, then vendor v3
            cvss_data = v.get('CVSS', {})
            cvss_score = 0.0
            
            if cvss_data:
                # Find highest v3 score across vendors
                for vendor, scores in cvss_data.items():
                    if 'V3Score' in scores:
                        cvss_score = max(cvss_score, float(scores['V3Score']))
            
            pkg_name = v.get('PkgName', 'unknown')
            installed_version = v.get('InstalledVersion', 'unknown')
            fixed_version = v.get('FixedVersion', 'unknown')
            title = v.get('Title', '')
            description = v.get('Description', '')
            
            vuln_record = VulnerabilityRecord(
                cve_id=cve_id,
                severity=severity,
                cvss_score=cvss_score,
                package_name=pkg_name,
                installed_version=installed_version,
                fixed_version=fixed_version,
                title=title,
                description=description,
                target=target
            )
            vulns.append(vuln_record)
            
    logger.info(f"Parsed {len(vulns)} vulnerabilities from Trivy results.")
    return vulns
