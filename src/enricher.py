import logging
import requests
from dataclasses import dataclass
from typing import Optional, List, Dict, Set
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from src.config import config
from src.scanner import VulnerabilityRecord

logger = logging.getLogger(__name__)

# Module-level cache
_CISA_KEV_CACHE: Optional[Set[str]] = None
_CISA_KEV_DUE_DATES: Dict[str, str] = {}

@dataclass
class EnrichedVulnerability:
    cve_id: str
    severity: str
    cvss_score: float
    package_name: str
    installed_version: str
    fixed_version: str
    title: str
    description: str
    target: str
    epss_score: float
    epss_percentile: float
    in_cisa_kev: bool
    kev_due_date: Optional[str]
    priority: str  # 'CRITICAL', 'MEDIUM', 'LOW'

def _get_session() -> requests.Session:
    """Create a requests Session with retry logic."""
    session = requests.Session()
    retries = Retry(
        total=3,
        backoff_factor=1.0,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"]
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session

def fetch_epss_scores(cve_ids: List[str]) -> Dict[str, Dict]:
    """
    Fetch EPSS scores for a list of CVE IDs in batches.
    
    Args:
        cve_ids: List of CVE IDs.
        
    Returns:
        A dictionary mapping CVE ID to EPSS data dict with 'epss' and 'percentile' keys.
    """
    if not cve_ids:
        return {}

    unique_cves = list(set(cve_ids))
    logger.info(f"Fetching EPSS scores for {len(unique_cves)} unique CVEs.")
    
    session = _get_session()
    batch_size = 30
    results = {}

    for i in range(0, len(unique_cves), batch_size):
        batch = unique_cves[i:i + batch_size]
        cve_param = ",".join(batch)
        url = f"{config.EPSS_API_BASE}?cve={cve_param}"
        
        try:
            response = session.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            for item in data.get('data', []):
                cve = item.get('cve')
                if cve:
                    results[cve] = {
                        'epss': float(item.get('epss', 0.0)),
                        'percentile': float(item.get('percentile', 0.0))
                    }
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error fetching EPSS scores for batch: {e}")
        except (ValueError, KeyError) as e:
            logger.error(f"Error parsing EPSS response data: {e}")

    logger.info(f"Successfully retrieved EPSS scores for {len(results)} CVEs.")
    return results

def fetch_cisa_kev_catalog() -> Set[str]:
    """
    Fetch the CISA Known Exploited Vulnerabilities catalog.
    Caches the results in memory.
    
    Returns:
        Set of CVE IDs present in the KEV catalog.
    """
    global _CISA_KEV_CACHE, _CISA_KEV_DUE_DATES
    
    if _CISA_KEV_CACHE is not None:
        return _CISA_KEV_CACHE

    logger.info("Fetching CISA KEV catalog...")
    session = _get_session()
    
    try:
        response = session.get(config.CISA_KEV_URL, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        kev_set = set()
        vulnerabilities = data.get('vulnerabilities', [])
        
        for vuln in vulnerabilities:
            cve_id = vuln.get('cveID')
            due_date = vuln.get('dueDate')
            if cve_id:
                kev_set.add(cve_id)
                if due_date:
                    _CISA_KEV_DUE_DATES[cve_id] = due_date
                    
        _CISA_KEV_CACHE = kev_set
        logger.info(f"Successfully loaded {len(_CISA_KEV_CACHE)} vulnerabilities from CISA KEV.")
        return _CISA_KEV_CACHE
    except requests.exceptions.RequestException as e:
        logger.warning(f"Network error fetching CISA KEV catalog. Defaulting to empty set. Error: {e}")
        return set()
    except ValueError as e:
        logger.warning(f"Error parsing CISA KEV catalog JSON. Defaulting to empty set. Error: {e}")
        return set()

def calculate_priority(vuln_data: Dict) -> str:
    """
    Calculate the priority of a vulnerability based on its characteristics.
    
    Args:
        vuln_data: Dict containing 'in_cisa_kev', 'epss_score', and 'cvss_score'
        
    Returns:
        Priority string: 'CRITICAL', 'MEDIUM', or 'LOW'
    """
    in_kev = vuln_data.get('in_cisa_kev', False)
    epss = vuln_data.get('epss_score', 0.0)
    cvss = vuln_data.get('cvss_score', 0.0)
    
    if in_kev or epss > config.EPSS_CRITICAL_THRESHOLD:
        return 'CRITICAL'
    elif config.EPSS_MEDIUM_THRESHOLD <= epss <= config.EPSS_CRITICAL_THRESHOLD or cvss >= config.CVSS_HIGH_THRESHOLD:
        return 'MEDIUM'
    else:
        return 'LOW'

def enrich_vulnerabilities(vulns: List[VulnerabilityRecord]) -> List[EnrichedVulnerability]:
    """
    Enrich a list of vulnerabilities with EPSS scores and CISA KEV status.
    
    Args:
        vulns: List of VulnerabilityRecord objects.
        
    Returns:
        List of EnrichedVulnerability objects sorted by priority.
    """
    logger.info(f"Enriching {len(vulns)} vulnerabilities with threat intelligence...")
    
    cve_ids = [v.cve_id for v in vulns]
    epss_data = fetch_epss_scores(cve_ids)
    kev_set = fetch_cisa_kev_catalog()
    
    enriched = []
    
    for v in vulns:
        cve_epss = epss_data.get(v.cve_id, {'epss': 0.0, 'percentile': 0.0})
        in_kev = v.cve_id in kev_set
        kev_due = _CISA_KEV_DUE_DATES.get(v.cve_id)
        
        priority_input = {
            'in_cisa_kev': in_kev,
            'epss_score': cve_epss['epss'],
            'cvss_score': v.cvss_score
        }
        priority = calculate_priority(priority_input)
        
        enriched.append(EnrichedVulnerability(
            cve_id=v.cve_id,
            severity=v.severity,
            cvss_score=v.cvss_score,
            package_name=v.package_name,
            installed_version=v.installed_version,
            fixed_version=v.fixed_version,
            title=v.title,
            description=v.description,
            target=v.target,
            epss_score=cve_epss['epss'],
            epss_percentile=cve_epss['percentile'],
            in_cisa_kev=in_kev,
            kev_due_date=kev_due,
            priority=priority
        ))
        
    # Sort by priority: CRITICAL first, then MEDIUM, then LOW
    priority_order = {'CRITICAL': 0, 'MEDIUM': 1, 'LOW': 2}
    enriched.sort(key=lambda x: (priority_order.get(x.priority, 3), -x.epss_score, -x.cvss_score))
    
    logger.info("Enrichment complete.")
    return enriched
