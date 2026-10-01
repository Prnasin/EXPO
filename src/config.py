import os
import logging
from dataclasses import dataclass
from typing import Optional

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

@dataclass
class AppConfig:
    GEMINI_API_KEY: Optional[str]
    SLACK_WEBHOOK_URL: Optional[str]
    TRIVY_RESULTS_PATH: str
    EPSS_API_BASE: str
    CISA_KEV_URL: str
    GEMINI_MODEL: str
    EPSS_CRITICAL_THRESHOLD: float
    EPSS_MEDIUM_THRESHOLD: float
    CVSS_HIGH_THRESHOLD: float
    LOG_LEVEL: str

config = AppConfig(
    GEMINI_API_KEY=os.environ.get('GEMINI_API_KEY'),
    SLACK_WEBHOOK_URL=os.environ.get('SLACK_WEBHOOK_URL'),
    TRIVY_RESULTS_PATH=os.environ.get('TRIVY_RESULTS_PATH', 'trivy-results.json'),
    EPSS_API_BASE=os.environ.get('EPSS_API_BASE', 'https://api.first.org/data/v1/epss'),
    CISA_KEV_URL=os.environ.get('CISA_KEV_URL', 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'),
    GEMINI_MODEL=os.environ.get('GEMINI_MODEL', 'gemini-3.5-flash-lite'),
    EPSS_CRITICAL_THRESHOLD=float(os.environ.get('EPSS_CRITICAL_THRESHOLD', '0.35')),
    EPSS_MEDIUM_THRESHOLD=float(os.environ.get('EPSS_MEDIUM_THRESHOLD', '0.05')),
    CVSS_HIGH_THRESHOLD=float(os.environ.get('CVSS_HIGH_THRESHOLD', '8.0')),
    LOG_LEVEL=os.environ.get('LOG_LEVEL', 'INFO').upper()
)

def validate_config() -> None:
    """Validate required and optional configuration keys."""
    if not config.GEMINI_API_KEY:
        logging.warning("GEMINI_API_KEY is not set. The pipeline will gracefully degrade to deterministic triage.")
    
    if not config.SLACK_WEBHOOK_URL:
        logging.warning("SLACK_WEBHOOK_URL is not set. Slack notifications will be skipped.")

def setup_logging() -> None:
    """Configure module-level logging."""
    numeric_level = getattr(logging, config.LOG_LEVEL, logging.INFO)
    logging.basicConfig(
        level=numeric_level,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

setup_logging()
