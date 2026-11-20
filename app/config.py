"""Site configuration — single place to rename the product."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SITE_NAME = "VulnDeck"
SITE_TAGLINE = "DevSecOps vulnerability & threat intelligence"
SITE_DESC = (
    "VulnDeck tracks exploited vulnerabilities, ransomware and breach claims, "
    "threat actors, malware references, exploit prediction scores and security advisories "
    "for DevSecOps and security engineering teams."
)
SITE_LANG = "en"
BASE_URL = os.environ.get("VULNDECK_BASE_URL", "https://vulndeck-uat.azmirilias.com").rstrip("/")
CONTACT_EMAIL = os.environ.get("VULNDECK_CONTACT", "security@azmirilias.com")
GITHUB_URL = os.environ.get("VULNDECK_GITHUB", "https://github.com/azmirilias/vulndeck")
ORG_NAME = "Azmir Ilias"

DB_PATH = os.environ.get("VULNDECK_DB", str(ROOT / "data" / "vulndeck.db"))

NAV = [
    ("/kev", "Exploited"),
    ("/vendors", "Vendors"),
    ("/advisories", "Advisories"),
    ("/intel", "Intel"),
    ("/ransomware", "Ransomware"),
    ("/breaches", "Breaches"),
    ("/actors", "Actors"),
    ("/malware", "Malware"),
    ("/today", "Today"),
    ("/sources", "Sources"),
    ("/about", "About"),
]
