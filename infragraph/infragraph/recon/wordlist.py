"""Built-in wordlist & subdomain permutator."""
from typing import List, Set

COMMON_SUBDOMAIN_PREFIXES = [
    "api", "dev", "staging", "test", "auth", "s3", "bucket", "admin", "portal",
    "vpn", "mail", "internal", "dashboard", "legacy", "old", "demo", "sandbox",
    "beta", "qa", "app", "status", "docs", "login", "sso", "corp", "remote",
    "git", "jenkins", "jira", "grafana", "k8s", "stage", "cdn", "assets",
    "static", "media", "shop", "pay", "checkout", "help", "support", "billing",
    "ops", "monitor", "prometheus", "vault", "elastic", "analytics", "preview",
    "release", "uat", "gateway", "connect", "proxy", "edge", "ws", "db"
]


def generate_subdomain_candidates(domain: str, extra_prefixes: Set[str] = None) -> List[str]:
    """Generate potential subdomain candidates for active DNS brute-force."""
    prefixes = set(COMMON_SUBDOMAIN_PREFIXES)
    if extra_prefixes:
        prefixes.update(extra_prefixes)

    domain = domain.strip().lower()
    return [f"{prefix}.{domain}" for prefix in prefixes]
