"""Cloud provider signatures and dangling takeover patterns."""
from typing import List, Dict, Optional
from pydantic import BaseModel


class CloudSignature(BaseModel):
    service_name: str
    provider: str
    cname_patterns: List[str]
    fingerprint_body: List[str] = []
    status_codes: List[int] = [404]
    nxdomain_vulnerable: bool = False
    remediation: str
    risk_level: str = "HIGH"


CLOUD_SIGNATURES: List[CloudSignature] = [
    CloudSignature(
        service_name="AWS S3 Bucket",
        provider="AWS",
        cname_patterns=[".s3.amazonaws.com", ".s3-website.", ".s3."],
        fingerprint_body=["The specified bucket does not exist", "NoSuchBucket"],
        remediation="Remove the DNS record or claim the S3 bucket name in AWS.",
        risk_level="CRITICAL"
    ),
    CloudSignature(
        service_name="AWS Elastic Beanstalk",
        provider="AWS",
        cname_patterns=[".elasticbeanstalk.com"],
        nxdomain_vulnerable=True,
        remediation="Delete the CNAME record or recreate the Beanstalk environment.",
        risk_level="CRITICAL"
    ),
    CloudSignature(
        service_name="AWS CloudFront",
        provider="AWS",
        cname_patterns=[".cloudfront.net"],
        fingerprint_body=["The request could not be satisfied", "Bad request: 400"],
        remediation="Associate the custom domain with your CloudFront distribution.",
        risk_level="MEDIUM"
    ),
    CloudSignature(
        service_name="GitHub Pages",
        provider="GitHub",
        cname_patterns=[".github.io"],
        fingerprint_body=["There isn't a GitHub Pages site here.", "404 There isn't a GitHub Pages site here"],
        remediation="Verify your custom domain in GitHub settings or delete the DNS record.",
        risk_level="HIGH"
    ),
    CloudSignature(
        service_name="Heroku App",
        provider="Heroku",
        cname_patterns=[".herokuapp.com", ".herokussl.com", ".herokudns.com"],
        fingerprint_body=["No such app", "Heroku | No such app", "there's no app here"],
        remediation="Remove the CNAME or add the custom domain to a valid Heroku app.",
        risk_level="HIGH"
    ),
    CloudSignature(
        service_name="Azure App Service / WebApp",
        provider="Azure",
        cname_patterns=[".azurewebsites.net", ".cloudapp.net", ".azurecontainer.io"],
        fingerprint_body=["404 Web Site not found", "Error 404 - Web app not found"],
        remediation="Claim the Azure App Service name or remove stale DNS CNAME.",
        risk_level="CRITICAL"
    ),
    CloudSignature(
        service_name="Azure Traffic Manager",
        provider="Azure",
        cname_patterns=[".trafficmanager.net"],
        nxdomain_vulnerable=True,
        remediation="Recreate the Traffic Manager profile or delete the DNS record.",
        risk_level="CRITICAL"
    ),
    CloudSignature(
        service_name="Google Cloud Storage",
        provider="GCP",
        cname_patterns=["c.storage.googleapis.com", "storage.googleapis.com"],
        fingerprint_body=["The specified bucket does not exist", "NoSuchBucket"],
        remediation="Claim the GCP Storage bucket or purge the CNAME.",
        risk_level="CRITICAL"
    ),
    CloudSignature(
        service_name="Fastly CDN",
        provider="Fastly",
        cname_patterns=[".fastly.net", ".fastlylb.net"],
        fingerprint_body=["Fastly error: unknown domain", "Details: cache-"],
        remediation="Add the domain to your Fastly service or remove CNAME record.",
        risk_level="HIGH"
    ),
    CloudSignature(
        service_name="Shopify Store",
        provider="Shopify",
        cname_patterns=["shops.myshopify.com"],
        fingerprint_body=["Sorry, this shop is currently unavailable"],
        remediation="Add domain to Shopify store settings or clean up CNAME.",
        risk_level="MEDIUM"
    ),
    CloudSignature(
        service_name="Surge.sh",
        provider="Surge",
        cname_patterns=["na-west1.surge.sh", ".surge.sh"],
        fingerprint_body=["project not found"],
        remediation="Deploy a project on surge.sh with that domain or remove CNAME.",
        risk_level="HIGH"
    ),
    CloudSignature(
        service_name="Netlify",
        provider="Netlify",
        cname_patterns=[".netlify.app", ".netlify.com"],
        fingerprint_body=["Not Found - Request ID:", "page not found"],
        remediation="Verify custom domain in Netlify DNS or remove record.",
        risk_level="HIGH"
    ),
    CloudSignature(
        service_name="Zendesk Help Center",
        provider="Zendesk",
        cname_patterns=[".zendesk.com"],
        fingerprint_body=["Help Center Closed", "No such host"],
        remediation="Configure domain in Zendesk host mapping or remove CNAME.",
        risk_level="MEDIUM"
    ),
    CloudSignature(
        service_name="Pantheon",
        provider="Pantheon",
        cname_patterns=[".pantheonsite.io"],
        fingerprint_body=["404 error unknown site!", "The gods are wise"],
        remediation="Link domain to an active Pantheon environment or remove CNAME.",
        risk_level="HIGH"
    ),
    CloudSignature(
        service_name="Bitbucket Pages",
        provider="Atlassian",
        cname_patterns=[".bitbucket.io"],
        fingerprint_body=["Repository not found", "404 - Page not found"],
        remediation="Claim Bitbucket repository or clean up DNS alias.",
        risk_level="HIGH"
    ),
    CloudSignature(
        service_name="Ghost Blog",
        provider="Ghost",
        cname_patterns=[".ghost.io"],
        fingerprint_body=["The thing you were looking for is gone.", "Domain not configured"],
        remediation="Attach domain to active Ghost publication or remove DNS CNAME.",
        risk_level="HIGH"
    )
]


def match_cloud_signature(cname_target: str) -> Optional[CloudSignature]:
    """Match a CNAME target against known cloud signatures."""
    target_lower = cname_target.lower().rstrip(".")
    for sig in CLOUD_SIGNATURES:
        for pattern in sig.cname_patterns:
            if pattern.startswith("."):
                if target_lower.endswith(pattern) or target_lower == pattern[1:]:
                    return sig
            elif pattern in target_lower:
                return sig
    return None
