"""Demo data generator for cert-watch."""
from datetime import datetime, timedelta

import yaml


def get_demo_inventory() -> str:
    """Generate sample certificate inventory with various issues."""
    now = datetime.now()
    certs = {
        "certificates": [
            {
                "domain": "api.example.com",
                "common_name": "api.example.com",
                "san_domains": ["api.example.com", "api-v2.example.com"],
                "issuer": "Let's Encrypt Authority X3",
                "provider": "lets_encrypt",
                "cert_type": "multi_san",
                "key_algorithm": "RSA-4096",
                "not_before": (now - timedelta(days=60)).strftime("%Y-%m-%d"),
                "not_after": (now + timedelta(days=200)).strftime("%Y-%m-%d"),
                "auto_renewal": True,
                "environment": "production",
            },
            {
                "domain": "*.staging.example.com",
                "common_name": "*.staging.example.com",
                "san_domains": [],
                "issuer": "DigiCert Inc",
                "provider": "digicert",
                "cert_type": "wildcard",
                "key_algorithm": "RSA-2048",
                "not_before": (now - timedelta(days=300)).strftime("%Y-%m-%d"),
                "not_after": (now + timedelta(days=20)).strftime("%Y-%m-%d"),
                "auto_renewal": False,
                "environment": "staging",
            },
            {
                "domain": "legacy.example.com",
                "common_name": "legacy.example.com",
                "san_domains": [],
                "issuer": "Self-Signed",
                "provider": "self_signed",
                "cert_type": "domain",
                "key_algorithm": "RSA-2048",
                "not_before": (now - timedelta(days=400)).strftime("%Y-%m-%d"),
                "not_after": (now - timedelta(days=10)).strftime("%Y-%m-%d"),
                "auto_renewal": False,
                "environment": "production",
            },
            {
                "domain": "payments.example.com",
                "common_name": "payments.example.com",
                "san_domains": ["payments.example.com"],
                "issuer": "GlobalSign",
                "provider": "globalsign",
                "cert_type": "domain",
                "key_algorithm": "ECDSA-P256",
                "not_before": (now - timedelta(days=30)).strftime("%Y-%m-%d"),
                "not_after": (now + timedelta(days=335)).strftime("%Y-%m-%d"),
                "auto_renewal": True,
                "environment": "production",
            },
            {
                "domain": "dashboard.example.com",
                "common_name": "dashboard.example.com",
                "san_domains": ["dashboard.example.com", "admin.example.com"],
                "issuer": "AWS ACM",
                "provider": "aws_acm",
                "cert_type": "multi_san",
                "key_algorithm": "RSA-2048",
                "not_before": (now - timedelta(days=10)).strftime("%Y-%m-%d"),
                "not_after": (now + timedelta(days=60)).strftime("%Y-%m-%d"),
                "auto_renewal": False,
                "environment": "production",
            },
            {
                "domain": "internal.example.com",
                "common_name": "internal.example.com",
                "san_domains": [],
                "issuer": "Self-Signed",
                "provider": "self_signed",
                "cert_type": "domain",
                "key_algorithm": "RSA-2048",
                "not_before": (now - timedelta(days=100)).strftime("%Y-%m-%d"),
                "not_after": (now + timedelta(days=500)).strftime("%Y-%m-%d"),
                "auto_renewal": False,
                "environment": "production",
            },
        ]
    }
    return yaml.dump(certs, default_flow_style=False)
