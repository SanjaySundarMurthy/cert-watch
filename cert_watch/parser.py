"""Parse certificate inventory YAML files."""
from datetime import datetime

import yaml

from .models import (
    Certificate,
    CertProvider,
    CertStatus,
    CertType,
    KeyAlgorithm,
)

PROVIDER_MAP = {
    "lets_encrypt": CertProvider.LETS_ENCRYPT,
    "letsencrypt": CertProvider.LETS_ENCRYPT,
    "digicert": CertProvider.DIGICERT,
    "comodo": CertProvider.COMODO,
    "globalsign": CertProvider.GLOBALSIGN,
    "aws_acm": CertProvider.AWS_ACM,
    "acm": CertProvider.AWS_ACM,
    "azure_keyvault": CertProvider.AZURE_KEYVAULT,
    "keyvault": CertProvider.AZURE_KEYVAULT,
    "gcp_cas": CertProvider.GCP_CAS,
    "self_signed": CertProvider.SELF_SIGNED,
}

KEY_MAP = {
    "RSA-2048": KeyAlgorithm.RSA_2048,
    "RSA-4096": KeyAlgorithm.RSA_4096,
    "ECDSA-P256": KeyAlgorithm.ECDSA_P256,
    "ECDSA-P384": KeyAlgorithm.ECDSA_P384,
    "Ed25519": KeyAlgorithm.ED25519,
}

TYPE_MAP = {
    "domain": CertType.DOMAIN,
    "wildcard": CertType.WILDCARD,
    "multi_san": CertType.MULTI_SAN,
    "code_signing": CertType.CODE_SIGNING,
    "client_auth": CertType.CLIENT_AUTH,
    "ca": CertType.CA,
}


def parse_inventory(yaml_content: str) -> list[Certificate]:
    """Parse a certificate inventory YAML into Certificate objects."""
    data = yaml.safe_load(yaml_content)
    if not data:
        return []
    certs_data = data if isinstance(data, list) else data.get("certificates", [])
    certs = []
    for entry in certs_data:
        domain = entry.get("domain", "")
        not_before = _parse_date(entry.get("not_before", ""))
        not_after = _parse_date(entry.get("not_after", ""))
        provider_str = entry.get("provider", "unknown").lower()
        key_str = entry.get("key_algorithm", "RSA-2048")
        type_str = entry.get("cert_type", "domain").lower()
        cert = Certificate(
            domain=domain,
            common_name=entry.get("common_name", domain),
            san_domains=entry.get("san_domains", []),
            issuer=entry.get("issuer", ""),
            provider=PROVIDER_MAP.get(provider_str, CertProvider.UNKNOWN),
            cert_type=TYPE_MAP.get(type_str, CertType.DOMAIN),
            key_algorithm=KEY_MAP.get(key_str, KeyAlgorithm.RSA_2048),
            key_size=entry.get("key_size", 2048),
            serial_number=entry.get("serial_number", ""),
            not_before=not_before,
            not_after=not_after,
            auto_renewal=entry.get("auto_renewal", False),
            chain_depth=entry.get("chain_depth", 0),
            environment=entry.get("environment", "production"),
            labels=entry.get("labels", {}),
        )
        if cert.is_expired:
            cert.status = CertStatus.EXPIRED
        elif cert.days_until_expiry <= 30:
            cert.status = CertStatus.EXPIRING_SOON
        if cert.provider == CertProvider.SELF_SIGNED:
            cert.status = CertStatus.SELF_SIGNED
        certs.append(cert)
    return certs


def _parse_date(val) -> datetime:
    if isinstance(val, datetime):
        return val
    if isinstance(val, str) and val:
        for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(val, fmt)
            except ValueError:
                continue
    return datetime.now()
