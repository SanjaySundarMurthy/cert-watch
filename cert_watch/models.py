"""Data models for certificate analysis."""
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CertStatus(str, Enum):
    VALID = "valid"
    EXPIRING_SOON = "expiring_soon"
    EXPIRED = "expired"
    REVOKED = "revoked"
    SELF_SIGNED = "self_signed"
    UNKNOWN = "unknown"


class CertType(str, Enum):
    DOMAIN = "domain"
    WILDCARD = "wildcard"
    MULTI_SAN = "multi_san"
    CODE_SIGNING = "code_signing"
    CLIENT_AUTH = "client_auth"
    CA = "ca"


class KeyAlgorithm(str, Enum):
    RSA_2048 = "RSA-2048"
    RSA_4096 = "RSA-4096"
    ECDSA_P256 = "ECDSA-P256"
    ECDSA_P384 = "ECDSA-P384"
    ED25519 = "Ed25519"


class CertProvider(str, Enum):
    LETS_ENCRYPT = "lets_encrypt"
    DIGICERT = "digicert"
    COMODO = "comodo"
    GLOBALSIGN = "globalsign"
    AWS_ACM = "aws_acm"
    AZURE_KEYVAULT = "azure_keyvault"
    GCP_CAS = "gcp_cas"
    SELF_SIGNED = "self_signed"
    UNKNOWN = "unknown"


@dataclass
class Certificate:
    domain: str = ""
    common_name: str = ""
    san_domains: list[str] = field(default_factory=list)
    issuer: str = ""
    provider: CertProvider = CertProvider.UNKNOWN
    cert_type: CertType = CertType.DOMAIN
    key_algorithm: KeyAlgorithm = KeyAlgorithm.RSA_2048
    key_size: int = 2048
    serial_number: str = ""
    not_before: datetime = field(default_factory=datetime.now)
    not_after: datetime = field(default_factory=lambda: datetime.now() + timedelta(days=365))
    auto_renewal: bool = False
    status: CertStatus = CertStatus.VALID
    chain_depth: int = 0
    environment: str = "production"
    labels: dict[str, str] = field(default_factory=dict)

    @property
    def days_until_expiry(self) -> int:
        return (self.not_after - datetime.now()).days

    @property
    def is_expired(self) -> bool:
        return self.not_after < datetime.now()

    @property
    def is_wildcard(self) -> bool:
        return self.domain.startswith("*.")


@dataclass
class Finding:
    rule_id: str = ""
    title: str = ""
    severity: Severity = Severity.INFO
    domain: str = ""
    cert_type: str = ""
    environment: str = ""
    description: str = ""
    recommendation: str = ""


@dataclass
class CertReport:
    certificates: list[Certificate] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    total_certs: int = 0
    expired_count: int = 0
    expiring_soon_count: int = 0
    valid_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    health_score: float = 100.0
    grade: str = "A"

    def compute_summary(self):
        self.total_certs = len(self.certificates)
        self.expired_count = sum(1 for c in self.certificates if c.is_expired)
        self.expiring_soon_count = sum(
            1 for c in self.certificates if 0 < c.days_until_expiry <= 30
        )
        self.valid_count = sum(1 for c in self.certificates if c.days_until_expiry > 30)
        self.critical_count = sum(1 for f in self.findings if f.severity == Severity.CRITICAL)
        self.high_count = sum(1 for f in self.findings if f.severity == Severity.HIGH)
        self.medium_count = sum(1 for f in self.findings if f.severity == Severity.MEDIUM)
        self.low_count = sum(1 for f in self.findings if f.severity == Severity.LOW)
        self.info_count = sum(1 for f in self.findings if f.severity == Severity.INFO)
        penalty = (
            (self.critical_count * 15) + (self.high_count * 10)
            + (self.medium_count * 5) + (self.low_count * 2)
        )
        self.health_score = max(0.0, 100.0 - penalty)
        if self.health_score >= 90:
            self.grade = "A"
        elif self.health_score >= 80:
            self.grade = "B"
        elif self.health_score >= 70:
            self.grade = "C"
        elif self.health_score >= 60:
            self.grade = "D"
        else:
            self.grade = "F"


CERT_RULES = {
    "CERT-001": {
        "title": "Certificate Expired",
        "severity": Severity.CRITICAL,
        "description": "Certificate has already expired",
        "recommendation": "Renew the certificate immediately",
    },
    "CERT-002": {
        "title": "Certificate Expiring Within 7 Days",
        "severity": Severity.CRITICAL,
        "description": "Certificate expires in less than 7 days",
        "recommendation": "Renew the certificate urgently",
    },
    "CERT-003": {
        "title": "Certificate Expiring Within 30 Days",
        "severity": Severity.HIGH,
        "description": "Certificate expires within 30 days",
        "recommendation": "Schedule certificate renewal",
    },
    "CERT-004": {
        "title": "Weak Key Algorithm",
        "severity": Severity.HIGH,
        "description": "Certificate uses RSA-2048 or weaker key",
        "recommendation": "Upgrade to RSA-4096 or ECDSA-P256/P384",
    },
    "CERT-005": {
        "title": "Self-Signed Certificate in Production",
        "severity": Severity.CRITICAL,
        "description": "Self-signed certificate used in production environment",
        "recommendation": "Replace with CA-signed certificate",
    },
    "CERT-006": {
        "title": "No Auto-Renewal Configured",
        "severity": Severity.MEDIUM,
        "description": "Certificate lacks automatic renewal configuration",
        "recommendation": "Enable auto-renewal via cert-manager or cloud provider",
    },
    "CERT-007": {
        "title": "Certificate Expiring Within 90 Days",
        "severity": Severity.MEDIUM,
        "description": "Certificate expires within 90 days",
        "recommendation": "Plan certificate renewal in upcoming maintenance window",
    },
    "CERT-008": {
        "title": "Wildcard Certificate Usage",
        "severity": Severity.LOW,
        "description": "Wildcard certificate detected — increases blast radius if compromised",
        "recommendation": "Consider using SAN certificates for specific subdomains",
    },
    "CERT-009": {
        "title": "Missing SAN Entries",
        "severity": Severity.MEDIUM,
        "description": "Certificate has no Subject Alternative Names",
        "recommendation": "Add SAN entries for all served domains",
    },
    "CERT-010": {
        "title": "Long Certificate Validity Period",
        "severity": Severity.LOW,
        "description": "Certificate validity exceeds 398 days (browser limit)",
        "recommendation": "Issue certificates with max 398-day validity",
    },
}
