"""Certificate analyzer — applies CERT-001 to CERT-010 rules."""
from ..models import (
    CERT_RULES,
    Certificate,
    CertProvider,
    CertReport,
    Finding,
    KeyAlgorithm,
)


def analyze_certificates(certificates: list[Certificate]) -> CertReport:
    """Analyze certificates and produce a report."""
    report = CertReport(certificates=certificates)
    for cert in certificates:
        _check_expired(cert, report)
        _check_expiring_7_days(cert, report)
        _check_expiring_30_days(cert, report)
        _check_weak_key(cert, report)
        _check_self_signed_production(cert, report)
        _check_auto_renewal(cert, report)
        _check_expiring_90_days(cert, report)
        _check_wildcard(cert, report)
        _check_missing_san(cert, report)
        _check_long_validity(cert, report)
    report.compute_summary()
    return report


def _make_finding(rule_id: str, cert: Certificate, **overrides) -> Finding:
    rule = CERT_RULES[rule_id]
    return Finding(
        rule_id=rule_id,
        title=overrides.get("title", rule["title"]),
        severity=overrides.get("severity", rule["severity"]),
        domain=cert.domain,
        cert_type=cert.cert_type.value,
        environment=cert.environment,
        description=overrides.get("description", rule["description"]),
        recommendation=overrides.get("recommendation", rule["recommendation"]),
    )


def _check_expired(cert: Certificate, report: CertReport):
    """CERT-001: Certificate expired."""
    if cert.is_expired:
        desc = f"Certificate for {cert.domain} expired {abs(cert.days_until_expiry)} days ago"
        report.findings.append(_make_finding("CERT-001", cert, description=desc))


def _check_expiring_7_days(cert: Certificate, report: CertReport):
    """CERT-002: Expiring within 7 days."""
    if not cert.is_expired and 0 < cert.days_until_expiry <= 7:
        report.findings.append(_make_finding("CERT-002", cert,
            description=f"Certificate for {cert.domain} expires in {cert.days_until_expiry} days"))


def _check_expiring_30_days(cert: Certificate, report: CertReport):
    """CERT-003: Expiring within 30 days."""
    if not cert.is_expired and 7 < cert.days_until_expiry <= 30:
        report.findings.append(_make_finding("CERT-003", cert,
            description=f"Certificate for {cert.domain} expires in {cert.days_until_expiry} days"))


def _check_weak_key(cert: Certificate, report: CertReport):
    """CERT-004: Weak key algorithm."""
    if cert.key_algorithm == KeyAlgorithm.RSA_2048:
        report.findings.append(_make_finding("CERT-004", cert))


def _check_self_signed_production(cert: Certificate, report: CertReport):
    """CERT-005: Self-signed in production."""
    if cert.provider == CertProvider.SELF_SIGNED and cert.environment == "production":
        report.findings.append(_make_finding("CERT-005", cert))


def _check_auto_renewal(cert: Certificate, report: CertReport):
    """CERT-006: No auto-renewal."""
    if not cert.auto_renewal and not cert.is_expired:
        report.findings.append(_make_finding("CERT-006", cert))


def _check_expiring_90_days(cert: Certificate, report: CertReport):
    """CERT-007: Expiring within 90 days."""
    if not cert.is_expired and 30 < cert.days_until_expiry <= 90:
        report.findings.append(_make_finding("CERT-007", cert,
            description=f"Certificate for {cert.domain} expires in {cert.days_until_expiry} days"))


def _check_wildcard(cert: Certificate, report: CertReport):
    """CERT-008: Wildcard certificate."""
    if cert.is_wildcard:
        report.findings.append(_make_finding("CERT-008", cert))


def _check_missing_san(cert: Certificate, report: CertReport):
    """CERT-009: Missing SAN entries."""
    if not cert.san_domains:
        report.findings.append(_make_finding("CERT-009", cert))


def _check_long_validity(cert: Certificate, report: CertReport):
    """CERT-010: Validity exceeds 398 days."""
    validity_days = (cert.not_after - cert.not_before).days
    if validity_days > 398:
        report.findings.append(_make_finding("CERT-010", cert,
            description=f"Certificate validity is {validity_days} days (max recommended: 398)"))
