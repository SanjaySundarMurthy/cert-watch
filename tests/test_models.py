"""Tests for data models."""
from datetime import datetime, timedelta
from cert_watch.models import (
    Certificate, CertReport, Finding, Severity, CertStatus,
    CertType, CertProvider, KeyAlgorithm, CERT_RULES,
)


class TestCertificate:
    def test_defaults(self):
        c = Certificate()
        assert c.domain == ""
        assert c.status == CertStatus.VALID
        assert not c.is_wildcard

    def test_days_until_expiry(self):
        c = Certificate(not_after=datetime.now() + timedelta(days=30))
        assert 29 <= c.days_until_expiry <= 31

    def test_is_expired(self):
        c = Certificate(not_after=datetime.now() - timedelta(days=1))
        assert c.is_expired

    def test_is_not_expired(self):
        c = Certificate(not_after=datetime.now() + timedelta(days=100))
        assert not c.is_expired

    def test_is_wildcard(self):
        c = Certificate(domain="*.example.com")
        assert c.is_wildcard

    def test_is_not_wildcard(self):
        c = Certificate(domain="api.example.com")
        assert not c.is_wildcard


class TestCertReport:
    def test_compute_summary_no_findings(self):
        report = CertReport(certificates=[Certificate(not_after=datetime.now() + timedelta(days=200))])
        report.compute_summary()
        assert report.total_certs == 1
        assert report.valid_count == 1
        assert report.health_score == 100.0
        assert report.grade == "A"

    def test_compute_summary_with_findings(self):
        report = CertReport(
            certificates=[Certificate()],
            findings=[
                Finding(severity=Severity.CRITICAL),
                Finding(severity=Severity.HIGH),
            ],
        )
        report.compute_summary()
        assert report.critical_count == 1
        assert report.high_count == 1
        assert report.health_score == 75.0
        assert report.grade == "C"

    def test_grade_f(self):
        report = CertReport(findings=[Finding(severity=Severity.CRITICAL)] * 7)
        report.compute_summary()
        assert report.grade == "F"

    def test_expired_count(self):
        now = datetime.now()
        report = CertReport(certificates=[
            Certificate(not_after=now - timedelta(days=10)),
            Certificate(not_after=now + timedelta(days=200)),
        ])
        report.compute_summary()
        assert report.expired_count == 1
        assert report.valid_count == 1

    def test_expiring_soon_count(self):
        now = datetime.now()
        report = CertReport(certificates=[
            Certificate(not_after=now + timedelta(days=15)),
        ])
        report.compute_summary()
        assert report.expiring_soon_count == 1


class TestRules:
    def test_all_rules_exist(self):
        assert len(CERT_RULES) == 10
        for i in range(1, 11):
            assert f"CERT-{i:03d}" in CERT_RULES

    def test_all_severities(self):
        severities = {r["severity"] for r in CERT_RULES.values()}
        assert Severity.CRITICAL in severities
        assert Severity.HIGH in severities
        assert Severity.MEDIUM in severities
        assert Severity.LOW in severities
