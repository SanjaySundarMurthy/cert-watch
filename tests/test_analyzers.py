"""Tests for certificate analyzer and parser."""
from cert_watch.parser import parse_inventory
from cert_watch.analyzers.cert_analyzer import analyze_certificates
from cert_watch.models import Severity


class TestParser:
    def test_parse_inventory(self, sample_inventory_yaml):
        certs = parse_inventory(sample_inventory_yaml)
        assert len(certs) == 2

    def test_parse_empty(self):
        assert parse_inventory("") == []

    def test_parse_good_cert(self, sample_inventory_yaml):
        certs = parse_inventory(sample_inventory_yaml)
        good = [c for c in certs if c.domain == "good.example.com"][0]
        assert good.auto_renewal is True
        assert len(good.san_domains) == 1

    def test_parse_bad_cert(self, sample_inventory_yaml):
        certs = parse_inventory(sample_inventory_yaml)
        bad = [c for c in certs if c.domain == "bad.example.com"][0]
        assert bad.is_expired


class TestCertAnalyzer:
    def test_cert001_expired(self, expired_cert):
        report = analyze_certificates([expired_cert])
        rule_ids = [f.rule_id for f in report.findings]
        assert "CERT-001" in rule_ids

    def test_cert002_expiring_7_days(self, expiring_soon_cert):
        report = analyze_certificates([expiring_soon_cert])
        rule_ids = [f.rule_id for f in report.findings]
        assert "CERT-002" in rule_ids

    def test_cert003_expiring_30_days(self, expiring_30_cert):
        report = analyze_certificates([expiring_30_cert])
        rule_ids = [f.rule_id for f in report.findings]
        assert "CERT-003" in rule_ids

    def test_cert004_weak_key(self, expired_cert):
        report = analyze_certificates([expired_cert])
        rule_ids = [f.rule_id for f in report.findings]
        assert "CERT-004" in rule_ids

    def test_cert004_strong_key_no_finding(self, healthy_cert):
        report = analyze_certificates([healthy_cert])
        rule_ids = [f.rule_id for f in report.findings]
        assert "CERT-004" not in rule_ids

    def test_cert005_self_signed_prod(self, self_signed_prod):
        report = analyze_certificates([self_signed_prod])
        rule_ids = [f.rule_id for f in report.findings]
        assert "CERT-005" in rule_ids

    def test_cert006_no_auto_renewal(self, expiring_30_cert):
        report = analyze_certificates([expiring_30_cert])
        rule_ids = [f.rule_id for f in report.findings]
        assert "CERT-006" in rule_ids

    def test_cert006_has_auto_renewal(self, healthy_cert):
        report = analyze_certificates([healthy_cert])
        rule_ids = [f.rule_id for f in report.findings]
        assert "CERT-006" not in rule_ids

    def test_cert007_expiring_90_days(self, expiring_90_cert):
        report = analyze_certificates([expiring_90_cert])
        rule_ids = [f.rule_id for f in report.findings]
        assert "CERT-007" in rule_ids

    def test_cert008_wildcard(self, wildcard_cert):
        report = analyze_certificates([wildcard_cert])
        rule_ids = [f.rule_id for f in report.findings]
        assert "CERT-008" in rule_ids

    def test_cert009_missing_san(self, self_signed_prod):
        report = analyze_certificates([self_signed_prod])
        rule_ids = [f.rule_id for f in report.findings]
        assert "CERT-009" in rule_ids

    def test_cert009_has_san(self, healthy_cert):
        report = analyze_certificates([healthy_cert])
        rule_ids = [f.rule_id for f in report.findings]
        assert "CERT-009" not in rule_ids

    def test_cert010_long_validity(self, long_validity_cert):
        report = analyze_certificates([long_validity_cert])
        rule_ids = [f.rule_id for f in report.findings]
        assert "CERT-010" in rule_ids

    def test_healthy_cert_minimal_findings(self, healthy_cert):
        report = analyze_certificates([healthy_cert])
        # Healthy cert: ECDSA-P256, auto-renewal, has SANs, valid >90 days, 365-day validity
        assert report.health_score >= 90

    def test_report_grade(self, expired_cert, self_signed_prod):
        report = analyze_certificates([expired_cert, self_signed_prod])
        assert report.grade in ("D", "F")
