"""Shared test fixtures for cert-watch."""
import pytest
from datetime import datetime, timedelta
from cert_watch.models import (
    Certificate, CertType, CertProvider, KeyAlgorithm, CertStatus, Severity,
)


@pytest.fixture
def now():
    return datetime.now()


@pytest.fixture
def expired_cert(now):
    return Certificate(
        domain="expired.example.com",
        issuer="Self-Signed",
        provider=CertProvider.SELF_SIGNED,
        key_algorithm=KeyAlgorithm.RSA_2048,
        not_before=now - timedelta(days=400),
        not_after=now - timedelta(days=10),
        auto_renewal=False,
        environment="production",
    )


@pytest.fixture
def expiring_soon_cert(now):
    return Certificate(
        domain="expiring.example.com",
        issuer="DigiCert",
        provider=CertProvider.DIGICERT,
        key_algorithm=KeyAlgorithm.RSA_2048,
        not_before=now - timedelta(days=300),
        not_after=now + timedelta(days=5),
        auto_renewal=False,
        environment="production",
    )


@pytest.fixture
def expiring_30_cert(now):
    return Certificate(
        domain="expiring30.example.com",
        issuer="DigiCert",
        provider=CertProvider.DIGICERT,
        key_algorithm=KeyAlgorithm.RSA_4096,
        not_before=now - timedelta(days=200),
        not_after=now + timedelta(days=20),
        auto_renewal=False,
        san_domains=["expiring30.example.com"],
        environment="staging",
    )


@pytest.fixture
def expiring_90_cert(now):
    return Certificate(
        domain="expiring90.example.com",
        issuer="Let's Encrypt",
        provider=CertProvider.LETS_ENCRYPT,
        key_algorithm=KeyAlgorithm.ECDSA_P256,
        not_before=now - timedelta(days=200),
        not_after=now + timedelta(days=60),
        auto_renewal=True,
        san_domains=["expiring90.example.com"],
        environment="production",
    )


@pytest.fixture
def healthy_cert(now):
    return Certificate(
        domain="healthy.example.com",
        issuer="Let's Encrypt",
        provider=CertProvider.LETS_ENCRYPT,
        key_algorithm=KeyAlgorithm.ECDSA_P256,
        not_before=now - timedelta(days=30),
        not_after=now + timedelta(days=335),
        auto_renewal=True,
        san_domains=["healthy.example.com", "www.healthy.example.com"],
        environment="production",
    )


@pytest.fixture
def wildcard_cert(now):
    return Certificate(
        domain="*.example.com",
        issuer="GlobalSign",
        provider=CertProvider.GLOBALSIGN,
        key_algorithm=KeyAlgorithm.RSA_4096,
        not_before=now - timedelta(days=30),
        not_after=now + timedelta(days=335),
        auto_renewal=True,
        san_domains=["*.example.com"],
        environment="production",
    )


@pytest.fixture
def self_signed_prod(now):
    return Certificate(
        domain="internal.example.com",
        issuer="Self-Signed",
        provider=CertProvider.SELF_SIGNED,
        key_algorithm=KeyAlgorithm.RSA_2048,
        not_before=now - timedelta(days=100),
        not_after=now + timedelta(days=500),
        auto_renewal=False,
        environment="production",
    )


@pytest.fixture
def long_validity_cert(now):
    return Certificate(
        domain="long.example.com",
        issuer="DigiCert",
        provider=CertProvider.DIGICERT,
        key_algorithm=KeyAlgorithm.RSA_4096,
        not_before=now - timedelta(days=10),
        not_after=now + timedelta(days=700),
        auto_renewal=True,
        san_domains=["long.example.com"],
        environment="production",
    )


@pytest.fixture
def sample_inventory_yaml(now):
    nb = (now - timedelta(days=30)).strftime("%Y-%m-%d")
    na = (now + timedelta(days=200)).strftime("%Y-%m-%d")
    exp = (now - timedelta(days=5)).strftime("%Y-%m-%d")
    return f"""certificates:
  - domain: good.example.com
    common_name: good.example.com
    san_domains:
      - good.example.com
    issuer: Let's Encrypt
    provider: lets_encrypt
    cert_type: domain
    key_algorithm: ECDSA-P256
    not_before: "{nb}"
    not_after: "{na}"
    auto_renewal: true
    environment: production
  - domain: bad.example.com
    common_name: bad.example.com
    san_domains: []
    issuer: Self-Signed
    provider: self_signed
    cert_type: domain
    key_algorithm: RSA-2048
    not_before: "{nb}"
    not_after: "{exp}"
    auto_renewal: false
    environment: production
"""
