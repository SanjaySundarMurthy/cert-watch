# 🔒 cert-watch

**TLS/SSL certificate expiry scanner and renewal tracker.**

Scans certificate inventories against 10 best-practice rules (CERT-001 to CERT-010) covering expiry, weak keys, self-signed certs, auto-renewal, wildcard risks, SAN coverage, and validity periods.

## Installation

```bash
pip install -e .
```

## Usage

```bash
# Scan certificate inventory
cert-watch scan certs.yaml

# Fail on critical findings (CI/CD gate)
cert-watch scan certs.yaml --fail-on critical

# JSON output
cert-watch scan certs.yaml --format json

# Run demo
cert-watch demo

# List rules
cert-watch rules
```

## Rules

| Rule | Severity | Title |
|------|----------|-------|
| CERT-001 | CRITICAL | Certificate Expired |
| CERT-002 | CRITICAL | Certificate Expiring Within 7 Days |
| CERT-003 | HIGH | Certificate Expiring Within 30 Days |
| CERT-004 | HIGH | Weak Key Algorithm |
| CERT-005 | CRITICAL | Self-Signed Certificate in Production |
| CERT-006 | MEDIUM | No Auto-Renewal Configured |
| CERT-007 | MEDIUM | Certificate Expiring Within 90 Days |
| CERT-008 | LOW | Wildcard Certificate Usage |
| CERT-009 | MEDIUM | Missing SAN Entries |
| CERT-010 | LOW | Long Certificate Validity Period |

## License

MIT

---

## Author

**Sanjay S** — [GitHub](https://github.com/SanjaySundarMurthy)
