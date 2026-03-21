# 🔒 cert-watch

[![CI](https://github.com/SanjaySundarMurthy/cert-watch/actions/workflows/ci.yml/badge.svg)](https://github.com/SanjaySundarMurthy/cert-watch/actions/workflows/ci.yml)
[![Python](https://img.shields.io/pypi/pyversions/cert-watch)](https://pypi.org/project/cert-watch/)
[![PyPI](https://img.shields.io/pypi/v/cert-watch)](https://pypi.org/project/cert-watch/)

**TLS/SSL certificate expiry scanner and renewal tracker.**

Scans certificate inventories against 10 best-practice rules (CERT-001 to CERT-010) covering expiry, weak keys, self-signed certs, auto-renewal, wildcard risks, SAN coverage, and validity periods.

## Installation

```bash
pip install cert-watch
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


## Command Reference

### `cert-watch scan`

Scan a certificate inventory file for security issues.

```bash
cert-watch scan <inventory-file> [OPTIONS]

Options:
  --format [text|json]    Output format (default: text)
  --fail-on [SEVERITY]    Exit with code 1 if findings at this level or above
  --output FILE           Write report to file
```

### `cert-watch demo`

Run a built-in demo with sample certificate inventory to see the tool in action.

```bash
cert-watch demo
```

### `cert-watch rules`

Display all 10 validation rules with severity levels and descriptions.

```bash
cert-watch rules
```

## Sample Output

```
cert-watch v1.0.0 - TLS/SSL Certificate Scanner

Scanning: certs.yaml
Certificates found: 8

  CERT-001 [CRITICAL] Certificate Expired
    â†’ api.example.com expired on 2024-01-15
  CERT-003 [HIGH] Certificate Expiring Within 30 Days
    â†’ auth.example.com expires on 2025-04-10
  CERT-005 [CRITICAL] Self-Signed Certificate in Production
    â†’ internal.example.com uses self-signed cert in production

Score: 45/100 (Grade: F)
Findings: 3 critical, 1 high, 2 medium, 1 low
```

## Inventory File Format

Create a YAML inventory of your certificates:

```yaml
certificates:
  - domain: api.example.com
    expiry: "2025-06-15"
    issuer: "Let's Encrypt"
    key_algorithm: RSA-2048
    auto_renewal: true
    environment: production
    san_entries:
      - api.example.com
      - api-v2.example.com
```

## License

MIT

---

## Author

**Sanjay S** — [GitHub](https://github.com/SanjaySundarMurthy)


## 🐳 Docker

Run without installing Python:

```bash
# Build the image
docker build -t cert-watch .

# Run
docker run --rm cert-watch --help

# Example with volume mount
docker run --rm -v ${PWD}:/workspace cert-watch [command] /workspace
```

Or pull from the container registry:

```bash
docker pull ghcr.io/SanjaySundarMurthy/cert-watch:latest
docker run --rm ghcr.io/SanjaySundarMurthy/cert-watch:latest --help
```

## 🤝 Contributing

Contributions are welcome! Here's how:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

Please ensure tests pass before submitting:

```bash
pip install cert-watch
pytest -v
ruff check .
```

## 🔗 Links

- **PyPI**: [https://pypi.org/project/cert-watch/](https://pypi.org/project/cert-watch/)
- **GitHub**: [https://github.com/SanjaySundarMurthy/cert-watch](https://github.com/SanjaySundarMurthy/cert-watch)
- **Issues**: [https://github.com/SanjaySundarMurthy/cert-watch/issues](https://github.com/SanjaySundarMurthy/cert-watch/issues)