# 🔒 cert-watch

[![CI](https://github.com/SanjaySundarMurthy/cert-watch/actions/workflows/ci.yml/badge.svg)](https://github.com/SanjaySundarMurthy/cert-watch/actions/workflows/ci.yml)
[![Python](https://img.shields.io/pypi/pyversions/cert-watch)](https://pypi.org/project/cert-watch/)
[![PyPI](https://img.shields.io/pypi/v/cert-watch)](https://pypi.org/project/cert-watch/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**TLS/SSL certificate expiry scanner and renewal tracker.**

Scans certificate inventories against **10 best-practice rules** (CERT-001 to CERT-010) covering expiry windows, weak keys, self-signed certs, auto-renewal gaps, wildcard risks, SAN coverage, and excessive validity periods.

---

## Features

- **10 Security Rules** — CERT-001 to CERT-010 covering critical-to-low findings
- **YAML Inventory Scanning** — Declarative certificate inventory as code
- **Multiple Output Formats** — Rich terminal tables, JSON, and HTML reports
- **CI/CD Gate** — `--fail-on` flag for pipeline integration
- **Health Scoring** — 0–100 health score with letter grades (A through F)
- **Built-in Demo** — Try instantly with `cert-watch demo`
- **File Export** — Save reports to file with `--output`

---

## Installation

```bash
pip install cert-watch
```

---

## Quick Start

```bash
# Scan certificate inventory
cert-watch scan certs.yaml

# Fail on critical findings (CI/CD gate)
cert-watch scan certs.yaml --fail-on critical

# JSON output
cert-watch scan certs.yaml --format json

# HTML report to file
cert-watch scan certs.yaml --format html --output report.html

# Run demo with sample data
cert-watch demo

# List all rules
cert-watch rules
```

---

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

---

## Commands

### `cert-watch scan`

Scan a certificate inventory file for security issues.

```bash
cert-watch scan <inventory-file> [OPTIONS]

Options:
  --format [terminal|json|html]   Output format (default: terminal)
  --fail-on [SEVERITY]            Exit with code 1 if findings at this level or above
                                  Choices: critical, high, medium, low
  --output, -o FILE               Write report to file
```

### `cert-watch demo`

Run a built-in demo with sample certificate inventory to see the tool in action.

```bash
cert-watch demo [OPTIONS]

Options:
  --format [terminal|json|html]   Output format (default: terminal)
```

### `cert-watch rules`

Display all 10 validation rules with severity levels and descriptions.

```bash
cert-watch rules
```

---

## Inventory File Format

Create a YAML inventory of your certificates:

```yaml
certificates:
  - domain: api.example.com
    common_name: api.example.com
    san_domains:
      - api.example.com
      - api-v2.example.com
    issuer: "Let's Encrypt"
    provider: lets_encrypt
    cert_type: multi_san
    key_algorithm: RSA-4096
    not_before: "2025-01-01"
    not_after: "2025-12-31"
    auto_renewal: true
    environment: production
```

### Supported Fields

| Field | Type | Description |
|-------|------|-------------|
| `domain` | string | Primary domain name |
| `common_name` | string | Certificate common name |
| `san_domains` | list | Subject Alternative Name entries |
| `issuer` | string | Certificate issuer |
| `provider` | string | Certificate provider (see below) |
| `cert_type` | string | `domain`, `wildcard`, `multi_san`, `code_signing`, `client_auth`, `ca` |
| `key_algorithm` | string | `RSA-2048`, `RSA-4096`, `ECDSA-P256`, `ECDSA-P384`, `Ed25519` |
| `not_before` | date | Certificate validity start date |
| `not_after` | date | Certificate expiry date |
| `auto_renewal` | bool | Whether auto-renewal is configured |
| `environment` | string | Deployment environment (e.g., `production`, `staging`) |

### Supported Providers

`lets_encrypt`, `digicert`, `comodo`, `globalsign`, `aws_acm`, `azure_keyvault`, `gcp_cas`, `self_signed`

---

## Health Scoring

The health score (0–100) is calculated from finding severity:

| Severity | Penalty |
|----------|---------|
| Critical | −15 points each |
| High | −10 points each |
| Medium | −5 points each |
| Low | −2 points each |

| Grade | Score Range |
|-------|------------|
| A | 90–100 |
| B | 80–89 |
| C | 70–79 |
| D | 60–69 |
| F | 0–59 |

---

## Sample Output

```
╭──────────── 🔒 Certificate Watch Report ────────────╮
│ Certificates: 6                                      │
│ Valid: 2 | Expiring Soon: 2 | Expired: 1             │
│ Health Score: 45.0/100 (Grade F)                     │
│ Findings: 12 (🔴 3 🟠 2 🟡 4 🔵 2 ⚪ 0)              │
╰──────────────────────────────────────────────────────╯

┌──────────┬──────────┬─────────────────────┬───────────────────────────┬──────────────────────────┐
│ Rule     │ Severity │ Domain              │ Issue                     │ Recommendation           │
├──────────┼──────────┼─────────────────────┼───────────────────────────┼──────────────────────────┤
│ CERT-001 │ CRITICAL │ legacy.example.com  │ Certificate expired       │ Renew immediately        │
│ CERT-003 │ HIGH     │ staging.example.com │ Expires in 20 days        │ Schedule renewal         │
│ CERT-005 │ CRITICAL │ internal.example.com│ Self-signed in production │ Replace with CA-signed   │
└──────────┴──────────┴─────────────────────┴───────────────────────────┴──────────────────────────┘
```

---

## CI/CD Integration

### GitHub Actions

```yaml
- name: Certificate Audit
  run: |
    pip install cert-watch
    cert-watch scan certs.yaml --fail-on critical
```

### Pre-commit Hook

```yaml
repos:
  - repo: local
    hooks:
      - id: cert-watch
        name: Certificate Watch
        entry: cert-watch scan certs.yaml --fail-on high
        language: system
        pass_filenames: false
```

---

## Project Structure

```
cert-watch/
├── cert_watch/
│   ├── __init__.py
│   ├── cli.py                    # Click CLI entry point
│   ├── models.py                 # Data models & 10 rule definitions
│   ├── parser.py                 # YAML inventory parser
│   ├── demo.py                   # Demo data generator
│   ├── analyzers/
│   │   └── cert_analyzer.py      # Rule engine (CERT-001 to CERT-010)
│   └── reporters/
│       ├── terminal_reporter.py  # Rich terminal output
│       └── export_reporter.py    # JSON & HTML export
├── tests/                        # 41 tests
│   ├── conftest.py
│   ├── test_analyzers.py
│   ├── test_cli.py
│   └── test_models.py
├── Dockerfile
├── pyproject.toml
└── README.md
```

---

## 🐳 Docker

Run without installing Python:

```bash
# Build the image
docker build -t cert-watch .

# Run
docker run --rm cert-watch --help

# Scan with volume mount
docker run --rm -v ${PWD}:/workspace cert-watch scan /workspace/certs.yaml
```

Or pull from the container registry:

```bash
docker pull ghcr.io/sanjaysundarmurthy/cert-watch:latest
docker run --rm ghcr.io/sanjaysundarmurthy/cert-watch:latest --help
```

---

## Development

```bash
git clone https://github.com/SanjaySundarMurthy/cert-watch.git
cd cert-watch
pip install -e ".[dev]"
pytest -v
ruff check .
```

---

## 🤝 Contributing

Contributions are welcome! Here's how:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

Please ensure tests pass before submitting:

```bash
pytest -v
ruff check .
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Author

**Sanjay S** — [GitHub](https://github.com/SanjaySundarMurthy)

## 🔗 Links

- **PyPI**: [https://pypi.org/project/cert-watch/](https://pypi.org/project/cert-watch/)
- **GitHub**: [https://github.com/SanjaySundarMurthy/cert-watch](https://github.com/SanjaySundarMurthy/cert-watch)
- **Issues**: [https://github.com/SanjaySundarMurthy/cert-watch/issues](https://github.com/SanjaySundarMurthy/cert-watch/issues)
