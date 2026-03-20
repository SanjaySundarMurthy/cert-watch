---
title: "🔒 cert-watch: TLS/SSL Certificate Expiry Scanner"
published: true
description: "A Python CLI that scans certificate inventories for expiry, weak keys, self-signed certs, and renewal gaps with health scoring."
tags: security, tls, devops, certificates
---

## What I Built

**cert-watch** — scans TLS/SSL certificate inventories:

- **10 Validation Rules** — CERT-001 to CERT-010
- **Expiry Tracking** — Expired, 7-day, 30-day, 90-day warnings
- **Security Checks** — Weak keys, self-signed in prod, missing SANs
- **Health Score & Grade** — A-F grading (0-100)

## Test Results

```
41 passed in 0.28s
```

## Links

- **GitHub**: [cert-watch](https://github.com/sanjaysundarmurthy/cert-watch)
- **Part of**: DevOps CLI Tools Suite (Tool 12 of 14)
