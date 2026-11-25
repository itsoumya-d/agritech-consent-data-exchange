# Consent-Governed Agricultural Data Exchange

Farmer-permissioned agricultural telemetry normalization, purpose-scoped field masking, and auditable third-party sharing engine.

## Problem

Modern farm data ecosystems connect machinery OEMs, milk processors, agronomy tools, and sustainability auditors, creating three recurring engineering challenges:

1. **Fragmented schemas & units**: Inconsistent imperial/metric farm metrics across soil nutrient, herd milk-volume, and paddock harvest feeds.
2. **Enforced farmer consent**: Third-party consumers must never bypass active consent grants, permitted metric scopes, or expiration timestamps.
3. **Privacy & auditability**: Restricting financial/owner metadata when sharing agronomic insights with sustainability or finance partners while logging every authorized read.

## Running Tests

```bash
PYTHONPATH=src python3 -m pytest -v
```
