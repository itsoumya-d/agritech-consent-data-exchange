"""Consent-governed farm telemetry normalization, purpose-scoped masking, and exchange audit logging."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
from typing import Any


@dataclass(frozen=True)
class ConsentGrant:
    grant_id: str
    farm_id: str
    partner_id: str
    allowed_scopes: tuple[str, ...]
    expires_at: datetime
    revoked: bool = False


@dataclass(frozen=True)
class NormalizedRecord:
    farm_id: str
    scope: str
    metric_name: str
    value: float
    unit: str
    recorded_at_utc: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ExchangeAuditEntry:
    grant_id: str
    farm_id: str
    partner_id: str
    scope: str
    record_count: int
    payload_sha256: str


_UNIT_FACTORS: dict[tuple[str, str], tuple[float, str]] = {
    ("lb_per_acre", "kg_per_ha"): (1.12085, "kg_per_ha"),
    ("gal_per_cow", "l_per_cow"): (3.78541, "l_per_cow"),
    ("short_ton_per_acre", "t_per_ha"): (2.2417, "t_per_ha"),
}

_SENSITIVE_FIELDS = frozenset({"owner_name", "bank_account", "contract_price_nzd"})


def normalize_farm_metric(
    farm_id: str,
    scope: str,
    metric_name: str,
    raw_value: float,
    raw_unit: str,
    target_unit: str,
    recorded_at: datetime,
    metadata: dict[str, Any] | None = None,
) -> NormalizedRecord:
    """Convert heterogeneous regional farm telemetry into canonical SI metrics and UTC timestamps."""
    if raw_unit == target_unit:
        val, unit = float(raw_value), target_unit
    elif (raw_unit, target_unit) in _UNIT_FACTORS:
        factor, unit = _UNIT_FACTORS[(raw_unit, target_unit)]
        val = round(raw_value * factor, 3)
    else:
        raise ValueError(f"Unsupported unit conversion: {raw_unit} -> {target_unit}")

    utc_ts = recorded_at.astimezone(timezone.utc).isoformat(timespec="seconds")
    return NormalizedRecord(
        farm_id=farm_id,
        scope=scope,
        metric_name=metric_name,
        value=val,
        unit=unit,
        recorded_at_utc=utc_ts,
        metadata=dict(metadata or {}),
    )


def dispatch_consented_exchange(
    grant: ConsentGrant,
    partner_id: str,
    scope: str,
    records: list[NormalizedRecord],
    now: datetime,
) -> tuple[list[dict[str, Any]], ExchangeAuditEntry]:
    """Filter farm records by active farmer consent, redact sensitive metadata, and emit audit hash."""
    if grant.revoked:
        raise PermissionError(f"Consent grant {grant.grant_id} has been revoked.")
    if grant.partner_id != partner_id:
        raise PermissionError(f"Partner {partner_id} does not match grant holder.")
    if now.astimezone(timezone.utc) >= grant.expires_at.astimezone(timezone.utc):
        raise PermissionError(f"Consent grant {grant.grant_id} expired.")
    if scope not in grant.allowed_scopes:
        raise PermissionError(f"Scope '{scope}' not authorized by farmer grant.")

    allow_financial = "financial_metadata" in grant.allowed_scopes
    payload: list[dict[str, Any]] = []

    for rec in records:
        if rec.farm_id != grant.farm_id or rec.scope != scope:
            continue
        clean_meta = {
            k: ("[REDACTED]" if (k in _SENSITIVE_FIELDS and not allow_financial) else v)
            for k, v in rec.metadata.items()
        }
        payload.append(
            {
                "farm_id": rec.farm_id,
                "metric": rec.metric_name,
                "value": rec.value,
                "unit": rec.unit,
                "recorded_at_utc": rec.recorded_at_utc,
                "metadata": clean_meta,
            }
        )

    digest = hashlib.sha256(repr(payload).encode("utf-8")).hexdigest()
    audit = ExchangeAuditEntry(
        grant_id=grant.grant_id,
        farm_id=grant.farm_id,
        partner_id=partner_id,
        scope=scope,
        record_count=len(payload),
        payload_sha256=digest,
    )
    return payload, audit
