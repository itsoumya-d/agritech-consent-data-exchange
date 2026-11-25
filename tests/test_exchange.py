from datetime import datetime, timedelta, timezone
import pytest

from agri_exchange.exchange import ConsentGrant, dispatch_consented_exchange, normalize_farm_metric

UTC = timezone.utc


def _dt(days_offset: int = 0) -> datetime:
    return datetime(2026, 11, 25, 12, 0, 0, tzinfo=UTC) + timedelta(days=days_offset)


def test_normalize_farm_units_and_redact_sensitive_fields_under_agronomy_scope():
    rec = normalize_farm_metric(
        farm_id="farm-nz-101",
        scope="nutrient",
        metric_name="nitrogen_applied",
        raw_value=100.0,
        raw_unit="lb_per_acre",
        target_unit="kg_per_ha",
        recorded_at=_dt(),
        metadata={"paddock": "P4", "owner_name": "R. Smith", "contract_price_nzd": 18500},
    )
    assert rec.value == 112.085
    assert rec.unit == "kg_per_ha"

    grant = ConsentGrant("g-1", "farm-nz-101", "sustainability-auditor", ("nutrient",), expires_at=_dt(30))
    payload, audit = dispatch_consented_exchange(grant, "sustainability-auditor", "nutrient", [rec], now=_dt())
    assert len(payload) == 1
    assert payload[0]["metadata"] == {"paddock": "P4", "owner_name": "[REDACTED]", "contract_price_nzd": "[REDACTED]"}
    assert audit.record_count == 1
    assert len(audit.payload_sha256) == 64


def test_revoked_expired_or_unauthorized_scope_raises_permission_error():
    rec = normalize_farm_metric("farm-1", "milk", "yield", 24.5, "l_per_cow", "l_per_cow", _dt())

    revoked = ConsentGrant("g-rev", "farm-1", "p1", ("milk",), _dt(10), revoked=True)
    with pytest.raises(PermissionError, match="revoked"):
        dispatch_consented_exchange(revoked, "p1", "milk", [rec], now=_dt())

    expired = ConsentGrant("g-exp", "farm-1", "p1", ("milk",), _dt(-1))
    with pytest.raises(PermissionError, match="expired"):
        dispatch_consented_exchange(expired, "p1", "milk", [rec], now=_dt())

    wrong_scope = ConsentGrant("g-sc", "farm-1", "p1", ("nutrient",), _dt(10))
    with pytest.raises(PermissionError, match="Scope 'milk'"):
        dispatch_consented_exchange(wrong_scope, "p1", "milk", [rec], now=_dt())
