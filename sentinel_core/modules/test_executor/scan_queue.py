"""Scan run queue state shared by the API and the scan-worker.

The API enqueues ``TestRun`` rows and reports queue/lease health; the scan-worker
claims and executes them. Lease, claim-limit and governance policy live here so
both sides read the same rules.
"""
from __future__ import annotations

import copy
import datetime
import json
import re
from hashlib import sha256
from urllib.parse import urlsplit

from sqlalchemy import select

from sentinel_core.config import settings
from sentinel_core.models.core import TestRun
from sentinel_core.modules.pentest.worker_isolation import (
    configured_worker_isolation_mode,
    worker_kubernetes_namespace,
    worker_kubernetes_service_account,
    worker_resource_limits,
)
from sentinel_core.modules.test_executor.kill_switch import kill_switch_enabled
from sentinel_core.modules.test_executor.target_guard import endpoint_target_url
from sentinel_core.modules.test_executor.worker_validation import build_worker_runtime_validation
from sentinel_core.modules.utils.redactor import Redactor
from sentinel_core.modules.vulnerability_detector.lifecycle import isoformat


_WORKER_ID_SAFE_CHARS = re.compile(r"[^A-Za-z0-9._:@*=-]+")


_ENGINE_EXECUTION_ARTIFACT_TYPES = {
    "templates": "templates_execution",
    "schemathesis": "schemathesis_execution",
    "nuclei": "nuclei_execution",
    "zap": "zap_execution",
    "passive": "passive_findings",
}


_EXTERNAL_ENGINE_ARTIFACT_TYPES = [
    _ENGINE_EXECUTION_ARTIFACT_TYPES["schemathesis"],
    _ENGINE_EXECUTION_ARTIFACT_TYPES["nuclei"],
    _ENGINE_EXECUTION_ARTIFACT_TYPES["zap"],
]


def _utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _lease_seconds() -> int:
    return max(1, int(settings.PENTEST_SCAN_DISPATCH_LEASE_SECONDS))


def _max_claims() -> int:
    return max(1, int(getattr(settings, "PENTEST_SCAN_MAX_CLAIMS", 3)))


def _worker_governance_policy(account_id: int | None) -> dict[str, object]:
    isolation_mode = configured_worker_isolation_mode()
    return {
        "lease_seconds": _lease_seconds(),
        "max_claims": _max_claims(),
        "tenant_scoped": account_id is not None,
        "kill_switch_enforced": True,
        "isolation_mode": isolation_mode,
        "per_run_worker_required": True,
        "kubernetes_job_ready": isolation_mode == "kubernetes_job",
        "kubernetes_namespace": worker_kubernetes_namespace(),
        "kubernetes_service_account": worker_kubernetes_service_account(),
        "resource_limits_required": True,
        "resource_limits": worker_resource_limits(),
    }


def _engine_accountability_policy() -> dict[str, object]:
    return {
        "isolation_model": "leased_external_worker",
        "lease_required": True,
        "worker_identity_required": True,
        "worker_isolation_manifest_required": True,
        "sandbox_cleanup_required": True,
        "artifact_hash_required": True,
        "artifact_verification_required": True,
        "redacted_evidence_required": True,
        "secret_values_persisted": False,
        "external_engine_artifact_types": list(_EXTERNAL_ENGINE_ARTIFACT_TYPES),
    }


def normalize_worker_id(worker_id: str | None) -> str | None:
    """Return a redacted, bounded worker identifier safe for persistence and audit logs."""
    if worker_id is None:
        return None
    normalized = Redactor.redact_text(str(worker_id)).strip()
    normalized = _WORKER_ID_SAFE_CHARS.sub("-", normalized).strip("-")
    if not normalized:
        return None
    return normalized[:100]


async def worker_queue_health(db, *, account_id: int) -> dict[str, object]:
    """Return tenant-scoped queue and lease health for operators."""
    now = _utc_now()
    max_claims = _max_claims()
    result = await db.execute(select(TestRun).where(TestRun.account_id == account_id))
    runs = result.scalars().all()
    pending = [run for run in runs if str(run.status or "").upper() == "PENDING"]
    dispatched = [run for run in runs if str(run.status or "").upper() == "DISPATCHED"]
    running = [run for run in runs if str(run.status or "").upper() == "RUNNING"]
    active = dispatched + running
    failed = [run for run in runs if str(run.status or "").upper() == "FAILED"]
    expired_active = [run for run in active if _lease_expired(run, now)]

    oldest_pending_age_seconds = None
    pending_created = [_as_aware_utc(getattr(run, "created_at", None)) for run in pending]
    pending_created = [created_at for created_at in pending_created if created_at is not None]
    if pending_created:
        oldest_pending_age_seconds = max(0, int((now - min(pending_created)).total_seconds()))

    oldest_expired_lease_age_seconds = None
    expired_lease_times = [
        _as_aware_utc(getattr(run, "dispatch_lease_expires_at", None)) for run in expired_active
    ]
    expired_lease_times = [expires_at for expires_at in expired_lease_times if expires_at is not None]
    if expired_lease_times:
        oldest_expired_lease_age_seconds = max(0, int((now - min(expired_lease_times)).total_seconds()))

    reclaimable_runs = [
        run
        for run in expired_active
        if _is_claimable_run(run, now) and int(run.claim_count or 0) < max_claims
    ]
    dead_letter_ready_runs = [
        run
        for run in runs
        if _is_claimable_run(run, now) and int(run.claim_count or 0) >= max_claims
    ]

    health = {
        "pending_count": len(pending),
        "dispatched_count": len(dispatched),
        "running_count": len(running),
        "active_count": len(active),
        "expired_lease_count": len(expired_active),
        "reclaimable_count": len(reclaimable_runs),
        "dead_letter_ready_count": len(dead_letter_ready_runs),
        "dead_letter_count": sum(1 for run in failed if int(run.error_count or 0) > 0),
        "exhausted_claim_count": sum(1 for run in runs if int(run.claim_count or 0) >= max_claims),
        "oldest_pending_age_seconds": oldest_pending_age_seconds,
        "oldest_expired_lease_age_seconds": oldest_expired_lease_age_seconds,
        "reclaimable_runs": _worker_health_run_samples(reclaimable_runs, now=now, max_claims=max_claims),
        "dead_letter_ready_runs": _worker_health_run_samples(
            dead_letter_ready_runs,
            now=now,
            max_claims=max_claims,
        ),
        "kill_switch_paused": kill_switch_enabled(),
        "lease_seconds": _lease_seconds(),
        "max_claims": max_claims,
        "worker_governance": _worker_governance_policy(account_id),
        "engine_accountability_policy": _engine_accountability_policy(),
    }
    health["runtime_validation"] = build_worker_runtime_validation(queue_health=health)
    return health


def _is_claimable_run(run: TestRun, now: datetime.datetime) -> bool:
    status = str(getattr(run, "status", "") or "").upper()
    if status == "PENDING":
        return True
    if status == "DISPATCHED":
        lease_expires_at = _as_aware_utc(getattr(run, "dispatch_lease_expires_at", None))
        if lease_expires_at is not None:
            return lease_expires_at < now
        stale_before = now - datetime.timedelta(seconds=_lease_seconds())
        started_at = _as_aware_utc(getattr(run, "started_at", None))
        return started_at is None or started_at < stale_before
    if status == "RUNNING":
        return getattr(run, "worker_id", None) is not None and _lease_expired(run, now)
    return False


def _worker_health_run_samples(
    runs: list[TestRun],
    *,
    now: datetime.datetime,
    max_claims: int,
) -> list[dict[str, object]]:
    sorted_runs = sorted(
        runs,
        key=lambda run: (
            _as_aware_utc(getattr(run, "dispatch_lease_expires_at", None)) or now,
            str(getattr(run, "id", "") or ""),
        ),
    )
    return [
        _worker_health_run_sample(run, now=now, max_claims=max_claims)
        for run in sorted_runs[:25]
    ]


def _worker_health_run_sample(
    run: TestRun,
    *,
    now: datetime.datetime,
    max_claims: int,
) -> dict[str, object]:
    lease_expires_at = _as_aware_utc(getattr(run, "dispatch_lease_expires_at", None))
    seconds_since_lease_expired = None
    if lease_expires_at is not None and lease_expires_at < now:
        seconds_since_lease_expired = max(0, int((now - lease_expires_at).total_seconds()))
    sample = {
        "run_id": Redactor.redact_text(str(getattr(run, "id", "") or "")),
        "status": str(getattr(run, "status", "") or "").upper(),
        "worker_id": normalize_worker_id(getattr(run, "worker_id", None)),
        "claim_count": int(getattr(run, "claim_count", None) or 0),
        "max_claims": max_claims,
        "lease_expires_at": isoformat(lease_expires_at),
        "seconds_since_lease_expired": seconds_since_lease_expired,
        "trigger_source": Redactor.redact_text(str(getattr(run, "trigger_source", "") or "")),
        "source_vulnerability_id": Redactor.redact_text(str(getattr(run, "source_vulnerability_id", "") or "")),
        "source_schedule_id": Redactor.redact_text(str(getattr(run, "source_schedule_id", "") or "")),
        "template_count": len(getattr(run, "template_ids", None) or []),
        "endpoint_count": len(getattr(run, "endpoint_ids", None) or []),
    }
    return {
        key: value
        for key, value in sample.items()
        if value not in (None, "")
    }


def _lease_expired(run: TestRun, now: datetime.datetime) -> bool:
    lease_expires_at = _as_aware_utc(getattr(run, "dispatch_lease_expires_at", None))
    return lease_expires_at is not None and lease_expires_at < now


def _as_aware_utc(value: datetime.datetime | None) -> datetime.datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=datetime.timezone.utc)
    return value.astimezone(datetime.timezone.utc)


def worker_spec_digest(spec: dict) -> str:
    return sha256(json.dumps(spec, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def scoped_worker_spec(spec: dict, endpoints: list, target_url: str) -> dict:
    """Constrain spec-driven engines to the selected method/path pairs."""
    if not isinstance(spec, dict):
        raise ValueError("worker_openapi_spec_invalid")
    result = copy.deepcopy(spec)
    base_path = urlsplit(target_url).path.rstrip("/")
    operations = {}
    for endpoint in endpoints:
        if urlsplit(endpoint_target_url(endpoint)).netloc != urlsplit(target_url).netloc:
            raise ValueError("worker_endpoint_outside_target")
        path = str(endpoint.path or "/")
        if base_path and not path.startswith(base_path + "/"):
            raise ValueError("worker_endpoint_outside_base_path")
        operations.setdefault(path[len(base_path):] or "/", set()).add(str(endpoint.method).lower())
    result["paths"] = {
        path: {key: value for key, value in item.items() if key in operations[path] or key == "parameters"}
        for path, item in (result.get("paths") or {}).items()
        if path in operations and isinstance(item, dict)
    }
    if not any(any(method in item for method in operations[path]) for path, item in result["paths"].items()):
        raise ValueError("worker_spec_has_no_selected_operations")
    def sanitize(node):
        if isinstance(node, dict):
            ref = node.get("$ref")
            if isinstance(ref, str) and not ref.startswith("#/"):
                raise ValueError("worker_external_spec_reference_blocked")
            for key in ("servers", "callbacks", "webhooks"):
                node.pop(key, None)
            for value in node.values():
                sanitize(value)
        elif isinstance(node, list):
            for value in node:
                sanitize(value)
    sanitize(result)
    result["servers"] = [{"url": target_url}]
    return result
