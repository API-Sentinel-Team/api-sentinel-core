"""Scan planning shared by the API (request time) and the scan-worker (execution time).

Builds the hashed, readable scan plan persisted on a ``TestRun``, and summarizes
it for audit logs. Nothing here sends traffic to scan targets.
"""
from __future__ import annotations

import shutil

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel_core.models.core import APIEndpoint, OpenAPISpec
from sentinel_core.modules.auth.audit import log_action
from sentinel_core.modules.business_logic.active_tests import (
    ACTIVE_BUSINESS_LOGIC_TEMPLATE_ID,
    build_active_business_logic_templates,
)
from sentinel_core.modules.business_logic.graph_builder import get_latest_graph
from sentinel_core.modules.pentest.auth_preflight import active_scan_auth_required
from sentinel_core.modules.pentest.engine_plan import (
    ENGINE_EXECUTION_ORDER,
    build_engine_plan,
    engine_outcome_summaries,
    engine_status_counts,
)
from sentinel_core.modules.test_executor.scan_plan import (
    build_readable_scan_plan,
    finalize_scan_plan_hash,
    verify_scan_plan_integrity,
)
from sentinel_core.modules.utils.redactor import Redactor


_SCAN_PLAN_COVERAGE_TARGETS = ("authorization", "business_logic", "llm_api")


_SCAN_PLAN_COVERAGE_STATUSES = {"available", "discovered", "gap", "not_requested", "partial", "ready"}


_SCAN_PLAN_COVERAGE_SIGNALS = {
    "auth_context",
    "body_key",
    "path_hint",
    "private_identifier",
    "role_context",
    "state_changing_method",
    "tool_context",
    "workflow_path",
}


_SCAN_PLAN_COVERAGE_READINESS_KEYS = {
    "auth_context_ready",
    "bfla_replay_testable",
    "bola_replay_testable",
    "private_identifier_context_ready",
    "prompt_context_ready",
    "role_context_ready",
    "state_change_context_ready",
    "tool_abuse_testable",
    "tool_context_ready",
    "workflow_abuse_testable",
    "workflow_context_ready",
}


_ACTIVE_TEST_FAMILIES = (
    "coupon_abuse",
    "otp_spam",
    "workflow_bypass",
    "resource_exhaustion",
    "prompt_injection",
    "rag_exfiltration",
    "indirect_prompt_injection",
    "dangerous_tool_invocation",
    "privilege_escalating_tool_invocation",
    "tool_chain_injection",
)


_ACTIVE_TEST_FAMILY_STATUSES = {"ready", "missing_template", "missing_endpoint_context"}


_ACTIVE_TEST_FAMILY_SIGNALS = {
    "body_key",
    "bulk",
    "captcha",
    "cart",
    "checkout",
    "coupon",
    "discount",
    "export",
    "invoice",
    "mfa",
    "order",
    "otp",
    "path_hint",
    "payment",
    "promo",
    "referral",
    "retrieval_context",
    "search",
    "subscription",
    "tool_invocation_context",
    "tool_output_context",
    "untrusted_context",
    "upload",
    "verification",
}


async def audit_scan_event(
    db: AsyncSession,
    *,
    action: str,
    account_id: int,
    run_id: str,
    user_id: str | None = None,
    details: dict | None = None,
    ip_address: str | None = None,
) -> None:
    await log_action(
        db=db,
        account_id=account_id,
        action=action,
        user_id=user_id,
        resource_type="test_run",
        resource_id=run_id,
        details=details or {},
        ip_address=ip_address,
    )


def planned_test_count(template_ids: list[str], endpoint_ids: list[str]) -> int:
    return len(template_ids) * len(endpoint_ids)


def templates_for_scan_plan(templates: list[dict], template_ids: list[str]) -> list[dict]:
    by_id = {str(template.get("id")): template for template in templates if isinstance(template, dict)}
    return [by_id.get(str(template_id)) or {"id": str(template_id), "info": {}} for template_id in template_ids]


def scan_plan_generated_templates(scan_plan: dict | None) -> list[dict]:
    if not isinstance(scan_plan, dict):
        return []
    generated = scan_plan.get("generated_templates")
    if not isinstance(generated, list):
        return []
    return [template for template in generated if isinstance(template, dict) and template.get("id")]


def runtime_templates_for_run(base_templates: list[dict], template_ids: list[str], scan_plan: dict | None) -> list[dict]:
    template_map = {
        str(template.get("id")): template
        for template in [*base_templates, *scan_plan_generated_templates(scan_plan)]
        if isinstance(template, dict) and template.get("id")
    }
    return [template_map[str(template_id)] for template_id in template_ids if str(template_id) in template_map]


async def expand_active_business_logic_templates(
    db: AsyncSession,
    *,
    account_id: int,
    template_ids: list[str],
    endpoints: list[APIEndpoint],
    base_templates: list[dict],
    test_intensity: str | None,
) -> tuple[list[str], list[dict], list[dict]]:
    if ACTIVE_BUSINESS_LOGIC_TEMPLATE_ID not in {str(template_id) for template_id in template_ids}:
        return template_ids, base_templates, []

    base_ids = [str(template_id) for template_id in template_ids if str(template_id) != ACTIVE_BUSINESS_LOGIC_TEMPLATE_ID]
    graph = await get_latest_graph(db, account_id)
    generated_templates = build_active_business_logic_templates(
        endpoints,
        graph=graph,
        test_intensity=test_intensity,
    )
    generated_ids = [str(template["id"]) for template in generated_templates]
    return [*base_ids, *generated_ids], [*base_templates, *generated_templates], generated_templates


def endpoint_scan_plan_context(endpoint: APIEndpoint, *, account_id: int) -> dict:
    return {
        "id": endpoint.id,
        "method": endpoint.method,
        "url": f"{endpoint.protocol or 'http'}://{endpoint.host}{endpoint.path}",
        "path": endpoint.path,
        "host": endpoint.host or "",
        "protocol": endpoint.protocol or "http",
        "last_response_body": endpoint.last_response_body,
        "last_request_body": endpoint.last_request_body,
        "last_query_string": endpoint.last_query_string,
        "last_response_code": endpoint.last_response_code,
        "last_response_headers": endpoint.last_response_headers or {},
        "auth_types_found": endpoint.auth_types_found or [],
        "private_variable_count": endpoint.private_variable_count or 0,
        "account_id": account_id,
    }


def engine_runtime_availability() -> dict[str, bool]:
    """Report which external scan engine CLIs are installed in this process's image."""
    return {
        "schemathesis": shutil.which("schemathesis") is not None,
        "nuclei": shutil.which("nuclei") is not None,
        "zap": any(shutil.which(name) for name in ("zap.sh", "zap.cmd", "zap.bat")),
    }


async def account_has_openapi_spec(db: AsyncSession, *, account_id: int) -> bool:
    result = await db.execute(
        select(OpenAPISpec.id)
        .where(OpenAPISpec.account_id == account_id)
        .limit(1)
    )
    return result.scalar_one_or_none() is not None


def build_scan_plan_for_run(
    *,
    templates: list[dict],
    template_ids: list[str],
    endpoints: list[APIEndpoint],
    account_id: int,
    test_intensity: str | None,
    profile: object | None,
    roles_context: dict | None = None,
    auth_profile: object | None = None,
    has_openapi_spec: bool = False,
    engine_availability: dict[str, bool] | None = None,
    generated_templates: list[dict] | None = None,
    test_accounts_count: int = 0,
    external_engine_scope: dict | None = None,
) -> dict:
    scan_plan = build_readable_scan_plan(
        templates=templates_for_scan_plan(templates, template_ids),
        endpoints=[
            endpoint_scan_plan_context(endpoint, account_id=account_id)
            for endpoint in endpoints
        ],
        roles_context=roles_context,
        test_intensity=test_intensity,
        profile=profile,
    )
    runtime_availability = engine_availability or engine_runtime_availability()
    scan_plan["engine_plan"] = build_engine_plan(
        profile=profile,
        auth_profile=auth_profile,
        has_openapi_spec=has_openapi_spec,
        schemathesis_available=bool(runtime_availability.get("schemathesis")),
        nuclei_available=bool(runtime_availability.get("nuclei")),
        zap_available=bool(runtime_availability.get("zap")),
        require_authenticated_active_scan=active_scan_auth_required(),
        test_accounts_count=test_accounts_count,
    )
    authorization = scan_plan.get("coverage_targets", {}).get("authorization", {})
    authorization_readiness = authorization.get("readiness", {}) if isinstance(authorization, dict) else {}
    replay_ready = bool(
        test_accounts_count >= 2
        and (
            authorization_readiness.get("bola_replay_testable")
            or authorization_readiness.get("bfla_replay_testable")
        )
    )
    replay_endpoint_ids = [
        str(endpoint.id)
        for endpoint in endpoints
        if str(endpoint.id)
        and bool(endpoint.auth_types_found)
        and (
            int(endpoint.private_variable_count or 0) > 0
            or "{" in str(endpoint.path or "")
            or str(endpoint.method or "").upper() in {"POST", "PUT", "PATCH", "DELETE"}
        )
    ]
    for entry in scan_plan["engine_plan"]:
        if entry.get("engine") == "authorization_replay" and entry.get("status") == "ready":
            if not replay_ready or not replay_endpoint_ids:
                entry.update(status="blocked", reason="no_authorization_replay_targets")
    scan_plan["authorization_replay"] = {
        "endpoint_ids": replay_endpoint_ids,
        "selection_reason": "authenticated_private_identifier_or_state_change_surface",
        "ready": replay_ready and bool(replay_endpoint_ids),
    }
    if external_engine_scope:
        scan_plan["external_engine_scope"] = external_engine_scope
    else:
        for entry in scan_plan["engine_plan"]:
            if entry["engine"] in {"schemathesis", "nuclei", "zap"} and entry["status"] == "ready":
                entry.update(status="blocked", reason="external_engine_scope_required")
    if generated_templates:
        safe_generated = Redactor.redact_json(generated_templates)
        scan_plan["generated_templates"] = safe_generated if isinstance(safe_generated, list) else []
    return finalize_scan_plan_hash(scan_plan)


def scan_plan_engine_audit_summary(scan_plan: dict) -> dict:
    raw_engine_plan = scan_plan_engine_plan(scan_plan)
    if not raw_engine_plan:
        return {}

    engine_plan = Redactor.redact_json(raw_engine_plan)
    if not isinstance(engine_plan, list):
        return {}
    entries = {
        str(item.get("engine")): item
        for item in engine_plan
        if isinstance(item, dict) and str(item.get("engine")) in ENGINE_EXECUTION_ORDER
    }
    ready_active_engines = [
        engine
        for engine in ENGINE_EXECUTION_ORDER
        if engine != "passive" and entries.get(engine, {}).get("status") == "ready"
    ]
    blocked_engines = [
        engine
        for engine in ENGINE_EXECUTION_ORDER
        if entries.get(engine, {}).get("status") == "blocked"
    ]
    disabled_engines = [
        engine
        for engine in ENGINE_EXECUTION_ORDER
        if entries.get(engine, {}).get("status") == "disabled"
    ]
    continuous_engines = [
        engine
        for engine in ENGINE_EXECUTION_ORDER
        if entries.get(engine, {}).get("status") in {"available", "continuous"}
    ]
    required_artifacts = [
        {
            "engine": engine,
            "artifact_type": str(entries[engine].get("artifact_type")),
        }
        for engine in ready_active_engines
        if entries.get(engine, {}).get("artifact_type")
    ]
    return {
        "engine_status_counts": engine_status_counts(engine_plan),
        "ready_active_engines": ready_active_engines,
        "blocked_engines": blocked_engines,
        "disabled_engines": disabled_engines,
        "continuous_engines": continuous_engines,
        "required_artifacts": required_artifacts,
        "engine_outcomes": engine_outcome_summaries(engine_plan),
    }


def scan_plan_engine_plan(scan_plan: dict | None) -> list[dict]:
    if not isinstance(scan_plan, dict):
        return []
    raw_engine_plan = scan_plan.get("engine_plan")
    if not isinstance(raw_engine_plan, list):
        return []
    return [
        dict(item)
        for item in raw_engine_plan
        if isinstance(item, dict) and str(item.get("engine")) in ENGINE_EXECUTION_ORDER
    ]


def execution_artifact_engine_plan(scan_plan: dict | None) -> list[dict]:
    engine_plan = scan_plan_engine_plan(scan_plan)
    if engine_plan:
        return engine_plan
    return [{"engine": "templates", "status": "ready", "reason": "template_execution_completed"}]


def scan_plan_audit_summary(scan_plan: dict | None) -> dict:
    if not isinstance(scan_plan, dict):
        return {}
    selection = scan_plan.get("selection") if isinstance(scan_plan.get("selection"), dict) else {}
    context = scan_plan.get("context") if isinstance(scan_plan.get("context"), dict) else {}
    summary = {
        "schema_version": scan_plan.get("schema_version"),
        "hash_algorithm": scan_plan.get("hash_algorithm"),
        "scan_plan_hash": scan_plan.get("scan_plan_hash"),
        "test_intensity": scan_plan.get("test_intensity"),
        "selected_pair_count": selection.get("selected_pair_count", 0),
        "skipped_pair_count": selection.get("skipped_pair_count", 0),
        "requested_pair_count": selection.get("template_endpoint_pair_count", 0),
        "context_status": context.get("status"),
        "selection_starved": bool(selection.get("selection_starved")),
        "skip_reason_counts": selection.get("skip_reason_counts", {}),
    }
    coverage_targets = scan_plan_coverage_targets_summary(scan_plan.get("coverage_targets"))
    if coverage_targets:
        summary["coverage_targets"] = coverage_targets
    summary.update(scan_plan_engine_audit_summary(scan_plan))
    integrity = scan_plan_integrity_summary(scan_plan)
    if integrity:
        summary["scan_plan_integrity"] = integrity
    return summary


def scan_plan_integrity_summary(scan_plan: dict | None) -> dict | None:
    if not isinstance(scan_plan, dict):
        return None
    if not (scan_plan.get("scan_plan_hash") or scan_plan.get("hash_algorithm")):
        return None
    integrity = verify_scan_plan_integrity(scan_plan)
    return {
        "verified": bool(integrity.get("verified")),
        "status": str(integrity.get("status") or "MISMATCH"),
        "hash_algorithm": integrity.get("hash_algorithm"),
        "expected_hash": integrity.get("expected_hash"),
        "actual_hash": integrity.get("actual_hash"),
    }


def scan_plan_integrity_failure(scan_plan: dict | None) -> dict | None:
    summary = scan_plan_integrity_summary(scan_plan)
    if not summary or summary["verified"]:
        return None
    return summary


def scan_plan_coverage_targets_summary(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    summary: dict[str, object] = {}
    for target in _SCAN_PLAN_COVERAGE_TARGETS:
        raw_target = value.get(target)
        if not isinstance(raw_target, dict):
            continue
        status = str(raw_target.get("status") or "not_requested")
        if status not in _SCAN_PLAN_COVERAGE_STATUSES:
            status = "gap"
        signals = [
            signal
            for signal in sorted(str(item) for item in (raw_target.get("signals") or []))
            if signal in _SCAN_PLAN_COVERAGE_SIGNALS
        ]
        target_summary: dict[str, object] = {
            "template_requested": bool(raw_target.get("template_requested")),
            "template_covered": bool(raw_target.get("template_covered")),
            "endpoint_signal_count": _safe_nonnegative_int(raw_target.get("endpoint_signal_count")),
            "status": status,
            "signals": signals,
        }
        identity_context = _scan_plan_identity_context_summary(raw_target.get("identity_context"))
        if identity_context:
            target_summary["identity_context"] = identity_context
        readiness = _scan_plan_readiness_summary(raw_target.get("readiness"))
        if readiness:
            target_summary["readiness"] = readiness
        active_families = _scan_plan_active_test_families_summary(
            raw_target.get("active_test_families")
        )
        if active_families:
            target_summary["active_test_families"] = active_families
        summary[target] = target_summary
    return summary


def _scan_plan_active_test_families_summary(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    summary: dict[str, object] = {}
    for family in _ACTIVE_TEST_FAMILIES:
        raw_family = value.get(family)
        if not isinstance(raw_family, dict):
            continue
        status = str(raw_family.get("status") or "")
        if status not in _ACTIVE_TEST_FAMILY_STATUSES:
            status = (
                "ready"
                if bool(raw_family.get("ready"))
                else "missing_template"
                if _safe_nonnegative_int(raw_family.get("template_count")) == 0
                else "missing_endpoint_context"
            )
        signals = [
            signal
            for signal in sorted(str(item) for item in (raw_family.get("signals") or []))
            if signal in _ACTIVE_TEST_FAMILY_SIGNALS
        ]
        summary[family] = {
            "template_count": _safe_nonnegative_int(raw_family.get("template_count")),
            "endpoint_signal_count": _safe_nonnegative_int(raw_family.get("endpoint_signal_count")),
            "ready": bool(raw_family.get("ready")),
            "status": status,
            "signals": signals,
        }
    return summary


def _scan_plan_identity_context_summary(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    return {
        "role_count": _safe_nonnegative_int(value.get("role_count")),
        "multi_identity_ready": bool(value.get("multi_identity_ready")),
        "privileged_role_present": bool(value.get("privileged_role_present")),
        "low_privilege_role_present": bool(value.get("low_privilege_role_present")),
        "privilege_boundary_pair_count": _safe_nonnegative_int(value.get("privilege_boundary_pair_count")),
    }


def _scan_plan_readiness_summary(value: object) -> dict[str, bool]:
    if not isinstance(value, dict):
        return {}
    return {
        key: bool(value.get(key))
        for key in sorted(_SCAN_PLAN_COVERAGE_READINESS_KEYS)
        if key in value
    }


def _safe_nonnegative_int(value: object) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0
