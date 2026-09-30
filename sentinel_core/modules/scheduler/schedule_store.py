"""Durable scan schedules: validation and persistence.

The API validates and stores schedules here; api-sentinel-scheduler reads the
``test_schedules`` table and registers cron jobs that enqueue scan runs.
"""
from __future__ import annotations

import datetime
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

try:
    from apscheduler.triggers.cron import CronTrigger
    APScheduler_AVAILABLE = True
except ImportError:
    APScheduler_AVAILABLE = False

from sentinel_core.config import settings
from sentinel_core.models.core import APIEndpoint, TestSchedule
from sentinel_core.modules.pentest.auth_preflight import ActiveScanAuthError, load_profile_and_auth_for_active_scan
from sentinel_core.modules.pentest.auth_scope import blocked_auth_profile_targets
from sentinel_core.modules.pentest.target_policy import build_target_guard_policy
from sentinel_core.modules.test_executor.target_guard import blocked_endpoint_targets


class ScheduleValidationError(ValueError):
    """Raised when a scheduled active scan would be unsafe or unrunnable."""

    def __init__(self, reason: str, message: str, *, detail: dict | None = None):
        super().__init__(message)
        self.reason = reason
        self.detail = {"reason": reason, "message": message}
        if detail:
            self.detail.update(detail)


def _blocked_targets_with_policy(blocked_targets: list[dict]) -> list[dict]:
    enriched: list[dict] = []
    for target in blocked_targets:
        target_url = str(target.get("url") or "")
        reason = str(target.get("reason") or "target guard blocked endpoint")
        target_guard_policy = target.get("target_guard_policy")
        if not isinstance(target_guard_policy, dict):
            target_guard_policy = build_target_guard_policy(
                url=target_url,
                base_url=target_url,
                reason=reason,
            )
        enriched.append({**target, "target_guard_policy": target_guard_policy})
    return enriched


def validate_cron_expression(cron_expression: str) -> None:
    parts = str(cron_expression or "").split()
    if len(parts) != 5:
        raise ScheduleValidationError(
            "invalid_cron_expression",
            "Schedule cron expression must contain exactly five fields.",
        )
    if APScheduler_AVAILABLE:
        try:
            CronTrigger(
                minute=parts[0],
                hour=parts[1],
                day=parts[2],
                month=parts[3],
                day_of_week=parts[4],
            )
        except Exception as exc:
            raise ScheduleValidationError(
                "invalid_cron_expression",
                "Schedule cron expression is not valid.",
            ) from exc


async def validate_schedule_plan(
    db: AsyncSession,
    *,
    template_ids: list,
    endpoint_ids: list,
    account_id: int,
    pentest_profile_id: str | None = None,
) -> None:
    planned_count = len(template_ids or []) * len(endpoint_ids or [])
    max_budget = max(1, int(settings.PENTEST_MAX_TESTS_PER_RUN))
    if planned_count > max_budget:
        raise ScheduleValidationError(
            "scan_budget_exceeded",
            (
                f"Schedule plan has {planned_count} template/endpoint combinations; "
                f"maximum budget is {max_budget}."
            ),
            detail={"planned_tests": planned_count, "max_tests_per_run": max_budget},
        )

    endpoint_result = await db.execute(
        select(APIEndpoint).where(
            APIEndpoint.id.in_(endpoint_ids),
            APIEndpoint.account_id == account_id,
        )
    )
    endpoints = endpoint_result.scalars().all()
    if len(endpoints) < len(endpoint_ids):
        raise ScheduleValidationError(
            "endpoint_scope_invalid",
            "One or more scheduled endpoints are unavailable for this account.",
        )

    blocked_targets = _blocked_targets_with_policy(blocked_endpoint_targets(endpoints))
    if blocked_targets:
        raise ScheduleValidationError(
            "target_guard_blocked",
            "Pentest target guard blocked one or more scheduled endpoints.",
            detail={"blocked_endpoints": blocked_targets},
        )

    try:
        _, auth_profile = await load_profile_and_auth_for_active_scan(
            db,
            account_id=account_id,
            pentest_profile_id=pentest_profile_id,
        )
    except ActiveScanAuthError as exc:
        raise ScheduleValidationError(
            exc.reason,
            "Scheduled active scans require an auth-ready pentest profile.",
            detail={"auth": exc.detail},
        ) from exc

    blocked_auth_targets = blocked_auth_profile_targets(auth_profile, endpoints)
    if blocked_auth_targets:
        raise ScheduleValidationError(
            "auth_profile_scope_blocked",
            "Auth profile scope blocked one or more scheduled endpoints.",
            detail={"blocked_endpoints": blocked_auth_targets},
        )


async def create_schedule(
    db: AsyncSession,
    *,
    name: str,
    cron_expression: str,
    template_ids: list,
    endpoint_ids: list,
    account_id: int,
    pentest_profile_id: str | None = None,
) -> str:
    """Validate and persist an enabled schedule; returns its id."""
    validate_cron_expression(cron_expression)
    await validate_schedule_plan(
        db,
        template_ids=template_ids,
        endpoint_ids=endpoint_ids,
        account_id=account_id,
        pentest_profile_id=pentest_profile_id,
    )
    schedule_id = str(uuid.uuid4())
    db.add(
        TestSchedule(
            id=schedule_id,
            account_id=account_id,
            name=name,
            cron_expression=cron_expression,
            template_ids=template_ids,
            endpoint_ids=endpoint_ids,
            pentest_profile_id=pentest_profile_id,
            enabled=True,
            created_at=datetime.datetime.now(datetime.timezone.utc),
        )
    )
    await db.commit()
    return schedule_id


async def enabled_schedules(db: AsyncSession) -> list[TestSchedule]:
    result = await db.execute(select(TestSchedule).where(TestSchedule.enabled == True))  # noqa: E712
    return result.scalars().all()
