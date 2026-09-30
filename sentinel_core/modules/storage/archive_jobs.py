"""Durable archive jobs: the queue contract between the API (submits) and the archiver (executes).

State machine, one row per request, always scoped to a tenant (``account_id``):

    PENDING --claim--> RUNNING --complete--> COMPLETED
       ^                  |
       |                  +--fail (attempts left)--> PENDING (next_attempt_at = exponential backoff)
       |                  +--fail (no attempts left)--> FAILED
       +--- lease expired while RUNNING (the archiver died) is reclaimed like a failure

Guarantees:
  * duplicate prevention: at most one PENDING/RUNNING job per tenant, enforced by a partial unique
    index, so concurrent or repeated requests return the job already in flight;
  * exactly-one claimant: a claim is a conditional UPDATE, so two archivers cannot both win;
  * ownership: only the worker that holds a RUNNING job can complete or fail it.
"""
from __future__ import annotations

import datetime
from typing import Any

from sqlalchemy import and_, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel_core.models.core import ArchiveJob
from sentinel_core.modules.utils.redactor import Redactor

PENDING = "PENDING"
RUNNING = "RUNNING"
COMPLETED = "COMPLETED"
FAILED = "FAILED"
ACTIVE_STATUSES = (PENDING, RUNNING)

DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_LEASE_SECONDS = 900
DEFAULT_BACKOFF_SECONDS = 30
_ERROR_LIMIT = 2000


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _safe_error(error: object) -> str:
    return Redactor.redact_text(str(error))[:_ERROR_LIMIT]


def serialize_archive_job(job: ArchiveJob) -> dict[str, Any]:
    def iso(value):
        return value.isoformat() if value is not None else None

    return {
        "id": job.id,
        "status": job.status,
        "attempts": job.attempts,
        "max_attempts": job.max_attempts,
        "next_attempt_at": iso(job.next_attempt_at),
        "result": job.result,
        "error": job.error,
        "created_at": iso(job.created_at),
        "started_at": iso(job.started_at),
        "completed_at": iso(job.completed_at),
    }


async def _active_job(db: AsyncSession, account_id: int) -> ArchiveJob | None:
    result = await db.execute(
        select(ArchiveJob).where(ArchiveJob.account_id == account_id, ArchiveJob.status.in_(ACTIVE_STATUSES))
    )
    return result.scalars().first()


async def submit_archive_job(
    db: AsyncSession,
    *,
    account_id: int,
    requested_by: str | None = None,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
) -> tuple[ArchiveJob, bool]:
    """Create a PENDING job, or return the tenant's job already in flight as ``(job, False)``."""
    existing = await _active_job(db, account_id)
    if existing is not None:
        return existing, False
    job = ArchiveJob(
        account_id=account_id,
        status=PENDING,
        requested_by=(str(requested_by)[:100] if requested_by else None),
        max_attempts=max(1, int(max_attempts)),
        attempts=0,
    )
    db.add(job)
    try:
        await db.commit()
    except IntegrityError:
        # Lost a race with a concurrent submit: the unique index guarantees exactly one winner.
        await db.rollback()
        winner = await _active_job(db, account_id)
        if winner is None:
            raise
        return winner, False
    await db.refresh(job)
    return job, True


async def get_archive_job(db: AsyncSession, *, account_id: int, job_id: str) -> ArchiveJob | None:
    """Tenant-scoped lookup: another tenant's job id behaves as if it does not exist."""
    result = await db.execute(select(ArchiveJob).where(ArchiveJob.id == job_id, ArchiveJob.account_id == account_id))
    return result.scalars().first()


async def list_archive_jobs(db: AsyncSession, *, account_id: int, limit: int = 20) -> list[ArchiveJob]:
    result = await db.execute(
        select(ArchiveJob)
        .where(ArchiveJob.account_id == account_id)
        .order_by(ArchiveJob.created_at.desc())
        .limit(max(1, min(int(limit), 100)))
    )
    return list(result.scalars().all())


def _claimable(now: datetime.datetime):
    return or_(
        and_(ArchiveJob.status == PENDING, or_(ArchiveJob.next_attempt_at.is_(None), ArchiveJob.next_attempt_at <= now)),
        and_(ArchiveJob.status == RUNNING, ArchiveJob.lease_expires_at < now),
    )


async def claim_next_archive_job(
    db: AsyncSession,
    *,
    worker_id: str,
    lease_seconds: int = DEFAULT_LEASE_SECONDS,
    now: datetime.datetime | None = None,
) -> ArchiveJob | None:
    """Atomically claim one runnable job for ``worker_id``; ``None`` when nothing is runnable.

    A RUNNING job whose lease expired belongs to an archiver that died; it is reclaimed, or failed
    for good when it has already used all its attempts.
    """
    now = now or _now()
    for _ in range(5):  # a few tries in case another archiver wins the conditional update
        candidate = (
            await db.execute(
                select(ArchiveJob)
                .where(_claimable(now))
                .order_by(ArchiveJob.created_at)
                .limit(1)
                .execution_options(populate_existing=True)
            )
        ).scalars().first()
        if candidate is None:
            return None
        seen_status, seen_attempts = candidate.status, candidate.attempts

        if seen_status == RUNNING and seen_attempts >= candidate.max_attempts:
            lost = await db.execute(
                update(ArchiveJob)
                .where(
                    ArchiveJob.id == candidate.id,
                    ArchiveJob.status == RUNNING,
                    ArchiveJob.attempts == seen_attempts,
                    ArchiveJob.lease_expires_at < now,
                )
.execution_options(synchronize_session=False)
                .values(
                    status=FAILED,
                    completed_at=now,
                    lease_expires_at=None,
                    error=_safe_error(f"lease expired after {seen_attempts} attempts"),
                )
            )
            await db.commit()
            continue

        claimed = await db.execute(
            update(ArchiveJob)
            .where(
                ArchiveJob.id == candidate.id,
                ArchiveJob.status == seen_status,
                ArchiveJob.attempts == seen_attempts,
                _claimable(now),
            )
            .execution_options(synchronize_session=False)
            .values(
                status=RUNNING,
                attempts=seen_attempts + 1,
                worker_id=worker_id,
                lease_expires_at=now + datetime.timedelta(seconds=lease_seconds),
                started_at=candidate.started_at or now,
                next_attempt_at=None,
            )
        )
        await db.commit()
        if claimed.rowcount == 1:
            # Re-read so the returned row reflects the claim, refreshing any copy the session already holds.
            return (
                await db.execute(
                    select(ArchiveJob).where(ArchiveJob.id == candidate.id).execution_options(populate_existing=True)
                )
            ).scalars().first()
    return None


async def complete_archive_job(
    db: AsyncSession, *, job_id: str, worker_id: str, result: dict[str, Any] | None = None, now: datetime.datetime | None = None
) -> bool:
    """Mark the job COMPLETED; ``False`` if this worker no longer holds it."""
    now = now or _now()
    outcome = await db.execute(
        update(ArchiveJob)
        .where(ArchiveJob.id == job_id, ArchiveJob.status == RUNNING, ArchiveJob.worker_id == worker_id)
        .execution_options(synchronize_session=False)
        .values(status=COMPLETED, completed_at=now, lease_expires_at=None, result=result or {}, error=None)
    )
    await db.commit()
    return outcome.rowcount == 1


async def fail_archive_job(
    db: AsyncSession,
    *,
    job_id: str,
    worker_id: str,
    error: object,
    now: datetime.datetime | None = None,
    backoff_seconds: int = DEFAULT_BACKOFF_SECONDS,
) -> str | None:
    """Record a failed attempt. Returns the new status (PENDING to retry, FAILED when out of
    attempts), or ``None`` if this worker no longer holds the job."""
    now = now or _now()
    job = (
        await db.execute(select(ArchiveJob).where(ArchiveJob.id == job_id, ArchiveJob.worker_id == worker_id, ArchiveJob.status == RUNNING))
    ).scalars().first()
    if job is None:
        return None
    if job.attempts < job.max_attempts:
        delay = backoff_seconds * (2 ** max(0, job.attempts - 1))
        values: dict[str, Any] = dict(
            status=PENDING, worker_id=None, lease_expires_at=None,
            next_attempt_at=now + datetime.timedelta(seconds=delay), error=_safe_error(error),
        )
    else:
        values = dict(status=FAILED, lease_expires_at=None, completed_at=now, error=_safe_error(error))
    outcome = await db.execute(
        update(ArchiveJob)
        .where(ArchiveJob.id == job_id, ArchiveJob.status == RUNNING, ArchiveJob.worker_id == worker_id)
        .execution_options(synchronize_session=False)
        .values(**values)
    )
    await db.commit()
    return values["status"] if outcome.rowcount == 1 else None
