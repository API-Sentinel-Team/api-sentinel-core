"""The archive job queue contract: duplicate prevention, tenant ownership, claiming, retry."""
import datetime

import pytest
from sqlalchemy import select

from sentinel_core.models.core import ArchiveJob
from sentinel_core.modules.storage import archive_jobs as jobs

T0 = datetime.datetime(2026, 9, 30, 12, 0, tzinfo=datetime.timezone.utc)


def later(seconds: int) -> datetime.datetime:
    return T0 + datetime.timedelta(seconds=seconds)


@pytest.mark.asyncio
async def test_submit_creates_a_pending_job_owned_by_the_tenant(db_session):
    job, created = await jobs.submit_archive_job(db_session, account_id=101, requested_by="alice")

    assert created is True
    assert job.status == jobs.PENDING and job.account_id == 101
    assert job.attempts == 0 and job.requested_by == "alice"


@pytest.mark.asyncio
async def test_a_second_request_returns_the_job_already_in_flight(db_session):
    first, created_first = await jobs.submit_archive_job(db_session, account_id=102)
    second, created_second = await jobs.submit_archive_job(db_session, account_id=102)

    assert (created_first, created_second) == (True, False)
    assert second.id == first.id
    rows = (await db_session.execute(select(ArchiveJob).where(ArchiveJob.account_id == 102))).scalars().all()
    assert len(rows) == 1


@pytest.mark.asyncio
async def test_the_database_itself_refuses_two_active_jobs_for_one_tenant(db_session):
    # Simulates losing the check-then-insert race: the unique index must still hold the line.
    db_session.add(ArchiveJob(account_id=103, status=jobs.PENDING))
    await db_session.commit()
    db_session.add(ArchiveJob(account_id=103, status=jobs.RUNNING))
    with pytest.raises(Exception):
        await db_session.commit()
    await db_session.rollback()


@pytest.mark.asyncio
async def test_different_tenants_can_each_have_an_active_job(db_session):
    _, a = await jobs.submit_archive_job(db_session, account_id=104)
    _, b = await jobs.submit_archive_job(db_session, account_id=105)

    assert a is True and b is True


@pytest.mark.asyncio
async def test_job_lookup_is_scoped_to_the_owning_tenant(db_session):
    job, _ = await jobs.submit_archive_job(db_session, account_id=106)

    assert (await jobs.get_archive_job(db_session, account_id=106, job_id=job.id)).id == job.id
    assert await jobs.get_archive_job(db_session, account_id=107, job_id=job.id) is None
    assert [j.id for j in await jobs.list_archive_jobs(db_session, account_id=107)] == []


@pytest.mark.asyncio
async def test_claim_runs_the_job_once_and_a_second_claim_finds_nothing(db_session):
    job, _ = await jobs.submit_archive_job(db_session, account_id=108)

    claimed = await jobs.claim_next_archive_job(db_session, worker_id="w1", now=T0)
    again = await jobs.claim_next_archive_job(db_session, worker_id="w2", now=T0)

    assert claimed.id == job.id and claimed.status == jobs.RUNNING
    assert claimed.attempts == 1 and claimed.worker_id == "w1"
    assert again is None


@pytest.mark.asyncio
async def test_only_the_worker_holding_the_job_can_complete_it(db_session):
    job, _ = await jobs.submit_archive_job(db_session, account_id=109)
    job_id = job.id
    await jobs.claim_next_archive_job(db_session, worker_id="w1", now=T0)

    assert await jobs.complete_archive_job(db_session, job_id=job.id, worker_id="intruder", result={"x": 1}) is False
    assert await jobs.complete_archive_job(db_session, job_id=job.id, worker_id="w1", result={"archived": 7}, now=later(5)) is True

    db_session.expire_all()
    done = await jobs.get_archive_job(db_session, account_id=109, job_id=job_id)
    assert done.status == jobs.COMPLETED and done.result == {"archived": 7}


@pytest.mark.asyncio
async def test_finishing_a_job_frees_the_tenant_to_submit_another(db_session):
    job, _ = await jobs.submit_archive_job(db_session, account_id=110)
    await jobs.claim_next_archive_job(db_session, worker_id="w1", now=T0)
    await jobs.complete_archive_job(db_session, job_id=job.id, worker_id="w1")

    next_job, created = await jobs.submit_archive_job(db_session, account_id=110)

    assert created is True and next_job.id != job.id


@pytest.mark.asyncio
async def test_a_failed_attempt_is_retried_after_exponential_backoff(db_session):
    job, _ = await jobs.submit_archive_job(db_session, account_id=111, max_attempts=3)
    await jobs.claim_next_archive_job(db_session, worker_id="w1", now=T0)

    status = await jobs.fail_archive_job(
        db_session, job_id=job.id, worker_id="w1", error="disk full", now=T0, backoff_seconds=30
    )

    assert status == jobs.PENDING
    assert await jobs.claim_next_archive_job(db_session, worker_id="w1", now=later(10)) is None  # still backing off
    retry = await jobs.claim_next_archive_job(db_session, worker_id="w1", now=later(31))
    assert retry.attempts == 2
    await jobs.fail_archive_job(
        db_session, job_id=job.id, worker_id="w1", error="disk full", now=later(31), backoff_seconds=30
    )
    assert await jobs.claim_next_archive_job(db_session, worker_id="w1", now=later(31 + 59)) is None  # 60s delay
    assert (await jobs.claim_next_archive_job(db_session, worker_id="w1", now=later(31 + 61))).attempts == 3


@pytest.mark.asyncio
async def test_a_job_fails_for_good_when_attempts_are_exhausted(db_session):
    job, _ = await jobs.submit_archive_job(db_session, account_id=112, max_attempts=1)
    job_id = job.id
    await jobs.claim_next_archive_job(db_session, worker_id="w1", now=T0)

    status = await jobs.fail_archive_job(db_session, job_id=job.id, worker_id="w1", error="boom", now=T0)

    assert status == jobs.FAILED
    db_session.expire_all()
    failed = await jobs.get_archive_job(db_session, account_id=112, job_id=job_id)
    assert failed.status == jobs.FAILED and failed.completed_at is not None
    assert (await jobs.submit_archive_job(db_session, account_id=112))[1] is True  # the tenant can try again


@pytest.mark.asyncio
async def test_a_dead_workers_job_is_reclaimed_after_its_lease_expires(db_session):
    job, _ = await jobs.submit_archive_job(db_session, account_id=113)
    await jobs.claim_next_archive_job(db_session, worker_id="dead", lease_seconds=60, now=T0)

    assert await jobs.claim_next_archive_job(db_session, worker_id="w2", now=later(30)) is None  # lease still valid
    reclaimed = await jobs.claim_next_archive_job(db_session, worker_id="w2", now=later(61))

    assert reclaimed.id == job.id and reclaimed.worker_id == "w2" and reclaimed.attempts == 2
    assert await jobs.complete_archive_job(db_session, job_id=job.id, worker_id="dead") is False  # old owner lost it


@pytest.mark.asyncio
async def test_an_expired_lease_on_the_last_attempt_fails_the_job_instead_of_looping(db_session):
    job, _ = await jobs.submit_archive_job(db_session, account_id=114, max_attempts=1)
    job_id = job.id
    await jobs.claim_next_archive_job(db_session, worker_id="dead", lease_seconds=60, now=T0)

    assert await jobs.claim_next_archive_job(db_session, worker_id="w2", now=later(120)) is None

    db_session.expire_all()
    assert (await jobs.get_archive_job(db_session, account_id=114, job_id=job_id)).status == jobs.FAILED


@pytest.mark.asyncio
async def test_stored_errors_are_redacted(db_session):
    job, _ = await jobs.submit_archive_job(db_session, account_id=115, max_attempts=1)
    job_id = job.id
    await jobs.claim_next_archive_job(db_session, worker_id="w1", now=T0)

    await jobs.fail_archive_job(
        db_session, job_id=job.id, worker_id="w1", error="upload failed Authorization: Bearer super-secret-token", now=T0
    )

    db_session.expire_all()
    stored = (await jobs.get_archive_job(db_session, account_id=115, job_id=job_id)).error
    assert "super-secret-token" not in stored
