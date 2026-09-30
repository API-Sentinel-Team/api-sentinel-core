"""Durable archive jobs.

Revision ID: 20260930_archive_jobs
Revises: 20260815_request_log_host
Create Date: 2026-09-30 00:00:00.000000

The API used to run archiving inside the request. It now creates an archive_jobs row and the
archiver service executes it. A partial unique index allows at most one PENDING/RUNNING job per
tenant.
"""
from alembic import op
import sqlalchemy as sa

revision = "20260930_archive_jobs"
down_revision = "20260815_request_log_host"
branch_labels = None
depends_on = None

_ACTIVE = "status IN ('PENDING', 'RUNNING')"


def upgrade():
    op.create_table(
        "archive_jobs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("account_id", sa.BigInteger(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="PENDING"),
        sa.Column("requested_by", sa.String(100), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="3"),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("worker_id", sa.String(100), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("result", sa.JSON(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_archive_jobs_account_id", "archive_jobs", ["account_id"])
    op.create_index("ix_archive_jobs_claim", "archive_jobs", ["status", "next_attempt_at"])
    op.create_index(
        "uq_archive_jobs_one_active_per_account",
        "archive_jobs",
        ["account_id"],
        unique=True,
        sqlite_where=sa.text(_ACTIVE),
        postgresql_where=sa.text(_ACTIVE),
    )


def downgrade():
    op.drop_index("uq_archive_jobs_one_active_per_account", table_name="archive_jobs")
    op.drop_index("ix_archive_jobs_claim", table_name="archive_jobs")
    op.drop_index("ix_archive_jobs_account_id", table_name="archive_jobs")
    op.drop_table("archive_jobs")
