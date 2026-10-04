"""apply_tenant_context must work on asyncpg, where `SET LOCAL x = $1` is a syntax error."""
import os

import pytest

from sentinel_core.config import settings
from sentinel_core.modules.persistence import database
from sentinel_core.modules.tenancy.context import set_current_account_id


class _Recorder:
    def __init__(self):
        self.calls = []

    async def execute(self, stmt, params=None):
        self.calls.append((str(stmt), params))


@pytest.fixture
def rls_on(monkeypatch):
    monkeypatch.setattr(settings, "TENANT_RLS_ENABLED", True)
    monkeypatch.setattr(settings, "DATABASE_URL", "postgresql+asyncpg://u:p@h/db")
    monkeypatch.setattr(settings, "TENANT_RLS_SETTING_NAME", "app.current_account_id")


@pytest.mark.asyncio
async def test_uses_parameterised_set_config(rls_on):
    set_current_account_id(42)
    s = _Recorder()
    await database.apply_tenant_context(s)
    stmt, params = s.calls[0]
    assert "set_config" in stmt and "SET LOCAL" not in stmt.upper().replace("SET_CONFIG", "")
    assert params == {"name": "app.current_account_id", "value": "42"}


@pytest.mark.asyncio
async def test_rejects_unsafe_setting_name(rls_on, monkeypatch):
    monkeypatch.setattr(settings, "TENANT_RLS_SETTING_NAME", "x; drop table a")
    set_current_account_id(1)
    with pytest.raises(ValueError):
        await database.apply_tenant_context(_Recorder())


@pytest.mark.asyncio
async def test_noop_when_disabled(monkeypatch):
    monkeypatch.setattr(settings, "TENANT_RLS_ENABLED", False)
    set_current_account_id(1)
    s = _Recorder()
    await database.apply_tenant_context(s)
    assert s.calls == []


@pytest.mark.asyncio
async def test_real_postgres_asyncpg_roundtrip(rls_on):
    url = os.getenv("TEST_POSTGRES_URL")
    if not url:
        pytest.skip("TEST_POSTGRES_URL not set")
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    engine = create_async_engine(url)
    try:
        async with engine.connect() as conn:
            set_current_account_id(77)
            await database.apply_tenant_context(conn)
            got = (await conn.execute(text("select current_setting('app.current_account_id')"))).scalar()
            assert got == "77"
            await conn.rollback()
            after = (await conn.execute(text("select current_setting('app.current_account_id', true)"))).scalar()
            assert after in (None, ""), "value must be transaction-local"
    finally:
        await engine.dispose()
