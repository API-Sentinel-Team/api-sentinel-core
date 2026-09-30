import threading
import time

import pytest

from sentinel_core import migrate


def test_non_postgres_databases_skip_the_lock(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///./x.db")
    with migrate._single_migrator():
        pass  # must not try to connect anywhere


def test_an_unreachable_postgres_fails_loudly_instead_of_migrating_unguarded(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://u:p@127.0.0.1:1/none")
    with pytest.raises(RuntimeError, match="migration lock"):
        with migrate._single_migrator():
            raise AssertionError("must not run the migration body")
