"""`sentinel-migrate`: run the shared database migrations bundled with sentinel-core.

    sentinel-migrate upgrade [revision]     (default: head)
    sentinel-migrate downgrade <revision>
    sentinel-migrate current | history | heads

sentinel-core is the single owner of the schema. Services never carry their own migrations.
"""
from __future__ import annotations

import asyncio
import contextlib
import os
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

from alembic import command
from alembic.config import Config


def _config() -> Config:
    ini = Path(__file__).resolve().with_name("alembic.ini")
    cfg = Config(str(ini))
    cfg.set_main_option("script_location", str(ini.parent / "migrations"))
    return cfg


_LOCK_KEY = 727_274_001  # arbitrary, fixed: every sentinel-migrate on one database contends for it


@contextlib.contextmanager
def _single_migrator():
    """Hold a Postgres advisory lock so concurrent migrators (several pod init containers, compose
    restarts) run one at a time; the second sees an up-to-date schema and does nothing."""
    url = os.environ.get("DATABASE_URL", "")
    if not url.startswith(("postgresql", "postgres")):
        yield  # SQLite and friends have no concurrent migrators to coordinate
        return
    import asyncpg

    dsn = url.replace("postgresql+asyncpg://", "postgresql://", 1)
    held, release, failed = threading.Event(), threading.Event(), []

    def hold():
        async def run():
            try:
                conn = await asyncpg.connect(dsn)
                await conn.execute("SELECT pg_advisory_lock($1)", _LOCK_KEY)
            except Exception as exc:  # surface to the caller instead of migrating unguarded
                failed.append(exc)
                held.set()
                return
            held.set()
            while not release.is_set():
                await asyncio.sleep(0.2)
            await conn.close()  # closing the session drops the lock

        asyncio.run(run())

    thread = threading.Thread(target=hold, daemon=True)
    thread.start()
    held.wait()
    if failed:
        raise RuntimeError(f"could not take the migration lock: {failed[0]}")
    try:
        yield
    finally:
        release.set()
        thread.join(timeout=10)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    action = args[0] if args else "upgrade"
    cfg = _config()
    commands = {
        "upgrade": command.upgrade,
        "downgrade": command.downgrade,
        "current": command.current,
        "history": command.history,
        "heads": command.heads,
    }
    if action not in commands:
        print(__doc__)
        return 2
    if action == "downgrade" and len(args) < 2:
        print("downgrade needs a target revision", file=sys.stderr)
        return 2
    # migrations/env.py decides whether to bootstrap a fresh database by looking at
    # config.cmd_opts.cmd, which alembic's own CLI sets. Mirror that shape here so
    # `sentinel-migrate upgrade head` behaves exactly like `alembic upgrade head`.
    fn = commands[action]
    cfg.cmd_opts = SimpleNamespace(cmd=(fn, [], {}))
    if action in ("upgrade", "downgrade"):
        target = args[1] if len(args) > 1 else "head"
        with _single_migrator():
            fn(cfg, target)
    else:
        fn(cfg)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
