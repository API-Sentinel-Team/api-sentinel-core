"""`sentinel-migrate`: run the shared database migrations bundled with sentinel-core.

    sentinel-migrate upgrade [revision]     (default: head)
    sentinel-migrate downgrade <revision>
    sentinel-migrate current | history | heads

sentinel-core is the single owner of the schema. Services never carry their own migrations.
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

from alembic import command
from alembic.config import Config


def _config() -> Config:
    ini = Path(__file__).resolve().with_name("alembic.ini")
    cfg = Config(str(ini))
    cfg.set_main_option("script_location", str(ini.parent / "migrations"))
    return cfg


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
    if action == "upgrade":
        fn(cfg, args[1] if len(args) > 1 else "head")
    elif action == "downgrade":
        fn(cfg, args[1])
    else:
        fn(cfg)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
