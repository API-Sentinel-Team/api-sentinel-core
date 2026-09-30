"""Runs one recon source: fetch, process, and dispatch recon alerts."""
from __future__ import annotations

import datetime
import logging
import structlog
from typing import Dict, Any


from sentinel_core.config import settings
from sentinel_core.modules.recon.adapters import ReconAdapterRegistry
from sentinel_core.modules.recon.processor import ReconProcessor
from sentinel_core.modules.integrations.dispatcher import dispatch_event
from sentinel_core.modules.response.playbook_executor import execute_playbooks
from sentinel_core.models.core import ReconSourceConfig, Alert

logger = structlog.get_logger(__name__)


class ReconSourceRunner:
    def __init__(self) -> None:
        self.adapters = ReconAdapterRegistry()
        self.processor = ReconProcessor()

    async def run_source(self, db, source: ReconSourceConfig) -> Dict[str, Any]:
        now = datetime.datetime.now(datetime.timezone.utc)
        interval = source.interval_seconds or settings.RECON_DEFAULT_INTERVAL_SECONDS
        source.last_run_at = now
        source.next_run_at = now + datetime.timedelta(seconds=interval)

        items, error = await self.adapters.fetch_items(source)
        if error:
            source.last_status = "ERROR"
            source.last_error = error
            return {"success": False, "error": error}

        stats = await self.processor.ingest(db, source.account_id, source.provider, items)
        source.last_status = "SUCCESS"
        source.last_error = None
        if stats.get("created", 0) > 0:
            alert = Alert(
                account_id=source.account_id,
                title="Shadow endpoints detected (external recon)",
                message=f"{stats.get('created')} new shadow candidates from {source.provider}",
                severity="HIGH",
                category="SHADOW_ENDPOINT",
                endpoint=None,
            )
            db.add(alert)
            await db.flush()
            await execute_playbooks(
                db,
                alert,
                evidence={
                    "source": source.provider,
                    "stats": stats,
                },
                trigger="endpoint.shadow_detected",
            )
            await dispatch_event(
                "endpoint.shadow_detected",
                {
                    "type": "SHADOW_ENDPOINT",
                    "severity": "HIGH",
                    "source": source.provider,
                    "description": f"{stats.get('created')} new shadow candidates from {source.provider}",
                    "stats": stats,
                },
                source.account_id,
                db,
            )
        return {"success": True, "stats": stats}
