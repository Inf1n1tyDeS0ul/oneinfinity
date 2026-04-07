"""core/target_repository.py — TargetRepository wrapping DBManager.

FastAPI dependency: Depends(get_target_repo)
Direct use:         repo = await get_target_repo()
"""
from __future__ import annotations

from typing import Optional

from core.db_manager import get_db_manager


class TargetRepository:
    """Thin async wrapper over DBManager target methods."""

    def __init__(self, db) -> None:
        self._db = db

    async def add(
        self,
        target_id: str,
        target_value: str,
        name: str = "",
        platform: str = "hackerone",
        target_type: str = "web",
    ) -> dict:
        """Signature matches TargetDB.add: (target_id, target_value, name, platform, target_type)."""
        return await self._db.save_target(
            {
                "target_id": target_id,
                "target_value": target_value,
                "target_type": target_type,
                "name": name or target_value,
                "platform": platform,
            }
        )

    async def get(self, target_id: str) -> Optional[dict]:
        return await self._db.get_target(target_id)

    async def list_all(self) -> list:
        return await self._db.list_targets()

    async def delete(self, target_id: str) -> bool:
        return await self._db.delete_target(target_id)

    async def update_status(
        self,
        target_id: str,
        status: str,
        last_scan_time: str = None,
    ) -> None:
        await self._db.update_target_status(target_id, status, last_scan_time)

    async def update_vuln_count(self, target_id: str, count: int) -> None:
        await self._db.update_target_vuln_count(target_id, count)


async def get_target_repo() -> TargetRepository:
    """FastAPI dependency — returns a TargetRepository backed by the singleton DBManager."""
    return TargetRepository(await get_db_manager())
