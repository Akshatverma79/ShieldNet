"""
ShieldNet WebSocket Manager
Tracks connected clients and broadcasts threat events in real time.
asyncio.Lock is created lazily (inside the first coroutine call) so it is
always bound to the running event loop, avoiding the Python 3.10+ deprecation
warning that fires when a Lock is created before any loop exists.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Optional, Set

from fastapi import WebSocket

logger = logging.getLogger("shieldnet.websocket")


class ConnectionManager:
    """Async-safe registry of active WebSocket connections."""

    def __init__(self) -> None:
        self._active: Set[WebSocket] = set()
        self._lock:   Optional[asyncio.Lock] = None   # created lazily

    def _get_lock(self) -> asyncio.Lock:
        """Return the lock, creating it on first call (inside a running loop)."""
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._get_lock():
            self._active.add(ws)
        logger.info("WS client connected  — total: %d", len(self._active))

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._get_lock():
            self._active.discard(ws)
        logger.info("WS client disconnected — total: %d", len(self._active))

    async def broadcast(self, data: dict) -> None:
        """Serialise data to JSON and push to every connected client."""
        if not self._active:
            return

        message = json.dumps(data, default=str)

        async with self._get_lock():
            targets = list(self._active)   # snapshot to avoid mutation during iteration

        dead: Set[WebSocket] = set()
        for ws in targets:
            try:
                await ws.send_text(message)
            except Exception:
                dead.add(ws)

        if dead:
            async with self._get_lock():
                self._active -= dead

    @property
    def client_count(self) -> int:
        return len(self._active)


# Module-level singleton
manager = ConnectionManager()
