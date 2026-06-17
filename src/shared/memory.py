"""
shared/memory.py
----------------
Simple in-memory shared state that all agents read from and write to.
Acts as the message bus between agents in the pipeline.

In a production system this would be Redis or a database.
For this project, a plain Python dict is enough.
"""

from typing import Any
import threading
import json
from datetime import datetime


class SharedMemory:
    """
    Thread-safe key-value store that agents use to pass data between steps.

    Usage:
        memory = SharedMemory()

        # Agent 1 writes
        memory.set("extracted_events", [...])

        # Agent 2 reads
        events = memory.get("extracted_events")
    """

    def __init__(self):
        self._store: dict[str, Any] = {}
        self._lock = threading.Lock()
        self._history: list[dict] = []

    def set(self, key: str, value: Any) -> None:
        """Store a value and log the write to history."""
        with self._lock:
            self._store[key] = value
            self._history.append({
                "timestamp": datetime.now().isoformat(),
                "action": "write",
                "key": key,
            })

    def get(self, key: str, default: Any = None) -> Any:
        """Retrieve a value, returning default if key does not exist."""
        with self._lock:
            return self._store.get(key, default)

    def get_history(self) -> list[dict]:
        """Return the full audit trail of reads and writes."""
        with self._lock:
            return list(self._history)

    def dump(self) -> str:
        """Dump the entire store as a formatted JSON string (for debugging)."""
        with self._lock:
            return json.dumps(self._store, indent=2, default=str)

    def clear(self) -> None:
        """Wipe all stored data (useful between pipeline runs)."""
        with self._lock:
            self._store.clear()


# Global singleton — all agents import this same instance
memory = SharedMemory()