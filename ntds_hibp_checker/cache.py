"""
Cache persistant des reponses HIBP (mode online), sans dependance externe.

S'appuie sur sqlite3 (bibliotheque standard -> embarque d'office dans l'exe).
On ne stocke QUE les reponses publiques de l'API k-anonymity (un dict
{suffixe: count} par prefixe de 5 caracteres) ; JAMAIS les hash du domaine
analyse. Aucun secret n'est ecrit sur disque.

Interet : entre deux analyses, les prefixes deja vus ne sont pas re-interroges.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from typing import Dict, Optional


def default_cache_path() -> str:
    return os.path.join(os.path.expanduser("~"),
                        ".ntds_hibp_checker_cache.sqlite")


class PrefixCache:
    """Cache prefixe -> {suffixe: count}, partage entre threads (verrou)."""

    def __init__(self, path: Optional[str] = None):
        self.path = path or default_cache_path()
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS prefixes "
            "(prefix TEXT PRIMARY KEY, data TEXT NOT NULL)")
        self._conn.commit()

    def get(self, prefix: str) -> Optional[Dict[str, int]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT data FROM prefixes WHERE prefix = ?",
                (prefix,)).fetchone()
        if not row:
            return None
        try:
            return json.loads(row[0])
        except (ValueError, TypeError):
            return None

    def set(self, prefix: str, mapping: Dict[str, int]) -> None:
        payload = json.dumps(mapping, separators=(",", ":"))
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO prefixes (prefix, data) "
                "VALUES (?, ?)", (prefix, payload))
            self._conn.commit()

    def count(self) -> int:
        with self._lock:
            return self._conn.execute(
                "SELECT COUNT(*) FROM prefixes").fetchone()[0]

    def clear(self) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM prefixes")
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except Exception:
                pass
