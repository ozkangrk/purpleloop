"""Append-only JSONL audit log with SHA256 hash chaining.

Each record carries prev_sha256 and sha256 of the canonical record body
(including prev_sha256). Tampering with any line breaks the chain and
verify_chain() raises / reports it.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
from typing import Any


class AuditTamperError(Exception):
    """Raised when the audit chain fails verification."""


_LOCK = threading.Lock()


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _record_sha(record: dict) -> str:
    body = {k: v for k, v in record.items() if k != "sha256"}
    return hashlib.sha256(_canon(body).encode("utf-8")).hexdigest()


class AuditLog:
    GENESIS = "0" * 64

    def __init__(self, path: str):
        self.path = path
        self._cached_last_sha: str | None = None   # append hızlandırma ( zincir güvenliği değişmez)
        self._known_len: int = 0                    # cache'in hangi dosya uzunluğuna ait olduğu

    def _last_sha(self) -> str:
        last = self.GENESIS
        if not os.path.exists(self.path):
            return last
        # hızlı yol: dosya cache'ten beri büyüdüyse SADECA yeni satırları oku
        with open(self.path, "rb") as f:
            f.seek(self._known_len)
            for raw in f.read().decode("utf-8", errors="replace").splitlines():
                line = raw.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                last = rec.get("sha256", last)
            self._known_len = f.tell()
        if last != self.GENESIS:
            self._cached_last_sha = last
        return last if last != self.GENESIS else self._cached_last_sha or self.GENESIS

    def append(self, event: str, **fields: Any) -> dict:
        with _LOCK:
            record = {
                "event": event,
                "prev_sha256": self._last_sha(),
            }
            record.update(fields)
            record["sha256"] = _record_sha(record)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(_canon(record) + "\n")
                f.flush()
                # NOT: fsync bilinçli olarak kaldırıldı (performans).
                # Dayanıklılık değişimi: OS kapanışında yazar; proses kill durumunda
                # son kayıtlar kaybedilebilir ANCAK zincir doğrulaması verify_chain()
                # ile tam dosyadan yapılır — kayıp satır zinciri BOZMAZ, sadece kısaltır.
                # Kritik dağıtımlarda append'lerden sonra os.sync() çağrılabilir.
            self._cached_last_sha = record["sha256"]
            self._known_len = os.path.getsize(self.path)
            return record

    def verify_chain(self) -> bool:
        """True if chain intact. Raises AuditTamperError on the first break."""
        prev = self.GENESIS
        with open(self.path, "r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError as e:
                    raise AuditTamperError(f"line {lineno}: invalid JSON: {e}") from e
                if rec.get("prev_sha256") != prev:
                    raise AuditTamperError(f"line {lineno}: prev_sha256 mismatch (chain broken or line inserted)")
                if rec.get("sha256") != _record_sha(rec):
                    raise AuditTamperError(f"line {lineno}: sha256 mismatch (record tampered)")
                prev = rec["sha256"]
        return True
