"""app/services/stats_service.py — Privacy-safe persistent usage stats for the dashboard."""

import json
import logging
import re
import time
from pathlib import Path
from typing import Any, Dict, List

from app.config import settings

log = logging.getLogger("scamshield.stats")
ROOT = Path(__file__).resolve().parents[2]


def mask(kind: str, value: str) -> str:
    if kind == "PHONE":
        d = re.sub(r"\D", "", value)
        return "•" * max(len(d) - 2, 0) + d[-2:]
    if kind == "UPI":
        local, _, handle = value.partition("@")
        return f"{local[:1]}•••@{handle}"
    return value[:60]


class StatsService:
    def __init__(self):
        self.path = ROOT / settings.STATS_FILE
        self.d = self._load()

    @staticmethod
    def _empty() -> Dict[str, Any]:
        return {"total": 0, "by_level": {}, "by_type": {}, "by_scam_type": {}, "brands": {},
                "signals": {}, "actions": {}, "recent": [], "since": int(time.time())}

    def _load(self) -> Dict[str, Any]:
        try:
            if self.path.exists():
                return {**self._empty(), **json.loads(self.path.read_text("utf-8"))}
        except Exception as exc:
            log.warning("Could not load stats: %r", exc)
        return self._empty()

    def _save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self.d, ensure_ascii=False), "utf-8")
        except Exception as exc:
            log.warning("Could not save stats: %r", exc)

    @staticmethod
    def _inc(bucket: Dict[str, int], key: str) -> None:
        bucket[key] = bucket.get(key, 0) + 1

    def record(self, input_type: str, level: str, score: int, brand: str, signals: List[str], identifier: str) -> None:
        d = self.d
        d["total"] += 1
        self._inc(d["by_level"], level)
        self._inc(d["by_type"], input_type)
        if brand:
            self._inc(d["brands"], brand)
        for s in signals:
            self._inc(d["signals"], s)
        d["recent"].insert(0, {"ts": int(time.time()), "type": input_type, "level": level, "score": score,
                               "brand": brand or "", "id": mask(input_type, identifier)})
        del d["recent"][30:]
        self._save()

    def bump(self, bucket: str, key: str) -> None:
        self._inc(self.d[bucket], key)
        self._save()

    def snapshot(self) -> Dict[str, Any]:
        return self.d


stats_service = StatsService()