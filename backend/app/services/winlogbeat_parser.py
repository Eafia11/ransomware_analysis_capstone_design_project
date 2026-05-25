from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.core.logger import get_logger
from app.services.attack_chain_builder import (
    build_abstracted_attack_chains,
    build_attack_chain_candidates,
)
from app.services.normalizer import (
    filter_events,
    normalize_winlogbeat_event,
    safe_get,
    summarize_events,
)

logger = get_logger(__name__)


def load_json_lines(file_path: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []

    with open(file_path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                logger.warning("line %s: failed to parse JSON: %s", line_no, exc)
                continue

    return events


def parse_winlogbeat_file(file_path: str) -> list[dict[str, Any]]:
    raw_events = load_json_lines(file_path)
    parsed_events = [normalize_winlogbeat_event(event) for event in raw_events]
    parsed_events.sort(key=lambda x: x.get("timestamp") or "")
    return parsed_events


def save_json(data: Any, output_path: str) -> None:
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


__all__ = [
    "build_abstracted_attack_chains",
    "build_attack_chain_candidates",
    "filter_events",
    "load_json_lines",
    "normalize_winlogbeat_event",
    "parse_winlogbeat_file",
    "safe_get",
    "save_json",
    "summarize_events",
]
