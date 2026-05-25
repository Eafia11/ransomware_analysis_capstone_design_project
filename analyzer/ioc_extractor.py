from __future__ import annotations

from typing import Any

from backend.app.services.ioc_extractor import extract_iocs_from_chains


def extract_iocs(actions: list[dict[str, Any]]) -> dict[str, list[str]]:
    return extract_iocs_from_chains([{"actions": actions}])


def extract_iocs_from_chain(chain: dict[str, Any]) -> dict[str, Any]:
    iocs = extract_iocs_from_chains([chain])

    return {
        "process_guid": chain.get("process_guid"),
        "image": chain.get("image"),
        "iocs": iocs,
        "ioc_count": sum(len(values) for values in iocs.values()),
    }
