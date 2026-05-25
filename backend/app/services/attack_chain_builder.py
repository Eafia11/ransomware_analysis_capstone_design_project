from __future__ import annotations

from collections import defaultdict
from typing import Any


CORE_SYSMON_EVENT_IDS = {"1", "3", "11", "12", "13", "14"}


def filter_core_sysmon_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [event for event in events if str(event.get("event_id")) in CORE_SYSMON_EVENT_IDS]


def build_process_groups(events: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for event in events:
        event_id = str(event.get("event_id") or "")
        process_guid = event.get("process_guid")
        process_id = event.get("process_id")
        image = event.get("image")
        command_line = event.get("command_line")
        parent_image = event.get("parent_image")
        user = event.get("user")
        timestamp = event.get("timestamp") or ""

        if process_guid and process_guid != "{GUID-REDACTED}":
            group_key = f"guid::{process_guid}"
        elif event_id == "1":
            group_key = f"proc::{process_id}::{image}::{command_line}"
        else:
            time_bucket = timestamp[:16] if timestamp else "unknown_time"
            group_key = f"fallback::{process_id}::{image}::{parent_image}::{user}::{time_bucket}"

        grouped[group_key].append(event)

    for group_key in grouped:
        grouped[group_key].sort(key=lambda x: x.get("timestamp") or "")

    return dict(grouped)


def build_process_index(events: list[dict[str, Any]]) -> tuple[dict[str, dict[str, Any]], dict[str, list[str]]]:
    process_info_map: dict[str, dict[str, Any]] = {}
    children_map: dict[str, list[str]] = defaultdict(list)

    for event in events:
        if str(event.get("event_id")) != "1":
            continue

        process_guid = event.get("process_guid")
        parent_process_guid = event.get("parent_process_guid")

        if not process_guid:
            continue

        if process_guid not in process_info_map:
            process_info_map[process_guid] = {
                "process_guid": process_guid,
                "process_id": event.get("process_id"),
                "image": event.get("image"),
                "command_line": event.get("command_line"),
                "parent_process_guid": parent_process_guid,
                "parent_process_id": event.get("parent_process_id"),
                "parent_image": event.get("parent_image"),
                "parent_command_line": event.get("parent_command_line"),
                "user": event.get("user"),
                "timestamp": event.get("timestamp"),
            }

        if (
            parent_process_guid
            and parent_process_guid != "{GUID-REDACTED}"
            and process_guid != "{GUID-REDACTED}"
            and parent_process_guid != process_guid
        ):
            if process_guid not in children_map[parent_process_guid]:
                children_map[parent_process_guid].append(process_guid)

    return process_info_map, dict(children_map)


def summarize_process_group(group_key: str, events: list[dict[str, Any]]) -> dict[str, Any]:
    first = events[0] if events else {}
    process_create = next((event for event in events if event.get("event_id") == "1"), None)
    base = process_create or first

    return {
        "group_key": group_key,
        "process_guid": base.get("process_guid"),
        "process_id": base.get("process_id"),
        "parent_process_guid": base.get("parent_process_guid"),
        "parent_process_id": base.get("parent_process_id"),
        "event_count": len(events),
        "start_time": first.get("timestamp"),
        "image": base.get("image"),
        "command_line": base.get("command_line"),
        "parent_image": base.get("parent_image"),
        "parent_command_line": base.get("parent_command_line"),
        "user": base.get("user"),
        "events": events,
    }


def build_attack_chain_candidates(sysmon_core_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups = build_process_groups(sysmon_core_events)
    process_info_map, children_map = build_process_index(sysmon_core_events)
    chains: list[dict[str, Any]] = []

    for group_key, events in groups.items():
        summary = summarize_process_group(group_key, events)
        parent_guid = summary.get("parent_process_guid")
        parent_info = process_info_map.get(parent_guid, {}) if parent_guid else {}

        child_processes = []
        for child_guid in children_map.get(summary.get("process_guid"), []):
            child_info = process_info_map.get(child_guid, {})
            child_processes.append({
                "process_guid": child_guid,
                "process_id": child_info.get("process_id"),
                "image": child_info.get("image"),
                "command_line": child_info.get("command_line"),
                "user": child_info.get("user"),
                "timestamp": child_info.get("timestamp"),
            })

        actions = [build_action_from_event(event) for event in events]
        chains.append({
            "group_key": summary.get("group_key"),
            "process_guid": summary.get("process_guid"),
            "process_id": summary.get("process_id"),
            "image": summary.get("image"),
            "command_line": summary.get("command_line"),
            "parent_process": {
                "process_guid": parent_guid,
                "process_id": summary.get("parent_process_id"),
                "image": summary.get("parent_image") or parent_info.get("image"),
                "command_line": summary.get("parent_command_line") or parent_info.get("command_line"),
            } if parent_guid else None,
            "child_processes": child_processes,
            "user": summary.get("user"),
            "start_time": summary.get("start_time"),
            "event_count": summary.get("event_count"),
            "actions": actions,
        })

    chains.sort(key=lambda x: x.get("start_time") or "")
    return chains


def build_action_from_event(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "timestamp": event.get("timestamp"),
        "event_id": event.get("event_id"),
        "event_type": event.get("event_type_name"),
        "image": event.get("image"),
        "command_line": event.get("command_line"),
        "target_filename": event.get("target_filename"),
        "target_object": event.get("target_object"),
        "destination_ip": event.get("destination_ip"),
        "destination_port": event.get("destination_port"),
        "details": event.get("details"),
    }


def abstract_event(event: dict[str, Any]) -> str:
    event_id = str(event.get("event_id") or "")
    image = event.get("image") or "unknown_image"
    command_line = event.get("command_line") or ""
    target_filename = event.get("target_filename") or ""
    target_object = event.get("target_object") or ""
    destination_ip = event.get("destination_ip") or ""
    destination_port = event.get("destination_port") or ""

    if event_id == "1":
        return f"Process execution: {image} | command: {command_line}"
    if event_id == "3":
        return f"Network connection: {image} -> {destination_ip}:{destination_port}"
    if event_id == "11":
        return f"File created: {target_filename}"
    if event_id == "12":
        return f"Registry object created/deleted: {target_object}"
    if event_id == "13":
        return f"Registry value changed: {target_object}"
    if event_id == "14":
        return f"Registry object renamed: {target_object}"

    return f"Other event: {event_id}"


def build_abstracted_attack_chains(attack_chains: list[dict[str, Any]]) -> list[dict[str, Any]]:
    results = []

    for chain in attack_chains:
        abstracted_actions = [
            {
                "timestamp": action.get("timestamp"),
                "summary": abstract_event(action),
            }
            for action in chain.get("actions", [])
        ]

        results.append({
            "process_guid": chain.get("process_guid"),
            "process_id": chain.get("process_id"),
            "image": chain.get("image"),
            "command_line": chain.get("command_line"),
            "parent_process": chain.get("parent_process"),
            "child_processes": chain.get("child_processes", []),
            "user": chain.get("user"),
            "start_time": chain.get("start_time"),
            "event_count": chain.get("event_count"),
            "abstracted_actions": abstracted_actions,
        })

    return results

