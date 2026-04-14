from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any


def load_json_lines(file_path: str) -> list[dict[str, Any]]:
    """
    Winlogbeat JSON Lines 파일을 읽는다.
    한 줄에 JSON 객체 하나씩 들어있는 형식 전용.
    """
    events: list[dict[str, Any]] = []

    with open(file_path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"[WARN] {line_no}번째 줄 JSON 파싱 실패: {e}")
                continue

    return events


def safe_get(data: dict[str, Any], *keys: str) -> Any:
    current: Any = data
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
        if current is None:
            return None
    return current


def map_sysmon_event_name(event_id: str | None) -> str | None:
    mapping = {
        "1": "ProcessCreate",
        "2": "FileCreationTimeChanged",
        "3": "NetworkConnection",
        "5": "ProcessTerminate",
        "6": "DriverLoaded",
        "7": "ImageLoaded",
        "8": "CreateRemoteThread",
        "10": "ProcessAccess",
        "11": "FileCreate",
        "12": "RegistryObjectCreateDelete",
        "13": "RegistryValueSet",
        "14": "RegistryObjectRename",
        "15": "FileCreateStreamHash",
        "17": "PipeCreated",
        "18": "PipeConnected",
        "22": "DNSEvent",
        "23": "FileDelete",
        "24": "ClipboardChange",
        "25": "ProcessTampering",
        "26": "FileDeleteDetected",
    }
    return mapping.get(event_id)


def parse_common_event(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "timestamp": event.get("@timestamp"),
        "message": event.get("message"),
        "event_code": safe_get(event, "event", "code"),
        "event_action": safe_get(event, "event", "action"),
        "event_kind": safe_get(event, "event", "kind"),
        "provider": safe_get(event, "event", "provider"),
        "channel": safe_get(event, "winlog", "channel"),
        "event_id": str(safe_get(event, "winlog", "event_id")) if safe_get(event, "winlog", "event_id") is not None else None,
        "record_id": safe_get(event, "winlog", "record_id"),
        "computer_name": safe_get(event, "winlog", "computer_name"),
        "provider_name": safe_get(event, "winlog", "provider_name"),
        "log_level": safe_get(event, "log", "level"),
        "host_name": safe_get(event, "host", "name"),
        "host_hostname": safe_get(event, "host", "hostname"),
        "host_os": safe_get(event, "host", "os", "name"),
        "agent_type": safe_get(event, "agent", "type"),
        "agent_version": safe_get(event, "agent", "version"),
        "process_pid": safe_get(event, "winlog", "process", "pid"),
        "raw_event_data": safe_get(event, "winlog", "event_data") or {},
        "raw": event,
    }


def parse_powershell_event(event: dict[str, Any], base: dict[str, Any]) -> dict[str, Any]:
    event_data = safe_get(event, "winlog", "event_data") or {}

    base.update({
        "parsed_type": "powershell",
        "ps_param1": event_data.get("param1"),
        "ps_param2": event_data.get("param2"),
        "ps_detail": event_data.get("param3"),
        "script_block_text": event_data.get("ScriptBlockText"),
        "script_block_id": event_data.get("ScriptBlockId"),
        "path": event_data.get("Path"),
    })

    return base


def parse_sysmon_event(event: dict[str, Any], base: dict[str, Any]) -> dict[str, Any]:
    event_data = safe_get(event, "winlog", "event_data") or {}
    event_id = base.get("event_id")

    base.update({
        "parsed_type": "sysmon",
        "event_type_name": map_sysmon_event_name(event_id),

        "process_guid": event_data.get("ProcessGuid"),
        "process_id": event_data.get("ProcessId"),
        "image": event_data.get("Image"),
        "command_line": event_data.get("CommandLine"),
        "current_directory": event_data.get("CurrentDirectory"),
        "user": event_data.get("User"),
        "logon_guid": event_data.get("LogonGuid"),
        "logon_id": event_data.get("LogonId"),
        "terminal_session_id": event_data.get("TerminalSessionId"),
        "integrity_level": event_data.get("IntegrityLevel"),
        "hashes": event_data.get("Hashes"),

        "parent_process_guid": event_data.get("ParentProcessGuid"),
        "parent_process_id": event_data.get("ParentProcessId"),
        "parent_image": event_data.get("ParentImage"),
        "parent_command_line": event_data.get("ParentCommandLine"),

        "target_filename": event_data.get("TargetFilename"),
        "creation_utc_time": event_data.get("CreationUtcTime"),

        "destination_ip": event_data.get("DestinationIp"),
        "destination_port": event_data.get("DestinationPort"),
        "source_ip": event_data.get("SourceIp"),
        "source_port": event_data.get("SourcePort"),
        "protocol": event_data.get("Protocol"),

        "target_object": event_data.get("TargetObject"),
        "details": event_data.get("Details"),
    })

    return base


def normalize_winlogbeat_event(event: dict[str, Any]) -> dict[str, Any]:
    base = parse_common_event(event)

    channel = base.get("channel")
    provider_name = base.get("provider_name")

    if channel == "Windows PowerShell" or provider_name == "PowerShell":
        return parse_powershell_event(event, base)

    if channel == "Microsoft-Windows-PowerShell/Operational" or provider_name == "Microsoft-Windows-PowerShell":
        return parse_powershell_event(event, base)

    if channel == "Microsoft-Windows-Sysmon/Operational" or provider_name == "Microsoft-Windows-Sysmon":
        return parse_sysmon_event(event, base)

    base["parsed_type"] = "generic"
    return base


def parse_winlogbeat_file(file_path: str) -> list[dict[str, Any]]:
    raw_events = load_json_lines(file_path)
    parsed_events = [normalize_winlogbeat_event(event) for event in raw_events]
    parsed_events.sort(key=lambda x: x.get("timestamp") or "")
    return parsed_events


def save_json(data: list[dict[str, Any]], output_path: str) -> None:
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def filter_events(
    events: list[dict[str, Any]],
    channel: str | None = None,
    provider_name: str | None = None,
    event_id: str | None = None,
    parsed_type: str | None = None,
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []

    for event in events:
        if channel is not None and event.get("channel") != channel:
            continue
        if provider_name is not None and event.get("provider_name") != provider_name:
            continue
        if event_id is not None and str(event.get("event_id")) != str(event_id):
            continue
        if parsed_type is not None and event.get("parsed_type") != parsed_type:
            continue
        result.append(event)

    return result


def summarize_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    by_channel: dict[str, int] = {}
    by_provider: dict[str, int] = {}
    by_event_id: dict[str, int] = {}

    for event in events:
        channel = str(event.get("channel"))
        provider = str(event.get("provider_name"))
        event_id = str(event.get("event_id"))

        by_channel[channel] = by_channel.get(channel, 0) + 1
        by_provider[provider] = by_provider.get(provider, 0) + 1
        by_event_id[event_id] = by_event_id.get(event_id, 0) + 1

    return {
        "total": len(events),
        "by_channel": dict(sorted(by_channel.items(), key=lambda x: x[0])),
        "by_provider": dict(sorted(by_provider.items(), key=lambda x: x[0])),
        "by_event_id": dict(sorted(by_event_id.items(), key=lambda x: x[0])),
    }


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

        # 1순위: 정상적인 ProcessGuid가 있으면 그걸 사용
        if process_guid and process_guid != "{GUID-REDACTED}":
            group_key = f"guid::{process_guid}"

        # 2순위: 프로세스 생성 이벤트는 PID+Image+CommandLine 기준
        elif event_id == "1":
            group_key = f"proc::{process_id}::{image}::{command_line}"

        # 3순위: 파일/레지스트리/네트워크 이벤트는 image 기반으로 묶기
        else:
            # timestamp 앞부분(분 단위)까지만 잘라서 너무 넓게 안 묶이게 제한
            time_bucket = timestamp[:16] if timestamp else "unknown_time"
            group_key = f"fallback::{process_id}::{image}::{parent_image}::{user}::{time_bucket}"

        grouped[group_key].append(event)

    for group_key in grouped:
        grouped[group_key].sort(key=lambda x: x.get("timestamp") or "")

    return dict(grouped)


def summarize_process_group(process_guid: str, events: list[dict[str, Any]]) -> dict[str, Any]:
    first = events[0] if events else {}

    process_create = None
    for event in events:
        if event.get("event_id") == "1":
            process_create = event
            break

    base = process_create or first

    return {
        "process_guid": process_guid,
        "event_count": len(events),
        "start_time": first.get("timestamp"),
        "image": base.get("image"),
        "command_line": base.get("command_line"),
        "parent_image": base.get("parent_image"),
        "user": base.get("user"),
        "events": events,
    }


def build_attack_chain_candidates(sysmon_core_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Sysmon 핵심 이벤트를 ProcessGuid 기준으로 묶어
    간단한 공격 체인 후보를 만든다.
    """
    groups = build_process_groups(sysmon_core_events)
    chains: list[dict[str, Any]] = []

    for process_guid, events in groups.items():
        summary = summarize_process_group(process_guid, events)

        actions: list[dict[str, Any]] = []
        for event in events:
            event_id = event.get("event_id")
            action = {
                "timestamp": event.get("timestamp"),
                "event_id": event_id,
                "event_type": event.get("event_type_name"),
                "image": event.get("image"),
                "command_line": event.get("command_line"),
                "target_filename": event.get("target_filename"),
                "target_object": event.get("target_object"),
                "destination_ip": event.get("destination_ip"),
                "destination_port": event.get("destination_port"),
                "details": event.get("details"),
            }
            actions.append(action)

        chains.append({
            "process_guid": process_guid,
            "image": summary.get("image"),
            "command_line": summary.get("command_line"),
            "parent_image": summary.get("parent_image"),
            "user": summary.get("user"),
            "start_time": summary.get("start_time"),
            "event_count": summary.get("event_count"),
            "actions": actions,
        })

    chains.sort(key=lambda x: x.get("start_time") or "")
    return chains

def abstract_event(event: dict[str, Any]) -> str:
    event_id = str(event.get("event_id") or "")
    image = event.get("image") or "unknown_image"
    command_line = event.get("command_line") or ""
    target_filename = event.get("target_filename") or ""
    target_object = event.get("target_object") or ""
    destination_ip = event.get("destination_ip") or ""
    destination_port = event.get("destination_port") or ""

    if event_id == "1":
        return f"프로세스 실행: {image} | 명령어: {command_line}"
    if event_id == "3":
        return f"네트워크 연결: {image} -> {destination_ip}:{destination_port}"
    if event_id == "11":
        return f"파일 생성: {target_filename}"
    if event_id == "12":
        return f"레지스트리 객체 생성/삭제: {target_object}"
    if event_id == "13":
        return f"레지스트리 값 변경: {target_object}"
    if event_id == "14":
        return f"레지스트리 객체 이름 변경: {target_object}"

    return f"기타 이벤트({event_id})"


def build_abstracted_attack_chains(attack_chains: list[dict[str, Any]]) -> list[dict[str, Any]]:
    results = []

    for chain in attack_chains:
        actions = chain.get("actions", [])
        abstracted_actions = []

        for action in actions:
            abstracted_actions.append({
                "timestamp": action.get("timestamp"),
                "summary": abstract_event(action),
            })

        results.append({
            "process_guid": chain.get("process_guid"),
            "image": chain.get("image"),
            "command_line": chain.get("command_line"),
            "parent_image": chain.get("parent_image"),
            "user": chain.get("user"),
            "start_time": chain.get("start_time"),
            "event_count": chain.get("event_count"),
            "abstracted_actions": abstracted_actions,
        })

    return results