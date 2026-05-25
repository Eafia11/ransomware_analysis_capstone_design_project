from __future__ import annotations

from typing import Any


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
    event_id = safe_get(event, "winlog", "event_id")
    return {
        "timestamp": event.get("@timestamp"),
        "message": event.get("message"),
        "event_code": safe_get(event, "event", "code"),
        "event_action": safe_get(event, "event", "action"),
        "event_kind": safe_get(event, "event", "kind"),
        "provider": safe_get(event, "event", "provider"),
        "channel": safe_get(event, "winlog", "channel"),
        "event_id": str(event_id) if event_id is not None else None,
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
