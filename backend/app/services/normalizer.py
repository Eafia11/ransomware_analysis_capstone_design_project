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


def first_present(*values: Any) -> Any:
    for value in values:
        if value is not None:
            return value
    return None


def event_data_from(event: dict[str, Any]) -> dict[str, Any]:
    event_data = (
        safe_get(event, "winlog", "event_data")
        or event.get("event_data")
        or event.get("EventData")
        or {}
    )
    return event_data if isinstance(event_data, dict) else {}


def event_value(event: dict[str, Any], event_data: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = event_data.get(key)
        if value is not None:
            return value
        value = event.get(key)
        if value is not None:
            return value
    return None


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
    event_id = first_present(
        safe_get(event, "winlog", "event_id"),
        safe_get(event, "event", "code"),
        event.get("event_id"),
        event.get("EventID"),
        event.get("EventId"),
    )
    provider_name = first_present(
        safe_get(event, "winlog", "provider_name"),
        safe_get(event, "event", "provider"),
        event.get("provider_name"),
        event.get("ProviderName"),
        event.get("Provider"),
    )
    channel = first_present(
        safe_get(event, "winlog", "channel"),
        event.get("channel"),
        event.get("Channel"),
    )

    if channel is None and str(provider_name or "").lower() == "microsoft-windows-sysmon":
        channel = "Microsoft-Windows-Sysmon/Operational"

    return {
        "timestamp": first_present(event.get("@timestamp"), event.get("TimeCreated")),
        "message": first_present(event.get("message"), event.get("Message")),
        "event_code": first_present(safe_get(event, "event", "code"), event.get("EventID")),
        "event_action": safe_get(event, "event", "action"),
        "event_kind": safe_get(event, "event", "kind"),
        "provider": first_present(safe_get(event, "event", "provider"), event.get("Provider")),
        "channel": channel,
        "event_id": str(event_id) if event_id is not None else None,
        "record_id": first_present(safe_get(event, "winlog", "record_id"), event.get("RecordId")),
        "computer_name": first_present(
            safe_get(event, "winlog", "computer_name"),
            event.get("MachineName"),
            event.get("ComputerName"),
        ),
        "provider_name": provider_name,
        "log_level": first_present(safe_get(event, "log", "level"), event.get("Level")),
        "host_name": safe_get(event, "host", "name"),
        "host_hostname": safe_get(event, "host", "hostname"),
        "host_os": safe_get(event, "host", "os", "name"),
        "agent_type": safe_get(event, "agent", "type"),
        "agent_version": safe_get(event, "agent", "version"),
        "process_pid": safe_get(event, "winlog", "process", "pid"),
        "raw_event_data": event_data_from(event),
        "raw": event,
    }


def parse_powershell_event(event: dict[str, Any], base: dict[str, Any]) -> dict[str, Any]:
    event_data = event_data_from(event)
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
    event_data = event_data_from(event)
    event_id = base.get("event_id")
    base.update({
        "parsed_type": "sysmon",
        "event_type_name": map_sysmon_event_name(event_id),
        "process_guid": event_value(event, event_data, "ProcessGuid", "process_guid"),
        "process_id": event_value(event, event_data, "ProcessId", "ProcessID", "process_id"),
        "image": event_value(event, event_data, "Image", "image"),
        "command_line": event_value(event, event_data, "CommandLine", "command_line"),
        "current_directory": event_value(event, event_data, "CurrentDirectory", "current_directory"),
        "user": event_value(event, event_data, "User", "user"),
        "logon_guid": event_value(event, event_data, "LogonGuid", "logon_guid"),
        "logon_id": event_value(event, event_data, "LogonId", "logon_id"),
        "terminal_session_id": event_value(
            event,
            event_data,
            "TerminalSessionId",
            "terminal_session_id",
        ),
        "integrity_level": event_value(event, event_data, "IntegrityLevel", "integrity_level"),
        "hashes": event_value(event, event_data, "Hashes", "hashes"),
        "parent_process_guid": event_value(
            event,
            event_data,
            "ParentProcessGuid",
            "parent_process_guid",
        ),
        "parent_process_id": event_value(
            event,
            event_data,
            "ParentProcessId",
            "ParentProcessID",
            "parent_process_id",
        ),
        "parent_image": event_value(event, event_data, "ParentImage", "parent_image"),
        "parent_command_line": event_value(
            event,
            event_data,
            "ParentCommandLine",
            "parent_command_line",
        ),
        "target_filename": event_value(
            event,
            event_data,
            "TargetFilename",
            "TargetFileName",
            "target_filename",
            "targetFilename",
            "FileName",
            "Filename",
        ),
        "creation_utc_time": event_value(
            event,
            event_data,
            "CreationUtcTime",
            "creation_utc_time",
        ),
        "destination_ip": event_value(event, event_data, "DestinationIp", "destination_ip"),
        "destination_port": event_value(
            event,
            event_data,
            "DestinationPort",
            "destination_port",
        ),
        "source_ip": event_value(event, event_data, "SourceIp", "source_ip"),
        "source_port": event_value(event, event_data, "SourcePort", "source_port"),
        "protocol": event_value(event, event_data, "Protocol", "protocol"),
        "target_object": event_value(event, event_data, "TargetObject", "target_object"),
        "details": event_value(event, event_data, "Details", "details"),
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
