from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class NormalizedLogEvent(BaseModel):
    timestamp: str | None = None
    message: str | None = None
    event_code: str | int | None = None
    event_action: str | None = None
    event_kind: str | None = None
    provider: str | None = None
    channel: str | None = None
    event_id: str | None = None
    record_id: str | int | None = None
    computer_name: str | None = None
    provider_name: str | None = None
    log_level: str | None = None
    host_name: str | None = None
    host_hostname: str | None = None
    host_os: str | None = None
    agent_type: str | None = None
    agent_version: str | None = None
    process_pid: str | int | None = None
    parsed_type: str | None = None
    raw_event_data: dict[str, Any] = Field(default_factory=dict)


class ProcessInfo(BaseModel):
    process_guid: str | None = None
    process_id: str | int | None = None
    image: str | None = None
    command_line: str | None = None
    user: str | None = None
    timestamp: str | None = None


class ParentProcessInfo(BaseModel):
    process_guid: str | None = None
    process_id: str | int | None = None
    image: str | None = None
    command_line: str | None = None


class ChainAction(BaseModel):
    timestamp: str | None = None
    event_id: str | int | None = None
    event_type: str | None = None
    image: str | None = None
    command_line: str | None = None
    target_filename: str | None = None
    target_object: str | None = None
    destination_ip: str | None = None
    destination_port: str | int | None = None
    details: str | None = None


class AttackChain(BaseModel):
    group_key: str | None = None
    process_guid: str | None = None
    process_id: str | int | None = None
    image: str | None = None
    command_line: str | None = None
    parent_process: ParentProcessInfo | None = None
    child_processes: list[ProcessInfo] = Field(default_factory=list)
    user: str | None = None
    start_time: str | None = None
    event_count: int | None = None
    actions: list[ChainAction] = Field(default_factory=list)


class AbstractedAction(BaseModel):
    timestamp: str | None = None
    summary: str


class AbstractedAttackChain(BaseModel):
    process_guid: str | None = None
    process_id: str | int | None = None
    image: str | None = None
    command_line: str | None = None
    parent_process: ParentProcessInfo | None = None
    child_processes: list[ProcessInfo] = Field(default_factory=list)
    user: str | None = None
    start_time: str | None = None
    event_count: int | None = None
    abstracted_actions: list[AbstractedAction] = Field(default_factory=list)
