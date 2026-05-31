from __future__ import annotations

import json
import socket
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from app.core.config import settings
from app.services.report_service import analyze_winlogbeat_file
from app.services.storage import (
    create_analysis,
    get_analysis,
    set_analysis_result,
    set_analysis_status,
    update_analysis,
)
from app.utils.file_utils import build_unique_file_path, ensure_directory, save_bytes
from app.utils.hash_utils import calculate_file_sha256, calculate_sha256


SANDBOX_TAG = "netguardian-sandbox"
ACTIVE_SANDBOX_STATUSES = {
    "queued",
    "launching",
    "waiting_for_ssh",
    "transferring",
    "running",
    "terminating",
    "analyzing_logs",
}


class SandboxBusyError(ValueError):
    """Raised when the configured sandbox concurrency limit is already reached."""


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utc_now().isoformat()


def session_path(session_id: str) -> Path:
    return ensure_directory(settings.sandbox_state_dir) / f"{session_id}.json"


def save_sandbox_session(session: dict[str, Any]) -> dict[str, Any]:
    session["updated_at"] = iso_now()
    path = session_path(session["session_id"])
    with open(path, "w", encoding="utf-8") as f:
        json.dump(session, f, ensure_ascii=False, indent=2)
    return session


def load_sandbox_session(session_id: str) -> dict[str, Any] | None:
    path = session_path(session_id)
    if not path.exists():
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def update_sandbox_session(session_id: str, **updates: Any) -> dict[str, Any]:
    session = load_sandbox_session(session_id)
    if session is None:
        raise ValueError(f"Sandbox session not found: {session_id}")
    session.update(updates)
    return save_sandbox_session(session)


def iter_sandbox_sessions() -> list[dict[str, Any]]:
    state_dir = ensure_directory(settings.sandbox_state_dir)
    sessions: list[dict[str, Any]] = []
    for path in state_dir.glob("*.json"):
        try:
            with open(path, "r", encoding="utf-8") as f:
                sessions.append(json.load(f))
        except (OSError, json.JSONDecodeError):
            continue
    return sessions


def active_sandbox_sessions() -> list[dict[str, Any]]:
    return [
        session
        for session in iter_sandbox_sessions()
        if session.get("status") in ACTIVE_SANDBOX_STATUSES
    ]


def enforce_sandbox_capacity() -> None:
    max_active = settings.sandbox_max_active_sessions
    if max_active <= 0:
        return

    active = active_sandbox_sessions()
    if len(active) < max_active:
        return

    active_session = sorted(active, key=lambda item: item.get("created_at", ""))[0]
    raise SandboxBusyError(
        "Another sandbox session is already active: "
        f"{active_session.get('session_id')}"
    )


def capture_ingest_offsets() -> dict[str, int]:
    ingest_dir = ensure_directory(settings.ingest_dir)
    return {
        file_path.name: count_lines(file_path)
        for file_path in ingest_dir.glob("*.jsonl")
    }


def create_sandbox_session(
    filename: str,
    content: bytes,
    runtime_seconds: int | None,
) -> dict[str, Any]:
    if not filename:
        raise ValueError("File name is required.")
    if not content:
        raise ValueError("Empty files cannot be uploaded.")

    suffix = Path(filename).suffix.lower()
    if suffix != ".exe":
        raise ValueError("Only .exe files can be submitted to the sandbox runner.")

    if len(content) > settings.max_upload_size_bytes:
        raise ValueError("Uploaded file is too large.")

    effective_runtime = runtime_seconds or settings.sandbox_runtime_seconds
    if effective_runtime <= 0:
        raise ValueError("runtime_seconds must be greater than zero.")

    enforce_sandbox_capacity()

    session_id = str(uuid.uuid4())
    saved_path = build_unique_file_path(settings.sandbox_upload_dir, session_id, filename)
    save_bytes(saved_path, content)
    ingest_offsets = capture_ingest_offsets()

    now = iso_now()
    session = {
        "session_id": session_id,
        "status": "queued",
        "filename": filename,
        "saved_path": str(saved_path),
        "sha256": calculate_sha256(content),
        "runtime_seconds": effective_runtime,
        "created_at": now,
        "updated_at": now,
        "instance_id": None,
        "public_ip": None,
        "private_ip": None,
        "remote_path": None,
        "execution_started_at": None,
        "scheduled_termination_at": None,
        "terminated_at": None,
        "error": None,
        "message": "Sandbox run queued.",
        "analysis_id": None,
        "analysis_status": None,
        "analysis_result": None,
        "analysis_error": None,
        "ingested_stream_id": None,
        "ingested_log_path": None,
        "ingested_source_log_path": None,
        "ingested_source_offset": None,
        "ingested_event_count": None,
        "ingest_offsets": ingest_offsets,
    }
    return save_sandbox_session(session)


def require_setting(value: Any, name: str) -> Any:
    if value:
        return value
    raise RuntimeError(f"Missing required sandbox setting: {name}")


def load_boto3() -> Any:
    try:
        import boto3  # type: ignore
    except ImportError as exc:
        raise RuntimeError("boto3 is required for sandbox EC2 control.") from exc
    return boto3


def launch_windows_instance(session: dict[str, Any]) -> dict[str, str | None]:
    boto3 = load_boto3()
    image_id = require_setting(settings.sandbox_windows_ami_id, "NG_WINDOWS_AMI_ID")
    key_name = require_setting(settings.sandbox_windows_key_name, "NG_WINDOWS_KEY_NAME")
    security_group_ids = require_setting(
        settings.sandbox_windows_security_group_ids,
        "NG_WINDOWS_SECURITY_GROUP_IDS",
    )

    run_args: dict[str, Any] = {
        "ImageId": image_id,
        "InstanceType": settings.sandbox_windows_instance_type,
        "MinCount": 1,
        "MaxCount": 1,
        "KeyName": key_name,
        "SecurityGroupIds": security_group_ids,
        "TagSpecifications": [
            {
                "ResourceType": "instance",
                "Tags": [
                    {"Key": "Name", "Value": f"netguardian-sandbox-{session['session_id'][:8]}"},
                    {"Key": "Project", "Value": "netguardian"},
                    {"Key": "ManagedBy", "Value": SANDBOX_TAG},
                    {"Key": "SandboxSessionId", "Value": session["session_id"]},
                ],
            }
        ],
    }

    if settings.sandbox_windows_subnet_id:
        run_args["SubnetId"] = settings.sandbox_windows_subnet_id

    resource = boto3.resource("ec2", region_name=settings.aws_region)
    instance = resource.create_instances(**run_args)[0]
    instance.wait_until_running()
    instance.reload()

    return {
        "instance_id": instance.id,
        "public_ip": instance.public_ip_address,
        "private_ip": instance.private_ip_address,
    }


def wait_for_tcp(host: str, port: int = 22, timeout_seconds: int = 900) -> None:
    deadline = time.time() + timeout_seconds
    last_error = ""
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=5):
                return
        except OSError as exc:
            last_error = str(exc)
            time.sleep(10)
    raise RuntimeError(f"TCP {host}:{port} did not open: {last_error}")


def windows_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def remote_session_dir(session_id: str) -> str:
    return settings.sandbox_windows_remote_sample_dir.rstrip("\\/") + "\\" + session_id


def sftp_path(windows_path: str) -> str:
    return windows_path.replace("\\", "/")


def exec_checked(client: Any, command: str) -> str:
    stdin, stdout, stderr = client.exec_command(command, timeout=120)
    exit_status = stdout.channel.recv_exit_status()
    output = stdout.read().decode("utf-8", errors="replace")
    error = stderr.read().decode("utf-8", errors="replace")
    if exit_status != 0:
        raise RuntimeError(error.strip() or output.strip() or f"command failed: {command}")
    return output


def clear_sysmon_event_log(client: Any) -> None:
    command = (
        "powershell -NoProfile -ExecutionPolicy Bypass -Command "
        "\"$logName = 'Microsoft-Windows-Sysmon/Operational'; "
        "if (Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue) { "
        "wevtutil.exe cl $logName "
        "}\""
    )
    exec_checked(client, command)


def connect_windows_ssh() -> Any:
    try:
        import paramiko  # type: ignore
    except ImportError as exc:
        raise RuntimeError("paramiko is required for Windows SSH control.") from exc

    password = settings.sandbox_windows_ssh_password
    key_path = settings.sandbox_windows_ssh_key_path
    if not password and not key_path:
        raise RuntimeError(
            "Missing Windows SSH credentials. Set NG_WINDOWS_SSH_PASSWORD "
            "or NG_WINDOWS_SSH_KEY_PATH."
        )

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    return client


def transfer_and_execute_sample(session: dict[str, Any]) -> str:
    client = connect_windows_ssh()
    key_filename = (
        str(settings.sandbox_windows_ssh_key_path)
        if settings.sandbox_windows_ssh_key_path
        else None
    )

    client.connect(
        hostname=session["public_ip"],
        username=settings.sandbox_windows_ssh_username,
        password=settings.sandbox_windows_ssh_password,
        key_filename=key_filename,
        timeout=20,
        banner_timeout=40,
        auth_timeout=40,
        look_for_keys=False,
        allow_agent=False,
    )

    try:
        local_path = Path(session["saved_path"])
        remote_dir = remote_session_dir(session["session_id"])
        remote_path = remote_dir + "\\" + local_path.name

        mkdir_command = (
            "powershell -NoProfile -ExecutionPolicy Bypass -Command "
            f"\"New-Item -ItemType Directory -Force -Path {windows_quote(remote_dir)} | Out-Null\""
        )
        exec_checked(client, mkdir_command)

        with client.open_sftp() as sftp:
            sftp.put(str(local_path), sftp_path(remote_path))

        clear_sysmon_event_log(client)

        execute_command = (
            "powershell -NoProfile -ExecutionPolicy Bypass -Command "
            f"\"Start-Process -FilePath {windows_quote(remote_path)} "
            f"-WorkingDirectory {windows_quote(remote_dir)} -WindowStyle Hidden\""
        )
        exec_checked(client, execute_command)
        return remote_path
    finally:
        client.close()


def terminate_windows_instance(instance_id: str, wait: bool = True) -> None:
    boto3 = load_boto3()
    client = boto3.client("ec2", region_name=settings.aws_region)
    client.terminate_instances(InstanceIds=[instance_id])
    if wait:
        resource = boto3.resource("ec2", region_name=settings.aws_region)
        instance = resource.Instance(instance_id)
        instance.wait_until_terminated()


def analysis_id_for_stream(stream_id: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"winlogbeat-stream:{stream_id}"))


def count_lines(file_path: Path) -> int:
    with open(file_path, "r", encoding="utf-8") as f:
        return sum(1 for _ in f)


def session_log_slices_dir() -> Path:
    return ensure_directory(settings.ingest_dir / "sessions")


def write_session_log_slice(
    session_id: str,
    stream_id: str,
    lines: list[str],
) -> Path:
    safe_stream_id = "".join(
        character if character.isalnum() or character in {"-", "_", "."} else "_"
        for character in stream_id
    )
    slice_path = session_log_slices_dir() / f"{session_id}_{safe_stream_id}.jsonl"
    with open(slice_path, "w", encoding="utf-8") as f:
        f.writelines(lines)
    return slice_path


def find_ingested_log_for_session(session: dict[str, Any]) -> dict[str, Any] | None:
    ingest_dir = ensure_directory(settings.ingest_dir)
    ingest_offsets = session.get("ingest_offsets") or {}
    needles = [
        session.get("session_id"),
        session.get("remote_path"),
        Path(session["saved_path"]).name if session.get("saved_path") else None,
    ]
    search_terms = [str(value).lower() for value in needles if value]

    for file_path in sorted(
        ingest_dir.glob("*.jsonl"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    ):
        source_offset = int(ingest_offsets.get(file_path.name, 0) or 0)
        lines_after_offset: list[str] = []
        matched = False
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line_number, line in enumerate(f, start=1):
                if line_number <= source_offset:
                    continue
                lines_after_offset.append(line)
                lowered_line = line.lower()
                matched = matched or any(term in lowered_line for term in search_terms)

        if matched and lines_after_offset:
            slice_path = write_session_log_slice(
                session["session_id"],
                file_path.stem,
                lines_after_offset,
            )
            return {
                "stream_id": file_path.stem,
                "file_path": slice_path,
                "source_file_path": file_path,
                "source_offset": source_offset,
                "event_count": len(lines_after_offset),
            }

    return None


def ensure_stream_analysis_record(
    analysis_id: str,
    stream_id: str,
    file_path: Path,
) -> dict[str, Any]:
    sha256 = calculate_file_sha256(file_path)
    filename = file_path.name
    existing = get_analysis(analysis_id)

    if existing is None:
        return create_analysis(
            {
                "analysis_id": analysis_id,
                "filename": filename,
                "saved_path": str(file_path),
                "sha256": sha256,
                "status": "uploaded",
            }
        )

    return update_analysis(
        analysis_id,
        filename=filename,
        saved_path=str(file_path),
        sha256=sha256,
        status="uploaded",
        result=None,
        error=None,
    ) or existing


def analyze_sandbox_logs(
    session_id: str,
    analyzer_func: Callable[..., dict[str, Any]] = analyze_winlogbeat_file,
) -> dict[str, Any]:
    session = load_sandbox_session(session_id)
    if session is None:
        raise ValueError(f"Sandbox session not found: {session_id}")

    match = find_ingested_log_for_session(session)
    if match is None:
        return update_sandbox_session(
            session_id,
            analysis_status="logs_not_found",
            analysis_error="No ingested Winlogbeat stream matched this sandbox session.",
            message="Sandbox completed, but matching logs were not found.",
        )

    stream_id = match["stream_id"]
    file_path = match["file_path"]
    analysis_id = analysis_id_for_stream(stream_id)
    ensure_stream_analysis_record(analysis_id, stream_id, file_path)

    session = update_sandbox_session(
        session_id,
        analysis_id=analysis_id,
        analysis_status="analyzing",
        analysis_error=None,
        ingested_stream_id=stream_id,
        ingested_log_path=str(file_path),
        ingested_source_log_path=str(match["source_file_path"]),
        ingested_source_offset=match["source_offset"],
        ingested_event_count=match["event_count"],
        message="Analyzing collected Winlogbeat logs.",
    )
    set_analysis_status(analysis_id, "analyzing")

    try:
        result = analyzer_func(str(file_path), analysis_id=analysis_id)
    except Exception as exc:
        update_analysis(analysis_id, status="failed", error=str(exc))
        return update_sandbox_session(
            session_id,
            analysis_status="failed",
            analysis_error=str(exc),
            message="Sandbox completed, but log analysis failed.",
        )

    set_analysis_result(analysis_id, result)
    return update_sandbox_session(
        session_id,
        analysis_status="completed",
        analysis_result=result,
        analysis_error=None,
        message="Sandbox completed and collected logs were analyzed.",
    )


def run_sandbox_session(
    session_id: str,
    launch_func: Callable[[dict[str, Any]], dict[str, str | None]] = launch_windows_instance,
    wait_for_ssh_func: Callable[[str, int, int], None] = wait_for_tcp,
    transfer_and_execute_func: Callable[[dict[str, Any]], str] = transfer_and_execute_sample,
    sleep_func: Callable[[int], None] = time.sleep,
    terminate_func: Callable[[str, bool], None] = terminate_windows_instance,
    analyze_collected_logs_func: Callable[[str], dict[str, Any]] = analyze_sandbox_logs,
) -> dict[str, Any]:
    session = update_sandbox_session(
        session_id,
        status="launching",
        message="Launching Windows sandbox instance.",
    )

    try:
        instance_info = launch_func(session)
        session = update_sandbox_session(
            session_id,
            status="waiting_for_ssh",
            instance_id=instance_info["instance_id"],
            public_ip=instance_info["public_ip"],
            private_ip=instance_info.get("private_ip"),
            message="Waiting for Windows SSH.",
        )

        if not session["public_ip"]:
            raise RuntimeError("Launched instance does not have a public IP address.")

        wait_for_ssh_func(session["public_ip"], 22, settings.sandbox_ssh_wait_seconds)

        session = update_sandbox_session(
            session_id,
            status="transferring",
            message="Transferring sample and starting execution.",
        )
        remote_path = transfer_and_execute_func(session)

        execution_started_at = utc_now()
        scheduled_termination_at = execution_started_at + timedelta(
            seconds=session["runtime_seconds"]
        )
        session = update_sandbox_session(
            session_id,
            status="running",
            remote_path=remote_path,
            execution_started_at=execution_started_at.isoformat(),
            scheduled_termination_at=scheduled_termination_at.isoformat(),
            message="Sample execution started.",
        )

        sleep_func(session["runtime_seconds"])

        session = update_sandbox_session(
            session_id,
            status="terminating",
            message="Runtime window elapsed; terminating sandbox instance.",
        )
        terminate_func(session["instance_id"], settings.sandbox_terminate_wait)

        session = update_sandbox_session(
            session_id,
            status="analyzing_logs",
            message="Runtime window elapsed; analyzing collected logs.",
        )
        session = analyze_collected_logs_func(session_id)

        return update_sandbox_session(
            session_id,
            status="terminated",
            terminated_at=iso_now(),
            message=session.get("message") or "Sandbox instance terminated after runtime window.",
        )
    except Exception as exc:
        failed_session = update_sandbox_session(
            session_id,
            status="failed",
            error=str(exc),
            message="Sandbox run failed.",
        )
        instance_id = failed_session.get("instance_id")
        if instance_id:
            try:
                terminate_func(instance_id, settings.sandbox_terminate_wait)
                failed_session = update_sandbox_session(
                    session_id,
                    status="failed",
                    terminated_at=iso_now(),
                    message="Sandbox run failed; instance termination was requested.",
                )
            except Exception as terminate_exc:
                failed_session = update_sandbox_session(
                    session_id,
                    status="failed",
                    error=f"{exc}; termination failed: {terminate_exc}",
                )
        return failed_session
