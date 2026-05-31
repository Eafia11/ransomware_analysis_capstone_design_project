from __future__ import annotations

from pathlib import Path

import pytest

from app.core.config import settings
from app.services import sandbox_service


def test_create_sandbox_session_saves_exe_and_initial_state(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "sandbox_upload_dir", tmp_path / "sandbox_uploads")
    monkeypatch.setattr(settings, "sandbox_state_dir", tmp_path / "sandbox_sessions")
    monkeypatch.setattr(settings, "sandbox_runtime_seconds", 120)

    session = sandbox_service.create_sandbox_session(
        filename="danger sample.exe",
        content=b"MZ fake exe",
        runtime_seconds=None,
    )

    assert session["status"] == "queued"
    assert session["filename"] == "danger sample.exe"
    assert session["runtime_seconds"] == 120
    assert "danger_sample.exe" in session["saved_path"]
    assert Path(session["saved_path"]).read_bytes() == b"MZ fake exe"
    assert sandbox_service.load_sandbox_session(session["session_id"]) == session


def test_create_sandbox_session_rejects_non_exe(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "sandbox_upload_dir", tmp_path / "sandbox_uploads")
    monkeypatch.setattr(settings, "sandbox_state_dir", tmp_path / "sandbox_sessions")

    with pytest.raises(ValueError, match="Only .exe"):
        sandbox_service.create_sandbox_session(
            filename="events.jsonl",
            content=b"{}",
            runtime_seconds=60,
        )


def test_run_sandbox_session_launches_transfers_runs_and_terminates(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "sandbox_upload_dir", tmp_path / "sandbox_uploads")
    monkeypatch.setattr(settings, "sandbox_state_dir", tmp_path / "sandbox_sessions")

    session = sandbox_service.create_sandbox_session(
        filename="sample.exe",
        content=b"MZ fake exe",
        runtime_seconds=30,
    )
    calls = []

    def fake_launch(record):
        calls.append(("launch", record["session_id"]))
        return {"instance_id": "i-123", "public_ip": "203.0.113.10"}

    def fake_wait(host, port, timeout_seconds):
        calls.append(("wait_ssh", host, port, timeout_seconds))

    def fake_transfer(record):
        calls.append(("transfer_execute", record["instance_id"]))
        return r"C:\NetGuardian\Samples\sample.exe"

    def fake_sleep(seconds):
        calls.append(("sleep", seconds))

    def fake_terminate(instance_id, wait):
        calls.append(("terminate", instance_id, wait))

    final_session = sandbox_service.run_sandbox_session(
        session["session_id"],
        launch_func=fake_launch,
        wait_for_ssh_func=fake_wait,
        transfer_and_execute_func=fake_transfer,
        sleep_func=fake_sleep,
        terminate_func=fake_terminate,
    )

    assert final_session["status"] == "terminated"
    assert final_session["instance_id"] == "i-123"
    assert final_session["public_ip"] == "203.0.113.10"
    assert final_session["remote_path"] == r"C:\NetGuardian\Samples\sample.exe"
    assert calls == [
        ("launch", session["session_id"]),
        ("wait_ssh", "203.0.113.10", 22, settings.sandbox_ssh_wait_seconds),
        ("transfer_execute", "i-123"),
        ("sleep", 30),
        ("terminate", "i-123", True),
    ]


def test_transfer_and_execute_sample_clears_sysmon_before_process_start(monkeypatch, tmp_path):
    sample_path = tmp_path / "payload.exe"
    sample_path.write_bytes(b"MZ fake exe")
    commands = []
    uploaded = []

    class FakeChannel:
        def recv_exit_status(self):
            return 0

    class FakeStream:
        channel = FakeChannel()

        def read(self):
            return b""

    class FakeSftp:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def put(self, local_path, remote_path):
            uploaded.append((local_path, remote_path))

    class FakeClient:
        def connect(self, **kwargs):
            self.connection_args = kwargs

        def exec_command(self, command, timeout=120):
            commands.append(command)
            return None, FakeStream(), FakeStream()

        def open_sftp(self):
            return FakeSftp()

        def close(self):
            commands.append("close")

    fake_client = FakeClient()
    monkeypatch.setattr(sandbox_service, "connect_windows_ssh", lambda: fake_client)
    monkeypatch.setattr(settings, "sandbox_windows_ssh_username", "Administrator")
    monkeypatch.setattr(settings, "sandbox_windows_ssh_password", "secret")
    monkeypatch.setattr(settings, "sandbox_windows_ssh_key_path", None)
    monkeypatch.setattr(settings, "sandbox_windows_remote_sample_dir", r"C:\NetGuardian\Samples")

    remote_path = sandbox_service.transfer_and_execute_sample(
        {
            "session_id": "session-1",
            "saved_path": str(sample_path),
            "public_ip": "203.0.113.10",
        }
    )

    assert remote_path == r"C:\NetGuardian\Samples\session-1\payload.exe"
    assert uploaded == [
        (
            str(sample_path),
            "C:/NetGuardian/Samples/session-1/payload.exe",
        )
    ]
    clear_index = next(
        index
        for index, command in enumerate(commands)
        if "wevtutil.exe cl" in command
    )
    execute_index = next(
        index
        for index, command in enumerate(commands)
        if "Start-Process" in command
    )
    assert "Microsoft-Windows-Sysmon/Operational" in commands[clear_index]
    assert clear_index < execute_index
