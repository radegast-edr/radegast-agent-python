import base64
import io
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import httpx
from ssage import SSAGE


def run_command(cmd, cwd=None, env=None):
    print(f"Running command: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    res = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, env=env, check=False)
    print("STDOUT:")
    print(res.stdout)
    print("STDERR:")
    print(res.stderr)
    if res.returncode != 0:
        raise RuntimeError(f"Command failed with code {res.returncode}")
    return res


def stop_process(proc, name, log_file=None):
    if not proc:
        return
    print(f"Stopping {name} process...")
    if sys.platform.startswith("win32"):
        # On Windows, terminating the parent process leaves child processes running.
        # Use taskkill to kill the whole process tree.
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
            capture_output=True,
            check=False,
        )
    else:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    if log_file and Path(log_file).exists():
        try:
            content = Path(log_file).read_text(encoding="utf-8", errors="replace")
            print(f"{name} log:\n{content}")
        except Exception as e:
            print(f"Failed to read {name} log: {e}")


def test_agent_integration():
    # 1. Setup temporary workspace
    temp_dir = tempfile.TemporaryDirectory()
    temp_path = Path(temp_dir.name)
    db_file = temp_path / "radegast_agent_integration.db"
    db_url = f"sqlite+aiosqlite:///{db_file}"
    uploads_dir = temp_path / "uploads"
    uploads_dir.mkdir(parents=True, exist_ok=True)

    agent_state_dir = temp_path / "agent_state"
    agent_rules_dir = temp_path / "agent_rules"
    agent_alerts_dir = temp_path / "agent_alerts"
    agent_state_dir.mkdir()
    agent_rules_dir.mkdir()
    agent_alerts_dir.mkdir()

    backend_dir = temp_path / "radegast-console-backend"

    # Environment variables for the backend and migrations
    backend_env = os.environ.copy()
    backend_env["RADEGAST_DATABASE_URL"] = db_url
    backend_env["RADEGAST_SECRET_KEY"] = "integration-test-secret-key"
    backend_env["RADEGAST_UPLOAD_DIR"] = str(uploads_dir)
    backend_env["RADEGAST_RELEASES_DIR"] = str(backend_dir / "agent" / "releases")
    backend_env["RADEGAST_ENVIRONMENT"] = "dev"
    backend_env["RADEGAST_ENABLE_EMAIL_WORKER"] = "False"

    server_process = None
    agent_process = None

    try:
        # Setup console backend: use local workspace repo if present, otherwise clone
        local_backend = Path(__file__).resolve().parents[2] / "radegast-console-backend"
        if not os.environ.get("FORCE_GITHUB_BACKEND") and local_backend.exists() and (local_backend / "app").exists():
            print(f"Using local console backend from {local_backend}...")
            shutil.copytree(
                local_backend,
                backend_dir,
                ignore=shutil.ignore_patterns(
                    ".git",
                    ".venv",
                    "__pycache__",
                    "*.pyc",
                    "node_modules",
                    ".antigravitycli*",
                    ".pytest_cache",
                    ".ruff_cache",
                    ".idea",
                    ".vscode",
                ),
            )
        else:
            print("Cloning console backend from GitHub...")
            run_command(
                [
                    "git",
                    "clone",
                    "--depth",
                    "1",
                    "https://github.com/radegast-edr/radegast-console-backend.git",
                    str(backend_dir),
                ]
            )

        # Run migrations on backend
        print("Applying database migrations on backend...")
        run_command(
            ["uv", "run", "python", "apply-migrations.py"],
            cwd=backend_dir,
            env=backend_env,
        )

        # Start backend uvicorn server in background
        print("Starting backend server...")
        backend_log = temp_path / "backend.log"
        backend_log_f = open(backend_log, "w", encoding="utf-8")
        server_process = subprocess.Popen(
            [
                "uv",
                "run",
                "uvicorn",
                "app.main:app",
                "--port",
                "8081",
                "--host",
                "127.0.0.1",
            ],
            cwd=backend_dir,
            env=backend_env,
            stdout=backend_log_f,
            stderr=subprocess.STDOUT,
        )

        # Wait for backend server to be healthy
        print("Waiting for server to become healthy...")
        healthy = False
        for _ in range(15):
            try:
                resp = httpx.get("http://127.0.0.1:8081/api/v1/health", timeout=1.0)
                if resp.status_code == 200 and resp.json().get("status") == "ok":
                    healthy = True
                    break
            except Exception:
                pass
            time.sleep(1)

        if not healthy:
            raise RuntimeError("Backend server failed to start or respond to health check.")

        # Register user via API
        print("Registering user...")
        email = "agent-integration@example.com"
        password = "IntegrationPass123!"
        with httpx.Client(base_url="http://127.0.0.1:8081/api/v1", follow_redirects=True) as client:
            resp = client.post("/auth/register", json={"email": email, "password": password})
            if resp.status_code != 200:
                raise RuntimeError(f"Registration failed: {resp.text}")

        # Promote and verify user via SQLite direct query
        print("Promoting and verifying user directly in SQLite...")
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET verified = 1, role = 'admin' WHERE email = ?;", (email,))
        conn.commit()
        conn.close()

        # Generate valid AGE keys using ssage
        private_key = SSAGE.generate_private_key()
        s = SSAGE(private_key)
        main_pub = s.public_key

        rec_private = SSAGE.generate_private_key()
        rec_s = SSAGE(rec_private)
        rec_pub = rec_s.public_key

        # Login and configure pack/group/device
        device_token = None
        device_id = None
        group_id = None
        rule_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

        with httpx.Client(base_url="http://127.0.0.1:8081/api/v1", follow_redirects=True) as client:
            # Login
            resp = client.post("/auth/login", json={"email": email, "password": password})
            if resp.status_code != 200:
                raise RuntimeError(f"Login failed: {resp.text}")

            # Setup AGE keys
            resp = client.post(
                "/user/keys/setup",
                json={
                    "public_key": main_pub,
                    "recovery_public_key": rec_pub,
                    "recovery_encrypted_private_key": "dummy-encrypted-private-key",
                },
            )
            if resp.status_code != 200:
                raise RuntimeError(f"Keys setup failed: {resp.text}")

            # Get team and group
            resp = client.get("/teams/")
            team_id = resp.json()[0]["id"]
            resp = client.get(f"/teams/{team_id}/groups")
            group_id = resp.json()[0]["id"]

            # Create Pack
            resp = client.post("/packs/", json={"name": "test-pack", "description": "test rules"})
            pack_id = resp.json()["id"]

            # Create in-memory zip for pack
            zip_buffer = io.BytesIO()
            rule_content = f"""
title: Test Rule
id: {rule_id}
status: experimental
description: Detects test event.
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    Image|endswith: '/whoami'
  condition: selection
level: low
"""
            with zipfile.ZipFile(zip_buffer, "a", zipfile.ZIP_DEFLATED, False) as zip_file:
                zip_file.writestr("sigma/test_rule.yml", rule_content.strip())
            zip_bytes = zip_buffer.getvalue()

            # Upload pack version
            resp = client.post(
                f"/packs/{pack_id}/versions?version=1.0.0",
                files={"file": ("pack.zip", zip_bytes, "application/zip")},
            )
            pack_version_id = resp.json()["id"]

            # Enable pack for group
            resp = client.post(
                f"/packs/groups/{group_id}/enable",
                json={"pack_version_id": pack_version_id, "autoupdate": False},
            )

            # Create device
            resp = client.post("/devices/", json={"name": "agent-test-device", "group_id": group_id})
            device_data = resp.json()
            device_token = device_data["token"]
            device_id = device_data["id"]

        print(f"Registered device with token: {device_token}")

        # Verify Windows installer templates served by the backend
        print("Verifying Windows installer templates from backend...")
        with httpx.Client(base_url="http://127.0.0.1:8081/api/v1") as client:
            # 1. Default Windows install (no explicit autoupdate param)
            resp = client.get("/device/install?os=windows")
            if resp.status_code != 200:
                raise RuntimeError(f"Failed to get default windows install script: {resp.status_code} {resp.text}")
            chunks = re.findall(r"\(echo\s+([A-Za-z0-9+/=]+)\)", resp.text)
            decoded_service = base64.b64decode("".join(chunks)).decode("utf-8")

            assert '<env name="UV_TOOL_DIR" value="{agent_tools_dir}" />' in decoded_service, (
                "Default Windows install script must configure UV_TOOL_DIR in service XML"
            )
            assert '<env name="UV_TOOL_BIN_DIR" value="{tool_bin_dir}" />' in decoded_service, (
                "Default Windows install script must configure UV_TOOL_BIN_DIR in service XML"
            )
            assert '<env name="UV_CACHE_DIR" value="{cache_dir}" />' in decoded_service, (
                "Default Windows install script must configure UV_CACHE_DIR in service XML"
            )
            assert '<env name="UV_PYTHON" value="{python_exe_path}" />' in decoded_service, (
                "Default Windows install script must configure UV_PYTHON in service XML"
            )

            # 2. Windows install with agent-autoupdate=false
            resp_noauto = client.get("/device/install?os=windows&agent-autoupdate=false")
            chunks_noauto = re.findall(r"\(echo\s+([A-Za-z0-9+/=]+)\)", resp_noauto.text)
            decoded_noauto = base64.b64decode("".join(chunks_noauto)).decode("utf-8")
            assert '<env name="UV_TOOL_DIR" value="{agent_tools_dir}" />' in decoded_noauto
            assert "agent_autoupdate = False" in decoded_noauto

            # 3. Windows install with agent-autoupdate=true
            resp_auto = client.get("/device/install?os=windows&agent-autoupdate=true")
            chunks_auto = re.findall(r"\(echo\s+([A-Za-z0-9+/=]+)\)", resp_auto.text)
            decoded_auto = base64.b64decode("".join(chunks_auto)).decode("utf-8")
            assert '<env name="UV_TOOL_DIR" value="{agent_tools_dir}" />' in decoded_auto
            assert "agent_autoupdate = True" in decoded_auto

        # Start agent CLI process pointing to our backend
        print("Starting python agent...")

        # Install agent as uv tool in temporary tool directory
        tool_dir = temp_path / "uv_tools"
        tool_bin_dir = temp_path / "uv_bin"
        tool_cache_dir = temp_path / "uv_cache"
        tool_env = os.environ.copy()
        tool_env["UV_TOOL_DIR"] = str(tool_dir)
        tool_env["UV_TOOL_BIN_DIR"] = str(tool_bin_dir)
        tool_env["UV_CACHE_DIR"] = str(tool_cache_dir)

        print("Installing radegast-edr-agent 0.8.0 as tool...")
        run_command(["uv", "tool", "install", "--force", "radegast-edr-agent==0.8.0"], env=tool_env)
        receipt_path = tool_dir / "radegast-edr-agent" / "uv-receipt.toml"
        if receipt_path.exists():
            receipt_content = receipt_path.read_text(encoding="utf-8")
            receipt_path.write_text(receipt_content.replace('specifier = "==0.8.0"', ""), encoding="utf-8")
        exe_name = "radegast-edr-agent.exe" if sys.platform.startswith("win32") else "radegast-edr-agent"
        agent_bin = tool_bin_dir / exe_name

        ver_res = run_command([str(agent_bin), "-V"])
        print(f"Installed initial agent version: {ver_res.stdout.strip()}")
        assert "0.8.0" in ver_res.stdout

        # Start agent CLI process pointing to our backend
        print("Starting python agent...")
        # Pre-create a valid encryption key file so agent doesn't generate a new one
        # (generating a new one would trigger a 90-second wait for backend to re-encrypt exclusions)
        encryption_key_path = agent_state_dir / "device_enc_key"
        encryption_key_path.parent.mkdir(parents=True, exist_ok=True)
        # Generate a valid AGE private key
        private_key = SSAGE.generate_private_key()
        encryption_key_path.write_text(private_key)

        rustinel_mock = shutil.which("true") or shutil.which("cmd") or sys.executable
        agent_env = os.environ.copy()
        agent_env.pop("UV_PROJECT_ROOT", None)
        agent_env.pop("VIRTUAL_ENV", None)
        # Ensure agent_env matches the environment configured by radegast-agent-service.xml
        # (which we validated above contains UV_TOOL_DIR, UV_TOOL_BIN_DIR, UV_CACHE_DIR, UV_PYTHON)
        agent_env["UV_TOOL_DIR"] = str(tool_dir)
        agent_env["UV_TOOL_BIN_DIR"] = str(tool_bin_dir)
        agent_env["UV_CACHE_DIR"] = str(tool_cache_dir)
        agent_env["UV_PYTHON"] = sys.executable
        agent_env["PYTHONUNBUFFERED"] = "1"
        agent_env["RADEGAST_AGENT_BACKEND_URL"] = "http://127.0.0.1:8081/api/v1"
        agent_env["RADEGAST_AGENT_DEVICE_TOKEN"] = device_token
        agent_env["RADEGAST_AGENT_RULES_DIR"] = str(agent_rules_dir)
        agent_env["RADEGAST_AGENT_ALERTS_DIR"] = str(agent_alerts_dir)
        agent_env["RADEGAST_AGENT_STATE_DIR"] = str(agent_state_dir)
        agent_env["RADEGAST_AGENT_RUSTINEL_BINARY"] = rustinel_mock
        agent_env["RADEGAST_AGENT_INIT_WAIT_SECONDS"] = "0"
        agent_env["RADEGAST_AGENT_AUTOUPDATE"] = "true"
        agent_env["RADEGAST_AGENT_AUTOUPDATE_INITIAL_DELAY"] = "4"
        agent_env["RADEGAST_AGENT_AGENT_AUTOUPDATE_INITIAL_DELAY"] = "4"
        agent_env["RADEGAST_AGENT_AUTOUPDATE_MIN_AGE_SECONDS"] = "0"
        agent_env["PATH"] = f"{tool_bin_dir}{os.pathsep}{agent_env.get('PATH', '')}"

        tool_python = (
            tool_dir
            / "radegast-edr-agent"
            / ("Scripts" if sys.platform.startswith("win32") else "bin")
            / ("python.exe" if sys.platform.startswith("win32") else "python3")
        )
        # On Windows, running radegast-edr-agent.exe locks the executable file.
        # Launching via tool venv's python interpreter prevents file locking on radegast-edr-agent.exe
        # so uv tool upgrade can overwrite radegast-edr-agent.exe on disk.
        agent_cmd = (
            [str(tool_python), "-m", "radegast_edr_agent.cli"] if sys.platform.startswith("win32") else [str(agent_bin)]
        )

        agent_log = temp_path / "agent.log"
        agent_log_f = open(agent_log, "w", encoding="utf-8")
        agent_process = subprocess.Popen(
            agent_cmd,
            env=agent_env,
            stdout=agent_log_f,
            stderr=subprocess.STDOUT,
        )

        # Wait for rules to be deployed by the agent
        print("Waiting for rules to be synced...")
        rules_file = agent_rules_dir / "sigma" / "test-pack" / "test_rule.yml"
        rules_synced = False
        for _ in range(15):
            if rules_file.exists():
                print("Rules synced successfully!")
                rules_synced = True
                break
            time.sleep(1)

        if not rules_synced:
            raise RuntimeError("Agent failed to check in and synchronize rules.")

        # Simulate alert log
        print("Simulating alert log writing...")

        current_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        alert_data = {
            "@timestamp": current_time,
            "rule.id": f"sigma::{rule_id}",
            "severity": "low",
            "message": "Simulated test alert",
        }
        alerts_file = agent_alerts_dir / "alerts.json"
        with open(alerts_file, "a") as f:
            f.write(json.dumps(alert_data) + "\n")

        # Verify the alert is received by backend
        print("Waiting for backend to receive the alert...")
        alert_received = False
        with httpx.Client(base_url="http://127.0.0.1:8081/api/v1") as client:
            client.post("/auth/login", json={"email": email, "password": password})
            for _ in range(15):
                resp = client.get("/logs/?min_level=low")
                if resp.status_code == 200:
                    logs = resp.json()
                    for log in logs:
                        if log.get("rule_id") == rule_id and log.get("device_id") == device_id:
                            print("SUCCESS: Alert successfully received at backend!")
                            alert_received = True
                            break
                if alert_received:
                    break
                time.sleep(1)

        if not alert_received:
            raise RuntimeError("Alert was not received by the backend.")

        # Verify agent auto-update on disk
        print("Waiting for agent to auto-update binary on disk...")
        upgraded_on_disk = False
        for _ in range(60):
            res = subprocess.run([str(agent_bin), "-V"], capture_output=True, text=True, check=False)
            if res.returncode == 0 and "0.9.0" in res.stdout:
                print(f"Agent binary updated on disk to: {res.stdout.strip()}")
                upgraded_on_disk = True
                break
            time.sleep(1)
        assert upgraded_on_disk, "Agent binary on disk was not updated to 0.9.0"

        # Verify upgraded agent communicates with backend and updates device agent_version
        print("Stopping initial agent process...")
        stop_process(agent_process, "agent", log_file=agent_log)
        agent_process = None

        print("Starting upgraded 0.9.0 agent binary...")
        agent_env["RADEGAST_AGENT_AUTOUPDATE"] = "false"
        agent_process = subprocess.Popen(
            [str(agent_bin)],
            env=agent_env,
            stdout=agent_log_f,
            stderr=subprocess.STDOUT,
        )

        print("Verifying upgraded agent reports version 0.9.0 to backend...")
        upgraded_in_backend = False
        dev_data = {}
        with httpx.Client(base_url="http://127.0.0.1:8081/api/v1") as client:
            client.post("/auth/login", json={"email": email, "password": password})
            for _ in range(30):
                dev_resp = client.get(f"/devices/{device_id}")
                if dev_resp.status_code == 200:
                    dev_data = dev_resp.json()
                    if "0.9.0" in dev_data.get("agent_version", ""):
                        print(f"Backend device details confirmed updated: {dev_data}")
                        upgraded_in_backend = True
                        break
                time.sleep(1)
        assert upgraded_in_backend, f"Backend did not record updated agent version 0.9.0: {dev_data}"

    finally:
        # Cleanup
        stop_process(agent_process, "agent", log_file=agent_log)
        stop_process(server_process, "backend", log_file=backend_log)
        try:
            agent_log_f.close()
        except Exception:
            pass
        try:
            backend_log_f.close()
        except Exception:
            pass
        temp_dir.cleanup()

    print("Agent integration test completed successfully!")


if __name__ == "__main__":
    test_agent_integration()
