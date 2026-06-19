import os
import subprocess
import sys
import time
import tempfile
import sqlite3
import json
from pathlib import Path
import httpx


def run_command(cmd, cwd=None, env=None):
    print(f"Running command: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    res = subprocess.run(
        cmd, cwd=cwd, capture_output=True, text=True, env=env, check=False
    )
    print("STDOUT:")
    print(res.stdout)
    print("STDERR:")
    print(res.stderr)
    if res.returncode != 0:
        raise RuntimeError(f"Command failed with code {res.returncode}")
    return res


def stop_process(proc, name):
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
        try:
            stdout, stderr = proc.communicate(timeout=5)
        except Exception:
            stdout, stderr = "", ""
    else:
        proc.terminate()
        try:
            stdout, stderr = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()

    print(f"{name} stdout:\n{stdout}\n{name} stderr:\n{stderr}")


def test_agent_integration():
    test_dir = Path(__file__).parent.resolve()
    agent_root = test_dir.parent

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
        # Clone console backend
        print("Cloning console backend...")
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
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
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
            raise RuntimeError(
                "Backend server failed to start or respond to health check."
            )

        # Register user via API
        print("Registering user...")
        email = "agent-integration@example.com"
        password = "IntegrationPass123!"
        with httpx.Client(
            base_url="http://127.0.0.1:8081/api/v1", follow_redirects=True
        ) as client:
            resp = client.post(
                "/auth/register", json={"email": email, "password": password}
            )
            if resp.status_code != 200:
                raise RuntimeError(f"Registration failed: {resp.text}")

        # Promote and verify user via SQLite direct query
        print("Promoting and verifying user directly in SQLite...")
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET verified = 1, role = 'admin' WHERE email = ?;", (email,)
        )
        conn.commit()
        conn.close()

        # Generate valid AGE keys using ssage
        from ssage import SSAGE

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

        with httpx.Client(
            base_url="http://127.0.0.1:8081/api/v1", follow_redirects=True
        ) as client:
            # Login
            resp = client.post(
                "/auth/login", json={"email": email, "password": password}
            )
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
            resp = client.post(
                "/packs/", json={"name": "test-pack", "description": "test rules"}
            )
            pack_id = resp.json()["id"]

            # Create in-memory zip for pack
            import io
            import zipfile

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
            with zipfile.ZipFile(
                zip_buffer, "a", zipfile.ZIP_DEFLATED, False
            ) as zip_file:
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
            resp = client.post(
                "/devices/", json={"name": "agent-test-device", "group_id": group_id}
            )
            device_data = resp.json()
            device_token = device_data["token"]
            device_id = device_data["id"]

        print(f"Registered device with token: {device_token}")

        # Start agent CLI process pointing to our backend
        print("Starting python agent...")
        agent_env = os.environ.copy()
        agent_env["RADEGAST_AGENT_BACKEND_URL"] = "http://127.0.0.1:8081/api/v1"
        agent_env["RADEGAST_AGENT_DEVICE_TOKEN"] = device_token
        agent_env["RADEGAST_AGENT_RULES_DIR"] = str(agent_rules_dir)
        agent_env["RADEGAST_AGENT_ALERTS_DIR"] = str(agent_alerts_dir)
        agent_env["RADEGAST_AGENT_STATE_DIR"] = str(agent_state_dir)
        agent_env["RADEGAST_AGENT_RUSTINEL_BINARY"] = (
            "true"  # Bypass binary path check since we mock
        )

        agent_process = subprocess.Popen(
            ["uv", "run", "python", "-m", "radegast_edr_agent.cli"],
            cwd=agent_root,
            env=agent_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
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
        from datetime import datetime, timezone

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
                        if (
                            log.get("rule_id") == rule_id
                            and log.get("device_id") == device_id
                        ):
                            print("SUCCESS: Alert successfully received at backend!")
                            alert_received = True
                            break
                if alert_received:
                    break
                time.sleep(1)

        if not alert_received:
            raise RuntimeError("Alert was not received by the backend.")

    finally:
        # Cleanup
        stop_process(agent_process, "agent")
        stop_process(server_process, "backend")
        temp_dir.cleanup()

    print("Agent integration test completed successfully!")
