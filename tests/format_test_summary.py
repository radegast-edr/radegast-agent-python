#!/usr/bin/env python3
"""Format integration test diagnostics into GitHub Step Summary Markdown."""

from __future__ import annotations

import argparse
import json
import os
import sys
import zipfile
from pathlib import Path


def append_collapsible_log(sf, title: str, log_file: Path, max_lines: int = 0):
    if not log_file.is_file():
        return
    try:
        content = log_file.read_text(encoding="utf-8", errors="replace")
        if not content.strip():
            return
        lines = content.splitlines()
        if max_lines > 0 and len(lines) > max_lines:
            lines = lines[-max_lines:]
            content = f"... (showing last {max_lines} lines)\n" + "\n".join(lines)

        sf.write(f"<details>\n<summary>{title}</summary>\n\n```\n{content}\n```\n</details>\n\n")
    except OSError as e:
        sf.write(f"*Failed to read {log_file.name}: {e}*\n\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate GitHub Step Summary for integration tests")
    parser.add_argument("--output-dir", help="Directory containing test output files")
    parser.add_argument("--exit-code", type=int, default=0, help="Test exit code")
    parser.add_argument(
        "--summary-file",
        default="",
        help="Path to step summary file (defaults to GITHUB_STEP_SUMMARY)",
    )
    parser.add_argument("--zip", nargs=2, metavar=("ZIP_OUT", "BIN_IN"), help="Helper: create single-binary zip")

    args = parser.parse_args()

    if args.zip:
        zip_out, bin_in = args.zip
        with zipfile.ZipFile(zip_out, "w", zipfile.ZIP_DEFLATED) as z:
            arcname = "rustinel.exe" if bin_in.endswith(".exe") else "rustinel"
            z.write(bin_in, arcname=arcname)
        return 0

    if not args.output_dir:
        parser.error("--output-dir is required when not using --zip")

    summary_file = args.summary_file or os.environ.get("GITHUB_STEP_SUMMARY", "")
    if not summary_file:
        return 0

    out_dir = Path(args.output_dir)
    result_file = out_dir / "test_result.json"

    version_label = "N/A"
    os_name = "linux"
    arch = "amd64"
    exit_code = args.exit_code

    if result_file.is_file():
        try:
            with open(result_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            version_label = data.get("detected_version", "N/A")
            os_name = data.get("os", "linux")
            arch = data.get("arch", "amd64")
            if data.get("status") == "FAIL" and exit_code == 0:
                exit_code = 1
        except (OSError, json.JSONDecodeError):
            pass

    platform_label = f"{os_name}/{arch}"

    service_desc = (
        "Systemd Services (`rustinel` & `radegast-agent`)"
        if os_name == "linux"
        else (
            "Launchd Daemons (`io.rustinel.daemon` & `app.radegast.agent`)"
            if os_name == "mac"
            else "Windows Services (`RadegastRustinel` & `RadegastAgent`)"
        )
    )

    with open(summary_file, "a", encoding="utf-8") as sf:
        sf.write(f"\n### 🧪 Real-Device Agent Integration Test ({platform_label})\n\n")
        if exit_code == 0:
            sf.write(
                f"✅ **PASSED** — Built agent package verified on `{platform_label}` "
                "via authentic backend installation & alert pipeline.\n\n"
            )
        else:
            sf.write(
                f"❌ **FAILED** — Integration test did not pass on `{platform_label}` (exit code: `{exit_code}`).\n\n"
            )

        sf.write("| Property | Value |\n")
        sf.write("|---|---|\n")
        sf.write(f"| **Evaluated Rustinel Version** | `{version_label}` |\n")
        sf.write(f"| **Target OS / Architecture** | `{platform_label}` |\n")
        sf.write("| **Agent Source Build** | Wheel built from local commit & deployed |\n")
        sf.write(f"| **Official Installer** | Executed (`GET /api/v1/device/install?os={os_name}`) |\n")
        sf.write(f"| **Background Services** | {service_desc} active |\n")
        sf.write("| **Alert Pipeline** | Native agent healthcheck probe verified |\n\n")

        append_collapsible_log(sf, f"📋 View Test Runner Log ({platform_label})", out_dir / "runner.log")

        # Radegast Agent logs
        for agent_candidate in (
            "radegast-agent.service.log",
            "radegast-agent-stdout.log",
            "radegast-agent-stderr.log",
            "radegast-agent.out.log",
            "radegast-agent.err.log",
        ):
            append_collapsible_log(sf, f"⚠️ View Radegast Agent Log ({agent_candidate})", out_dir / agent_candidate)

        # Rustinel logs
        for rustinel_candidate in (
            "rustinel.service.log",
            "rustinel-stdout.log",
            "rustinel-stderr.log",
            "rustinel.out.log",
            "rustinel.err.log",
        ):
            append_collapsible_log(sf, f"⚠️ View Rustinel Log ({rustinel_candidate})", out_dir / rustinel_candidate)

        # Backend server log
        append_collapsible_log(
            sf,
            f"⚠️ View Backend Server Log ({platform_label})",
            out_dir / "backend.log",
            max_lines=100,
        )

        # Filesystem permissions
        append_collapsible_log(sf, "🔍 Filesystem Permissions & Layout", out_dir / "filesystem_permissions.txt")

    return 0


if __name__ == "__main__":
    sys.exit(main())
