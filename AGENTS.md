# Radegast Agent (AGENTS.md)

Welcome, AI Agent! This file describes the project's architecture, conventions, environment, commands, and boundaries to help you build and maintain this codebase effectively.

## Project Overview
The **Radegast Agent** is a Python wrapper for the `rustinel` EDR (Endpoint Detection and Response) binary.
Its primary responsibilities are:
1. Synchronizing detection packs from a backend API.
2. Extracting Sigma, Yara, and IoC rules/signatures to local directories under `rules/`.
3. Tailing the `alerts.json` file in NDJSON format, encrypting alerts, signing them with the device key, and uploading them to the backend API.
4. Managing the lifecycle of the `rustinel` subprocess (auto-starting and monitoring/restarting it).

## Tech Stack
- **Language:** Python 3.11+
- **Project/Dependency Management:** `uv` (standard package manager for this repo), `pyproject.toml`
- **Build Backend:** Hatchling
- **Key Libraries:** `pydantic-core`, `pydantic-settings`, `cryptography`, `pynacl`, `pytest`, `respx`

## Project workflow

- After finishing implementation of a feature, run all tests to see that everything works as expected
- After implementing a new feature, be sure to add tests

## Environment & Commands
Always use the `uv` toolchain to run commands in this project:

- **Run tests:**
  ```bash
  uv run pytest
  ```
- **Run the agent CLI:**
  ```bash
  uv run python -m agent.cli
  ```

## Architecture and Structure

- [`agent/`](file:///home/adam/Projekty/radegast/radegast-agent-python/agent/) - Python package containing the agent implementation.
  - [`cli.py`](file:///home/adam/Projekty/radegast/radegast-agent-python/agent/cli.py) - Main CLI entry point. Initializes directories, backend clients, signing keys, starts the pack syncer, tails alerts, and manages subprocess lifecycles.
  - [`config.py`](file:///home/adam/Projekty/radegast/radegast-agent-python/agent/config.py) - Pydantic settings. Environment variables prefixed with `RADEGAST_AGENT_`.
  - [`client.py`](file:///home/adam/Projekty/radegast/radegast-agent-python/agent/client.py) - Handles authentication (login), pack downloads, encryption keys fetching, and log submission.
  - [`packs.py`](file:///home/adam/Projekty/radegast/radegast-agent-python/agent/packs.py) - Pulls zip packs from the backend, extracts rules, updates the IoC registry, and ensures required placeholder rules are present.
  - [`process.py`](file:///home/adam/Projekty/radegast/radegast-agent-python/agent/process.py) - Spawns and manages the `rustinel` EDR process.
  - [`crypto.py`](file:///home/adam/Projekty/radegast/radegast-agent-python/agent/crypto.py) - Cryptographic signing (Ed25519) and envelope encryption for alerts.
  - [`tailer.py`](file:///home/adam/Projekty/radegast/radegast-agent-python/agent/tailer.py) - Monitors, encrypts, signs, and uploads new alerts from the EDR log file.
- `rules/` - Rules directory created at runtime.
  - `sigma/` - Contains Sigma rules (extracted into namespaces per pack name).
  - `yara/` - Contains Yara rules (extracted into namespaces per pack name).
  - `ioc/` - Contains merged IoC file lists (e.g., IPs, domains, hashes, and regex paths).
- [`tests/`](file:///home/adam/Projekty/radegast/radegast-agent-python/tests/) - Tests for CLI, cryptography, packs/extraction, tailer, etc.


### Code Style
- Keep existing documentation, comments, and docstrings intact unless explicitly requested to modify them.
- Preserve relative imports (`from agent.xxx import yyy`) and Python 3.11+ type hinting conventions.
