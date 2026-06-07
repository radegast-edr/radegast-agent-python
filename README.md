# Radegast Agent

Agent wrapper for the `rustinel` EDR binary. This project syncs detection packs from a backend, extracts rules into the local `rules/` tree, and forwards encrypted alert lines from `logs/` to the backend.

## Features

- Syncs detection packs via backend API
- Extracts `sigma`, `yara`, and merged `ioc` rules
- Tracks IOC ownership across packs so removed pack IOC files are cleaned up safely
- Tails `alerts.json` logs and forwards encrypted alerts to the backend
- Optional local `rustinel` process startup controlled by configuration

## Requirements

- Python 3.11+
- `hatchling` build backend for packaging

## Installation

You can also install this project as a UV tool directly from GitHub:

```bash
uv tool install git+https://github.com/radegast-edr/radegast-agent-python

radegast-edr-agent --version
```

## Configuration

The agent uses environment variables prefixed with `RADEGAST_AGENT_`.

| Variable                               | Default                                                     | Description                                                                        |
|----------------------------------------|-------------------------------------------------------------|------------------------------------------------------------------------------------|
| `RADEGAST_AGENT_BACKEND_URL`           | `http://localhost:8000/api/v1`                              | Backend API URL, including the default `/api/v1` path                              |
| `RADEGAST_AGENT_DEVICE_TOKEN`          | ``                                                          | Device token for authenticating to the backend                                     |
| `RADEGAST_AGENT_RUSTINEL_BINARY`       | `./rustinel`                                                | Local path to the `rustinel` binary                                                |
| `RADEGAST_AGENT_RULES_DIR`             | `./rules`                                                   | Base directory for extracted rules                                                 |
| `RADEGAST_AGENT_ALERTS_DIR`            | `./logs`                                                    | Directory containing alert files                                                   |
| `RADEGAST_AGENT_ALERTS_FILENAME`       | `alerts.json`                                               | Alert file base name                                                               |
| `RADEGAST_AGENT_START_RUSTINEL`        | `false`                                                     | If `true`, start the local `rustinel` process; otherwise only tail alerts          |
| `RADEGAST_AGENT_LOG_SEVERITY`          | `true`                                                      | If `true`, parse the of the alert and send it unencrypted in the request           |
| `RADEGAST_AGENT_SYNC_INTERVAL`         | `300`                                                       | Seconds between pack sync checks                                                   |
| `RADEGAST_AGENT_AGENT_AUTOUPDATE_TIME` | `90000`                                                     | Seconds between agent autoupdate checks, set to 0 to disable update check          |
| `RADEGAST_AGENT_SIGNING_KEY_PATH`      | `${RADEGAST_AGENT_STATE_DIR:-./.radegast-agent}/device_key` | Path to the device signing keypair                                                 |
| `RADEGAST_AGENT_STATE_DIR`             | `./.radegast-agent`                                         | Local state directory for manifests, offsets, and the default signing key location |

### Notes

- When `RADEGAST_AGENT_START_RUSTINEL=false`, the agent does not launch the local `rustinel` process and only monitors the configured `alerts_dir`.
- If `RADEGAST_AGENT_SIGNING_KEY_PATH` is unset, it defaults to `${RADEGAST_AGENT_STATE_DIR:-./.radegast-agent}/device_key`.
- IOC files are merged into `rules/ioc/` and an ownership registry is kept in `rules/ioc/ioc_packs.json`.

## Usage

Run the agent via the console script:

```bash
radegast-edr-agent
```

Print the installed version:

```bash
radegast-edr-agent --version
```

Or with Python directly:

```bash
python -m radegast_edr_agent.cli
```

## Project layout

- `radegast_edr_agent/` — application package
  - `cli.py` — main entry point
  - `config.py` — environment-backed config schema
  - `client.py` — backend API client
  - `packs.py` — pack synchronization and extraction
  - `process.py` — subprocess management for `rustinel`
  - `tailer.py` — alert file tailing and forwarding
  - `version.py` — version reporting and detection utilities
  - `autoupdate.py` — agent autoupdate functionality
- `tests/` — unit tests
- `pyproject.toml` — package metadata and build config

## Testing

Run the test suite with:

```bash
.venv/bin/python -m pytest
```

## License

This project does not include a license file by default. Add a `LICENSE` file if you want to define reuse terms.
