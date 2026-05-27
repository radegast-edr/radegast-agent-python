from pathlib import Path

from pydantic_settings import BaseSettings


class AgentSettings(BaseSettings):
    model_config = {"env_prefix": "RADEGAST_AGENT_"}

    backend_url: str = "http://localhost:8000"
    device_token: str = ""

    rustinel_binary: str = "./rustinel"
    rules_dir: Path = Path("./rules")
    alerts_dir: Path = Path("./logs")
    alerts_filename: str = "alerts.json"
    start_radegast: bool = False

    sync_interval: int = 300  # seconds between pack sync checks
    signing_key_path: Path = Path("./device_key")
    state_dir: Path = Path("./.radegast-agent")


settings = AgentSettings()
