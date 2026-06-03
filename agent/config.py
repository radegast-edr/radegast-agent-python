from pathlib import Path
from typing import Any

from pydantic_settings import BaseSettings


class AgentSettings(BaseSettings):
    model_config = {"env_prefix": "RADEGAST_AGENT_"}

    backend_url: str = "http://localhost:8000/api/v1"
    device_token: str = ""

    rustinel_binary: str = "./rustinel"
    rules_dir: Path = Path("./rules")
    alerts_dir: Path = Path("./logs")
    alerts_filename: str = "alerts.json"
    start_rustinel: bool = False
    log_severity: bool = True

    sync_interval: int = 300  # seconds between pack sync checks
    signing_key_path: Path | None = None
    state_dir: Path = Path("./.radegast-agent")

    def model_post_init(self, __context: Any) -> None:
        if self.signing_key_path is None:
            self.signing_key_path = self.state_dir / "device_key"


settings = AgentSettings()
