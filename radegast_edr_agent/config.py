from pathlib import Path
from typing import Any

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings


class AgentSettings(BaseSettings):
    model_config = {"env_prefix": "RADEGAST_AGENT_"}

    backend_url: str = "http://localhost:8000/api/v1"
    device_token: str = ""

    rustinel_binary: str = "./rustinel"
    rules_dir: Path = Path("./rules")
    alerts_dir: Path = Path("./logs")
    alerts_filename: str = "alerts.json"
    send_severity: bool = True
    send_rule_id: bool = True
    send_excluded_by: bool = True

    max_log_size_mb: int = 10
    max_log_age_days: int = 720

    sync_interval: int = 300  # seconds between pack sync checks
    agent_autoupdate: bool = Field(
        True,
        validation_alias=AliasChoices(
            "agent_autoupdate",
            "autoupdate",
            "radegast_agent_agent_autoupdate",
            "radegast_agent_autoupdate",
        ),
    )
    agent_autoupdate_initial_delay: int = Field(
        300,
        validation_alias=AliasChoices(
            "agent_autoupdate_initial_delay",
            "autoupdate_initial_delay",
            "radegast_agent_agent_autoupdate_initial_delay",
            "radegast_agent_autoupdate_initial_delay",
        ),
    )
    agent_autoupdate_interval: int = Field(
        86400,
        validation_alias=AliasChoices(
            "agent_autoupdate_interval",
            "autoupdate_interval",
            "radegast_agent_agent_autoupdate_interval",
            "radegast_agent_autoupdate_interval",
        ),
    )
    agent_autoupdate_delay_hours: int = Field(
        96,
        validation_alias=AliasChoices(
            "agent_autoupdate_delay_hours",
            "autoupdate_delay_hours",
            "radegast_agent_agent_autoupdate_delay_hours",
            "radegast_agent_autoupdate_delay_hours",
        ),
    )
    init_wait_seconds: int = 90  # seconds to wait for backend to re-encrypt exclusions on new key registration
    signing_key_path: Path | None = None
    encryption_key_path: Path | None = None
    state_dir: Path = Path("./.radegast-agent")
    rustinel_config: Path = Path("config.toml")

    healthcheck: bool = True
    healthcheck_interval: int = 60  # seconds between healthcheck runs
    healthcheck_timeout: float = 30.0  # seconds to wait for rustinel alert
    healthcheck_rule_dir: Path | None = None

    def model_post_init(self, __context: Any) -> None:
        if self.signing_key_path is None:
            self.signing_key_path = self.state_dir / "device_key"
        if self.encryption_key_path is None:
            self.encryption_key_path = self.state_dir / "device_enc_key"
        if self.healthcheck_rule_dir is None:
            self.healthcheck_rule_dir = self.rules_dir / "sigma" / "_healthcheck"

    @property
    def autoupdate_delay_hours(self) -> int:
        return self.agent_autoupdate_delay_hours

    @autoupdate_delay_hours.setter
    def autoupdate_delay_hours(self, value: int) -> None:
        self.agent_autoupdate_delay_hours = value

    @property
    def autoupdate(self) -> bool:
        return self.agent_autoupdate

    @autoupdate.setter
    def autoupdate(self, value: bool) -> None:
        self.agent_autoupdate = value


settings = AgentSettings()
