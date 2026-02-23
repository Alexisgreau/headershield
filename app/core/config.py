from __future__ import annotations

from pathlib import Path
import secrets

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="HS_", env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    app_name: str = "headershield"
    debug: bool = False

    # The secret key is critical for session security.
    # It defaults to a new random value on each start,
    # but for production, it should be set to a stable value in the environment.
    secret_key: str = Field(default_factory=lambda: secrets.token_hex(32))

    # This field will be populated by the HS_DB_PATH env var
    db_path: Path | None = None
    database_url: str = ""

    rate_limit_per_minute: int = 30
    request_timeout_seconds: int = 10
    retries: int = 3

    @field_validator("database_url", mode="before")
    @classmethod
    def assemble_db_connection(cls, v: str | None, values) -> str:
        if isinstance(v, str) and v:
            return v

        db_path = values.data.get("db_path")
        if db_path:
            path = Path(db_path)
        else:
            path = Path("data") / "headershield.db"

        path.parent.mkdir(parents=True, exist_ok=True)
        return f"sqlite:///{path.as_posix()}"


settings = Settings()
