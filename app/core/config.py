from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel


class Settings(BaseModel):
    app_name: str = "headershield"
    debug: bool = False
    database_url: str = "sqlite:///data/headershield.db"
    rate_limit_per_minute: int = 30
    request_timeout_seconds: int = 10
    retries: int = 3

    @classmethod
    def load(cls) -> Settings:
        db_path = os.getenv("HS_DB_PATH")
        if db_path:
            # normalise le chemin Windows -> style URI sqlite et crée le dossier
            p = Path(db_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            database_url = f"sqlite:///{p.as_posix()}"
        else:
            # fallback par défaut: ./data/headershield.db
            default_rel = Path("data") / "headershield.db"
            default_rel.parent.mkdir(parents=True, exist_ok=True)
            database_url = f"sqlite:///{default_rel.as_posix()}"
        return cls(
            debug=os.getenv("HS_DEBUG", "0") == "1",
            database_url=database_url,
        )


settings = Settings.load()
