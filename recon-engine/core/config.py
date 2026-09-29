"""
core/config.py — Loads settings.yaml into a typed Pydantic settings object.
"""

from pathlib import Path
from typing import List, Optional

import yaml
from pydantic import BaseModel


# ---------------------------------------------------------------------------
# Settings models
# ---------------------------------------------------------------------------

class DatabaseSettings(BaseModel):
    path: str = "data/recon.db"


class ToolSettings(BaseModel):
    subfinder: str = "subfinder"
    dnsx: str = "dnsx"
    httpx: str = "httpx"
    katana: str = "katana"
    gau: str = "gau"
    nuclei: str = "nuclei"
    resolvers: str = "config/resolvers.txt"


class ScanSettings(BaseModel):
    subfinder_threads: int = 100
    dnsx_threads: int = 100
    httpx_threads: int = 50
    katana_depth: int = 3
    katana_js_crawl: bool = True
    nuclei_tags: List[str] = ["exposed-panels", "misconfigurations", "default-logins", "takeovers"]
    phase_timeout: int = 900


class WebhookConfig(BaseModel):
    enabled: bool = False
    webhook_url: Optional[str] = None
    min_severity: str = "medium"


class TelegramConfig(BaseModel):
    enabled: bool = False
    bot_token: Optional[str] = None
    chat_id: Optional[str] = None
    min_severity: str = "critical"


class AlertSettings(BaseModel):
    discord: WebhookConfig = WebhookConfig()
    slack: WebhookConfig = WebhookConfig()
    telegram: TelegramConfig = TelegramConfig()


class AuthSettings(BaseModel):
    enabled: bool = False
    username: str = "admin"
    password: Optional[str] = None  # Must be set explicitly when auth.enabled=true

    def model_post_init(self, __context) -> None:
        if self.enabled and not self.password:
            raise ValueError(
                "dashboard.auth.password must be set in config/settings.yaml "
                "when dashboard.auth.enabled is true. "
                "Example: password: 'your-secure-password-here'"
            )


class DashboardSettings(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8080
    auth: AuthSettings = AuthSettings()


class AppSettings(BaseModel):
    database: DatabaseSettings = DatabaseSettings()
    tools: ToolSettings = ToolSettings()
    scan: ScanSettings = ScanSettings()
    alerts: AlertSettings = AlertSettings()
    dashboard: DashboardSettings = DashboardSettings()


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def load_settings(path: str = "config/settings.yaml") -> AppSettings:
    cfg_path = Path(path)
    if not cfg_path.exists():
        return AppSettings()
    with open(cfg_path) as f:
        raw = yaml.safe_load(f) or {}
    return AppSettings(**raw)


settings: AppSettings = load_settings()
