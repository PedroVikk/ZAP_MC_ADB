"""Configuracao lida do ambiente (/.env). Nenhum segredo fica no codigo."""
from __future__ import annotations

import os
from dataclasses import dataclass

try:  # .env e opcional; variavel de ambiente sempre vence.
    from dotenv import load_dotenv

    load_dotenv()
except Exception:  # pragma: no cover - dotenv ausente nao e fatal
    pass


def _split(value: str | None) -> list[str]:
    if not value:
        return []
    return [p.strip() for p in value.replace(";", ",").split(",") if p.strip()]


@dataclass(frozen=True)
class Config:
    base_url: str
    api_key: str
    allowed_targets: tuple[str, ...]
    max_scan_seconds: int
    report_dir: str
    adb_path: str
    nuclei_path: str

    @staticmethod
    def from_env() -> "Config":
        return Config(
            base_url=os.environ.get("ZAP_BASE_URL", "http://localhost:8080").rstrip("/"),
            api_key=os.environ.get("ZAP_API_KEY", ""),
            allowed_targets=tuple(_split(os.environ.get("ZAP_ALLOWED_TARGETS"))),
            max_scan_seconds=int(os.environ.get("ZAP_MAX_SCAN_SECONDS", "900")),
            report_dir=os.environ.get("ZAP_REPORT_DIR", "reports"),
            adb_path=os.environ.get("ADB_PATH", "adb"),
            nuclei_path=os.environ.get("NUCLEI_PATH", "nuclei"),
        )
