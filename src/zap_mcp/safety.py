"""Protecoes do servidor: lista de alvos autorizados e registro de scans.

Deny by default: sem lista de alvos, nada e permitido. O scan ativo (que envia
ataques reais) ainda exige confirmacao explicita no server, alem da lista.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from urllib.parse import urlparse


class TargetNotAllowed(Exception):
    """Alvo fora da lista ZAP_ALLOWED_TARGETS."""


def host_of(target: str) -> str:
    """Extrai o hostname (minusculo) de uma URL ou de um host cru."""
    raw = target if "://" in target else f"http://{target}"
    return (urlparse(raw).hostname or "").lower()


def normalize_allowlist(entries) -> set[str]:
    hosts: set[str] = set()
    for entry in entries:
        host = host_of(entry)
        if host:
            hosts.add(host)
    return hosts


def is_allowed(target: str, allowlist: set[str]) -> bool:
    if not allowlist:  # deny by default
        return False
    host = host_of(target)
    if not host:
        return False
    for allowed in allowlist:
        if host == allowed or host.endswith("." + allowed):
            return True
    return False


def ensure_allowed(target: str, allowlist: set[str]) -> None:
    if not is_allowed(target, allowlist):
        permitidos = ", ".join(sorted(allowlist)) or "(nenhum)"
        raise TargetNotAllowed(
            f"'{target}' esta fora da lista de alvos autorizados. "
            f"Permitidos: {permitidos}. Edite ZAP_ALLOWED_TARGETS para liberar."
        )


@dataclass
class ScanRecord:
    scan_id: str
    kind: str  # "spider" | "ajax" | "active"
    target: str
    started_at: float = field(default_factory=time.monotonic)


class ScanRegistry:
    """Guarda os scans em andamento para consulta de status e limite de tempo."""

    def __init__(self) -> None:
        self._scans: dict[str, ScanRecord] = {}
        self._ajax_seq = 0

    def add(self, scan_id: str, kind: str, target: str) -> ScanRecord:
        record = ScanRecord(scan_id=scan_id, kind=kind, target=target)
        self._scans[scan_id] = record
        return record

    def next_ajax_id(self) -> str:
        self._ajax_seq += 1
        return f"ajax-{self._ajax_seq}"

    def get(self, scan_id: str) -> ScanRecord | None:
        return self._scans.get(scan_id)

    def all(self) -> list[ScanRecord]:
        return list(self._scans.values())

    def elapsed(self, record: ScanRecord) -> float:
        return time.monotonic() - record.started_at
