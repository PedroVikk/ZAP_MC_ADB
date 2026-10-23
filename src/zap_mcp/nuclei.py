"""Roda o Nuclei (ProjectDiscovery) contra alvos autorizados e junta os achados.

Complementa o ZAP: o Nuclei casa assinaturas conhecidas (CVEs, configuracoes
erradas, arquivos expostos, templates de SAP), com pouquissimo falso positivo. O
ZAP fuzza e acha falhas de logica; o Nuclei confere o que ja e conhecido.

So monta a linha de comando e le a saida JSONL — os guard-rails (allowlist)
ficam no server. O binario e externo (NUCLEI_PATH); se faltar, devolve erro
claro em vez de quebrar.
"""
from __future__ import annotations

import json
import subprocess
import threading
import time

SEVERITIES = ["critical", "high", "medium", "low", "info", "unknown"]


class NucleiUnavailable(Exception):
    """Binario do Nuclei nao encontrado ou nao executavel."""


def check(path: str) -> str:
    """Confere que o Nuclei roda e devolve a versao. Levanta se faltar."""
    try:
        proc = subprocess.run(  # noqa: S603 - path do .env, args fixos
            [path, "-version"], capture_output=True, text=True, timeout=15,
        )
    except FileNotFoundError as exc:
        raise NucleiUnavailable(
            f"'{path}' nao encontrado. Instale o Nuclei ou defina NUCLEI_PATH."
        ) from exc
    except Exception as exc:  # noqa: BLE001
        raise NucleiUnavailable(f"falha ao rodar o Nuclei: {exc}") from exc
    out = (proc.stderr or "") + (proc.stdout or "")
    for line in out.splitlines():
        if "Version" in line:
            return line.split("Version:")[-1].strip() or line.strip()
    return out.strip()[:80] or "desconhecida"


def _build_cmd(path, targets, severity, tags, templates, proxy, rate_limit):
    cmd = [path, "-jsonl", "-silent", "-no-color", "-disable-update-check",
           "-rate-limit", str(rate_limit)]
    for t in targets:
        cmd += ["-u", t]
    if severity:
        cmd += ["-severity", severity]
    if tags:
        cmd += ["-tags", tags]
    if templates:
        cmd += ["-t", templates]
    if proxy:
        cmd += ["-proxy", proxy]
    return cmd


def parse_line(line: str) -> dict | None:
    """Uma linha JSONL do Nuclei -> achado enxuto (ou None se nao der)."""
    line = line.strip()
    if not line or not line.startswith("{"):
        return None
    try:
        obj = json.loads(line)
    except ValueError:
        return None
    info = obj.get("info", {}) or {}
    return {
        "id": obj.get("template-id") or obj.get("templateID", ""),
        "name": info.get("name", ""),
        "severity": (info.get("severity") or "unknown").lower(),
        "host": obj.get("host", ""),
        "matched_at": obj.get("matched-at") or obj.get("host", ""),
        "type": obj.get("type", ""),
        "tags": info.get("tags", []),
    }


def summarize(findings: list[dict]) -> dict:
    """Agrupa por severidade (contagem) na ordem critical -> info."""
    by_sev = {s: 0 for s in SEVERITIES}
    for f in findings:
        by_sev[f["severity"] if f["severity"] in by_sev else "unknown"] += 1
    order = {s: i for i, s in enumerate(SEVERITIES)}
    ordered = sorted(findings, key=lambda f: order.get(f["severity"], 99))
    return {"total": len(findings), "by_severity": by_sev, "findings": ordered}


class NucleiRun:
    """Execucao em andamento: le a saida JSONL em uma thread, para o front
    acompanhar os achados chegando. Usada pelo painel web."""

    def __init__(self, targets: list[str], params: dict) -> None:
        self.targets = targets
        self.params = params
        self.findings: list[dict] = []
        self.log: list[str] = []
        self.lock = threading.Lock()
        self.proc: subprocess.Popen | None = None
        self.started_at = time.time()
        self.finished_at: float | None = None
        self.error: str | None = None

    def start(self, path, severity, tags, templates, proxy, rate_limit, cap_seconds) -> None:
        cmd = _build_cmd(path, self.targets, severity, tags, templates, proxy, rate_limit)
        try:
            self.proc = subprocess.Popen(  # noqa: S603 - path do .env, args controlados
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
        except FileNotFoundError:
            self.error = f"'{path}' nao encontrado. Instale o Nuclei ou defina NUCLEI_PATH."
            self.finished_at = time.time()
            return
        threading.Thread(target=self._pump, args=(cap_seconds,), daemon=True).start()

    def _pump(self, cap_seconds: float) -> None:
        proc = self.proc
        assert proc is not None
        deadline = time.time() + cap_seconds
        try:
            for line in proc.stdout:  # type: ignore[union-attr]
                f = parse_line(line)
                if f:
                    with self.lock:
                        self.findings.append(f)
                        self.log.append(f"[{f['severity']}] {f['id']} — {f['matched_at']}")
                if time.time() > deadline:
                    proc.terminate()
                    with self.lock:
                        self.log.append("Parado pelo limite de tempo.")
                    break
            proc.wait(timeout=10)
        except Exception as exc:  # noqa: BLE001
            with self.lock:
                self.error = f"{type(exc).__name__}: {exc}"
        finally:
            self.finished_at = time.time()

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()

    def snapshot(self) -> dict:
        with self.lock:
            return {
                "running": self.finished_at is None,
                "targets": self.targets,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "error": self.error,
                "log": self.log[-120:],
                **summarize(list(self.findings)),
            }


def run_blocking(
    path: str,
    targets: list[str],
    severity: str = "",
    tags: str = "",
    templates: str = "",
    proxy: str = "",
    rate_limit: int = 150,
    cap_seconds: float = 300.0,
) -> dict:
    """Roda o Nuclei ate o fim (ou o cap) e devolve o resumo. Para o MCP."""
    check(path)  # erro claro antes de comecar
    cmd = _build_cmd(path, targets, severity, tags, templates, proxy, rate_limit)
    try:
        proc = subprocess.run(  # noqa: S603 - path do .env, args controlados
            cmd, capture_output=True, text=True, timeout=cap_seconds,
        )
        stdout = proc.stdout
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        timed_out = True
    findings = [f for line in stdout.splitlines() if (f := parse_line(line))]
    summary = summarize(findings)
    summary["targets"] = targets
    summary["timed_out"] = timed_out
    return summary
