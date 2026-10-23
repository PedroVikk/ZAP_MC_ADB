"""API HTTP do painel web (React em web/).

Rode com:  python -m zap_mcp.web   (ou o script zap-mcp-web)

Mesma logica do painel Streamlit, mas o teste roda numa thread e o front
acompanha por polling em /api/run. So um teste por vez; a allowlist editada na
tela vale para os guard-rails do servidor (em memoria, nao grava no .env).
O build do front (web/dist) e servido na raiz quando existir.
"""
from __future__ import annotations

import asyncio
import os
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from zap_mcp import server as S
from zap_mcp.explorer import explore
from zap_mcp.nuclei import NucleiRun, check as nuclei_check
from zap_mcp.reports import _EXT
from zap_mcp.safety import is_allowed, normalize_allowlist

_ROOT = Path(__file__).resolve().parents[2]
_DIST = _ROOT / "web" / "dist"


def origin_of(url: str) -> str:
    parsed = urlparse(url if "://" in url else "http://" + url)
    return f"{parsed.scheme}://{parsed.netloc}"


class Job:
    """Estado de um teste em andamento, lido pelo front a cada ~1.5s."""

    def __init__(self, params: dict) -> None:
        self.id = str(int(time.time() * 1000))
        self.params = params
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.started_at = time.time()
        self.finished_at: float | None = None
        self.phase = "iniciando"  # explorador | spider | ativo | relatorio | concluido | erro
        self.phases: list[str] = []
        self.failed: list[str] = []  # etapas que nao chegaram a rodar
        self.log: list[dict] = []
        self.explore: dict | None = None
        self.spider: dict | None = None
        self.active: dict | None = None
        self.report: dict | None = None
        self.error: str | None = None

    def say(self, msg: str, level: str = "info") -> None:
        with self.lock:
            self.log.append({"t": time.time(), "level": level, "msg": msg})

    def set(self, **kw) -> None:
        with self.lock:
            for k, v in kw.items():
                setattr(self, k, v)

    def snapshot(self) -> dict:
        with self.lock:
            return {
                "id": self.id,
                "params": {k: v for k, v in self.params.items() if k != "login_pass"},
                "phase": self.phase,
                "phases": self.phases,
                "failed": self.failed,
                "running": self.finished_at is None,
                "stop_requested": self.stop.is_set(),
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "log": self.log[-200:],
                "explore": self.explore,
                "spider": self.spider,
                "active": self.active,
                "report": self.report,
                "error": self.error,
            }


_job: Job | None = None
_job_lock = threading.Lock()


def _run(job: Job) -> None:
    p = job.params
    target = p["target"]
    origin = origin_of(target)
    try:
        if p.get("explore"):
            job.set(phase="explorador")
            job.say(f"Explorador abrindo {target} (headless={p.get('headless')})")
            res = asyncio.run(explore(
                target, S._config.base_url, float(p.get("max_seconds", 150)),
                int(p.get("max_actions", 300)), p.get("login_user", ""),
                p.get("login_pass", ""), headless=bool(p.get("headless")),
                route_sweep=bool(p.get("route_sweep", True)),
                should_stop=job.stop.is_set, crud=bool(p.get("crud"))))
            res.pop("endpoints_host", None)  # lista grande; o front le em /api/urls
            job.set(explore=res)
            job.say(f"Explorador: login {res.get('login_status')}, "
                    f"{res.get('routes_found', 0)} rotas, {res.get('actions')} acoes, "
                    f"{res.get('requests_total')} requests",
                    "warn" if res.get("stopped") else "ok")

        if p.get("spider") and not job.stop.is_set():
            job.set(phase="spider")
            started = S.spider_scan(origin)
            sid = started.get("scan_id")
            if sid is None:
                job.failed.append("spider")
                job.say(f"Spider nao iniciou: {started.get('detail') or started}", "error")
            else:
                job.say(f"Spider iniciado em {origin}")
                end = time.time() + 120
                while time.time() < end:
                    if job.stop.is_set():
                        S._client.spider_stop(sid)
                        job.say("Spider parado", "warn")
                        break
                    st = S.scan_status(sid)
                    job.set(spider={"progress": int(st.get("progress", 0)),
                                    "status": st.get("status")})
                    if st.get("status") != "em_andamento":
                        break
                    time.sleep(2)
                job.say("Spider concluido", "ok")

        if p.get("active") and not job.stop.is_set():
            job.set(phase="ativo")
            started = S.active_scan(origin, confirm=True)
            sid = started.get("scan_id")
            if sid is None:
                job.failed.append("ativo")
                job.say(f"Scan ativo nao iniciou: {started.get('detail') or started}", "error")
            else:
                job.say(f"Scan ATIVO iniciado em {origin}", "warn")
                end = time.time() + S._config.max_scan_seconds
                while time.time() < end:
                    if job.stop.is_set():
                        S._client.active_stop(sid)
                        job.say("Scan ativo parado", "warn")
                        break
                    feed = S.active_scan_feed(sid)
                    if "error" in feed:
                        job.failed.append("ativo")
                        job.say(f"Falha ao ler o scan ativo: {feed.get('detail')}", "error")
                        break
                    job.set(active=feed)
                    if feed.get("concluido"):
                        job.say("Scan ativo concluido", "ok")
                        break
                    time.sleep(2)

        job.set(phase="relatorio")
        rep = S.generate_report(p.get("report_format", "html"))
        job.set(report=rep)
        if "path" in rep:
            job.say(f"Relatorio gerado: {Path(rep['path']).name}", "ok")
        else:
            job.failed.append("relatorio")
            job.say(f"Relatorio nao gerado: {rep.get('detail') or rep}", "warn")
        job.set(phase="concluido")
    except Exception as exc:  # noqa: BLE001 - fronteira da thread
        job.set(phase="erro", error=f"{type(exc).__name__}: {exc}")
        job.say(f"Falha: {exc}", "error")
    finally:
        job.set(finished_at=time.time())


# ---------------- rotas ----------------

def _err(status: int, msg: str) -> JSONResponse:
    return JSONResponse({"error": msg}, status_code=status)


async def status(_: Request):
    st = await asyncio.to_thread(S.zap_status)
    st["allowed_targets"] = sorted(S._allowlist)
    st["base_url"] = S._config.base_url
    st["api_key_set"] = bool(S._config.api_key)
    return JSONResponse(st)


async def allowlist(request: Request):
    body = await request.json()
    hosts = body.get("hosts", [])
    S._allowlist = normalize_allowlist(h for h in hosts if str(h).strip())
    return JSONResponse({"allowed_targets": sorted(S._allowlist)})


async def run_start(request: Request):
    global _job
    p = await request.json()
    target = (p.get("target") or "").strip()
    if not target:
        return _err(400, "Informe o alvo.")
    if not (p.get("explore") or p.get("spider") or p.get("active")):
        return _err(400, "Marque pelo menos uma acao: explorador, spider ou scan ativo.")
    if not is_allowed(target, S._allowlist):
        return _err(403, f"'{target}' nao esta nos alvos autorizados.")
    if p.get("active") and not p.get("confirm_active"):
        return _err(400, "O scan ativo envia ataques reais: confirme antes de rodar.")
    with _job_lock:
        if _job is not None and _job.finished_at is None:
            return _err(409, "Ja existe um teste rodando.")
        p["target"] = target
        _job = Job(p)
        job = _job
    for name, on in (("explorador", p.get("explore")), ("spider", p.get("spider")),
                     ("ativo", p.get("active"))):
        if on:
            job.phases.append(name)
    job.phases.append("relatorio")
    threading.Thread(target=_run, args=(job,), daemon=True).start()
    return JSONResponse(job.snapshot())


async def run_get(_: Request):
    return JSONResponse(_job.snapshot() if _job else None)


async def run_stop(_: Request):
    if _job is None or _job.finished_at is not None:
        return _err(409, "Nenhum teste rodando.")
    _job.stop.set()
    _job.say("Parada pedida — encerra no proximo passo", "warn")
    return JSONResponse(_job.snapshot())


async def alerts(request: Request):
    min_risk = request.query_params.get("min_risk", "Low")
    data = await asyncio.to_thread(S.get_alerts, min_risk=min_risk)
    return JSONResponse(data)


async def alert_detail(request: Request):
    data = await asyncio.to_thread(S.get_alert_details, request.path_params["alert_id"])
    return JSONResponse(data)


async def urls(_: Request):
    data = await asyncio.to_thread(S.get_urls)
    return JSONResponse(data)


async def reports_list(_: Request):
    folder = Path(S._config.report_dir)
    if not folder.is_absolute():
        folder = _ROOT / folder
    files = []
    if folder.is_dir():
        for f in folder.iterdir():
            if f.is_file() and f.suffix.lstrip(".") in _EXT.values():
                files.append({"name": f.name, "size": f.stat().st_size,
                              "mtime": f.stat().st_mtime})
    files.sort(key=lambda f: f["mtime"], reverse=True)
    return JSONResponse(files)


async def reports_create(request: Request):
    body = await request.json()
    kind = body.get("kind", "zap")
    if kind == "endpoints":
        data = await asyncio.to_thread(S.report_endpoints)
    else:
        data = await asyncio.to_thread(S.generate_report, body.get("format", "html"))
    return JSONResponse(data)


async def odata_discover(request: Request):
    body = await request.json()
    url = (body.get("metadata_url") or "").strip()
    if not url:
        return _err(400, "Informe a URL do $metadata.")
    data = await asyncio.to_thread(S.odata_discover, url)
    return JSONResponse(data)


async def odata_probe(request: Request):
    body = await request.json()
    url = (body.get("metadata_url") or "").strip()
    if not url:
        return _err(400, "Informe a URL do $metadata.")
    data = await asyncio.to_thread(
        S.odata_probe, url, bool(body.get("include_writes")),
        bool(body.get("confirm")), body.get("username", ""), body.get("password", ""),
    )
    return JSONResponse(data)


_nuclei: NucleiRun | None = None
_nuclei_lock = threading.Lock()


async def nuclei_status(_: Request):
    try:
        version = await asyncio.to_thread(nuclei_check, S._config.nuclei_path)
        return JSONResponse({"available": True, "version": version})
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"available": False, "detail": str(exc)})


async def nuclei_start(request: Request):
    global _nuclei
    body = await request.json()
    raw = body.get("targets") or ([body["target"]] if body.get("target") else [])
    targets = [t.strip() for t in raw if str(t).strip()]
    if not targets:
        return _err(400, "Informe ao menos um alvo.")
    blocked = [t for t in targets if not is_allowed(t, S._allowlist)]
    if blocked:
        return _err(403, f"Fora dos alvos autorizados: {', '.join(blocked)}")
    with _nuclei_lock:
        if _nuclei is not None and _nuclei.finished_at is None:
            return _err(409, "Ja existe um scan do Nuclei rodando.")
        _nuclei = NucleiRun(targets, body)
        run = _nuclei
    proxy = S._config.base_url if body.get("through_zap") else ""
    cap = min(int(body.get("max_seconds", 300)), S._config.max_scan_seconds)
    run.start(S._config.nuclei_path, body.get("severity", ""), body.get("tags", ""),
              body.get("templates", ""), proxy, int(body.get("rate_limit", 150)), cap,
              headers=body.get("headers", []))
    return JSONResponse(run.snapshot())


async def nuclei_get(_: Request):
    return JSONResponse(_nuclei.snapshot() if _nuclei else None)


async def nuclei_stop(_: Request):
    if _nuclei is None or _nuclei.finished_at is not None:
        return _err(409, "Nenhum scan do Nuclei rodando.")
    _nuclei.stop()
    return JSONResponse(_nuclei.snapshot())


async def mobile_status(_: Request):
    return JSONResponse(await asyncio.to_thread(S.mobile_status))


async def mobile_guidance(_: Request):
    return JSONResponse(await asyncio.to_thread(S.mobile_guidance))


async def mobile_ca(request: Request):
    body = await request.json()
    return JSONResponse(await asyncio.to_thread(S.mobile_install_ca, body.get("serial", "")))


async def mobile_proxy(request: Request):
    body = await request.json()
    if body.get("enable"):
        data = await asyncio.to_thread(
            S.mobile_set_proxy, body.get("host", ""), int(body.get("port", 8080)),
            body.get("serial", ""),
        )
    else:
        data = await asyncio.to_thread(S.mobile_clear_proxy, body.get("serial", ""))
    return JSONResponse(data)


async def report_file(request: Request):
    name = os.path.basename(request.path_params["name"])  # sem ../
    folder = Path(S._config.report_dir)
    if not folder.is_absolute():
        folder = _ROOT / folder
    path = folder / name
    if not path.is_file():
        return _err(404, "Relatorio nao encontrado.")
    return FileResponse(path)


routes = [
    Route("/api/status", status),
    Route("/api/allowlist", allowlist, methods=["PUT"]),
    Route("/api/run", run_get),
    Route("/api/run", run_start, methods=["POST"]),
    Route("/api/run/stop", run_stop, methods=["POST"]),
    Route("/api/alerts", alerts),
    Route("/api/alerts/{alert_id}", alert_detail),
    Route("/api/urls", urls),
    Route("/api/odata/discover", odata_discover, methods=["POST"]),
    Route("/api/odata/probe", odata_probe, methods=["POST"]),
    Route("/api/nuclei/status", nuclei_status),
    Route("/api/nuclei", nuclei_get),
    Route("/api/nuclei", nuclei_start, methods=["POST"]),
    Route("/api/nuclei/stop", nuclei_stop, methods=["POST"]),
    Route("/api/mobile/status", mobile_status),
    Route("/api/mobile/guidance", mobile_guidance),
    Route("/api/mobile/ca", mobile_ca, methods=["POST"]),
    Route("/api/mobile/proxy", mobile_proxy, methods=["POST"]),
    Route("/api/reports", reports_list),
    Route("/api/reports", reports_create, methods=["POST"]),
    Route("/api/reports/{name}", report_file),
]
if _DIST.is_dir():
    routes.append(Mount("/", StaticFiles(directory=_DIST, html=True)))

app = Starlette(routes=routes)


def main() -> None:
    import uvicorn

    # so na maquina local: o painel dispara ataques e mostra o .env efetivo
    uvicorn.run(app, host="127.0.0.1", port=int(os.environ.get("ZAP_WEB_PORT", "8765")))


if __name__ == "__main__":
    main()
