"""Agrupamento enxuto de alertas e gravacao de relatorios em arquivo.

Agrupar por tipo+risco evita despejar milhares de achados repetidos no contexto.
"""
from __future__ import annotations

import datetime as _dt
import os

RISK_ORDER = {"informational": 0, "low": 1, "medium": 2, "high": 3}
_EXT = {"html": "html", "json": "json", "md": "md", "markdown": "md"}


def risk_rank(name: str | None) -> int:
    first = (name or "").strip().split(" ")[0].lower()
    return RISK_ORDER.get(first, 0)


def risk_counts(alerts: list[dict]) -> dict[str, int]:
    counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for alert in alerts:
        label = (alert.get("risk") or "").split(" ")[0].title()
        if label in counts:
            counts[label] += 1
    return counts


def group_alerts(
    alerts: list[dict],
    min_risk: str = "Informational",
    group_by_type: bool = True,
) -> dict:
    threshold = risk_rank(min_risk)
    kept = [a for a in alerts if risk_rank(a.get("risk")) >= threshold]

    if not group_by_type:
        items = [
            {
                "id": a.get("id"),
                "name": a.get("alert"),
                "risk": a.get("risk"),
                "url": a.get("url"),
            }
            for a in kept
        ]
        return {"total": len(kept), "min_risk": min_risk, "alerts": items}

    groups: dict[tuple[str, str], dict] = {}
    for a in kept:
        key = (a.get("alert") or "?", (a.get("risk") or "").split(" ")[0].title())
        bucket = groups.get(key)
        if bucket is None:
            bucket = {
                "name": key[0],
                "risk": key[1],
                "count": 0,
                "example_url": a.get("url"),
                "cweid": a.get("cweid"),
                "example_alert_id": a.get("id"),
            }
            groups[key] = bucket
        bucket["count"] += 1

    ordered = sorted(
        groups.values(),
        key=lambda g: (risk_rank(g["risk"]), g["count"]),
        reverse=True,
    )
    return {
        "total": len(kept),
        "min_risk": min_risk,
        "by_risk": risk_counts(kept),
        "groups": ordered,
    }


def markdown_from_alerts(grouped: dict) -> str:
    lines = ["# Relatorio ZAP", ""]
    counts = grouped.get("by_risk", {})
    lines.append(
        "Resumo: "
        + ", ".join(f"{k} {v}" for k, v in counts.items())
        + f" (total {grouped.get('total', 0)})"
    )
    lines.append("")
    for g in grouped.get("groups", []):
        lines.append(f"## [{g['risk']}] {g['name']} ({g['count']}x)")
        if g.get("example_url"):
            lines.append(f"- Exemplo: {g['example_url']}")
        if g.get("cweid"):
            lines.append(f"- CWE: {g['cweid']}")
        lines.append("")
    return "\n".join(lines)


_API_HINTS = ("/api/", "/odata/", "/rest/", "/service", "/graphql", "/v1/", "/v2/", "$batch")


def _looks_api(method: str, url: str, content_type: str) -> bool:
    if method.upper() not in ("GET", "HEAD", "OPTIONS"):
        return True
    ct = (content_type or "").lower()
    if "json" in ct or "xml" in ct:
        return True
    low = url.lower()
    return any(hint in low for hint in _API_HINTS)


def _first_line(header: str) -> str:
    return (header or "").split("\r\n", 1)[0].split("\n", 1)[0]


def _header_value(header: str, name: str) -> str:
    name_l = name.lower() + ":"
    for line in (header or "").replace("\r\n", "\n").split("\n"):
        if line.lower().startswith(name_l):
            return line.split(":", 1)[1].strip()
    return ""


def summarize_endpoints(messages: list[dict]) -> dict:
    """Agrupa as requisicoes do ZAP em endpoints unicos (metodo + path).

    Separa 'pages' (navegacao/estaticos) de 'endpoints' (API/XHR: metodo que
    muda estado, ou resposta JSON/XML, ou path tipico de API).
    """
    seen: dict[tuple[str, str], dict] = {}
    for m in messages:
        req_first = _first_line(m.get("requestHeader", ""))
        parts = req_first.split(" ")
        method = parts[0] if parts else "?"
        url = parts[1] if len(parts) > 1 else ""
        if not url:
            continue
        resp = m.get("responseHeader", "")
        status_parts = _first_line(resp).split(" ")
        status = status_parts[1] if len(status_parts) > 1 else ""
        content_type = _header_value(resp, "Content-Type").split(";")[0]
        path = url.split("?", 1)[0]
        key = (method, path)
        entry = seen.get(key)
        if entry is None:
            entry = {
                "method": method,
                "url": path,
                "status": status,
                "content_type": content_type,
                "hits": 0,
                "has_params": "?" in url,
            }
            seen[key] = entry
        entry["hits"] += 1
        entry["has_params"] = entry["has_params"] or "?" in url

    items = list(seen.values())
    endpoints = [e for e in items if _looks_api(e["method"], e["url"], e["content_type"])]
    pages = [e for e in items if e not in endpoints]
    endpoints.sort(key=lambda e: (e["method"], e["url"]))
    pages.sort(key=lambda e: e["url"])
    return {"total_urls": len(items), "endpoints": endpoints, "pages": pages}


_STATIC_EXT = (
    ".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".ico", ".map", ".html", ".htm",
    ".txt", ".properties", ".less", ".scss",
)


def _is_static(path: str) -> bool:
    low = path.lower().rstrip("/")
    return any(low.endswith(ext) for ext in _STATIC_EXT)


def summarize_urls(urls: list[str]) -> dict:
    """Resume a lista de URLs do ZAP (chamada leve `core.urls`) em endpoints x paginas.

    Sem o metodo HTTP (a lista de URLs nao traz), a separacao e pelo caminho:
    recurso estatico (js/css/img/fonte/html) e pagina; path tipico de API
    (/api/, /v1/, /odata/, $batch...) e endpoint. Agrupa por caminho (sem query).
    """
    seen: dict[str, dict] = {}
    for u in urls:
        if not u:
            continue
        path = u.split("?", 1)[0]
        entry = seen.get(path)
        if entry is None:
            low = path.lower()
            is_api = (not _is_static(path)) and any(h in low for h in _API_HINTS)
            entry = {
                "method": "",
                "url": path,
                "content_type": "",
                "is_api": is_api,
                "has_params": False,
            }
            seen[path] = entry
        entry["has_params"] = entry["has_params"] or "?" in u

    items = list(seen.values())
    endpoints = [e for e in items if e["is_api"]]
    pages = [e for e in items if not e["is_api"]]
    endpoints.sort(key=lambda e: e["url"])
    pages.sort(key=lambda e: e["url"])
    return {"total_urls": len(items), "endpoints": endpoints, "pages": pages}


_RISK_LABEL = {3: "Alto", 2: "Medio", 1: "Baixo", 0: "Informativo"}


def report_by_endpoint(alerts: list[dict], urls: list[str] | None = None,
                       min_risk: str = "Informational") -> str:
    """Documento por tela/endpoint: o que o ZAP testou e achou em cada URL.

    Agrupa os alertas por (metodo, URL) — cada grupo e um endpoint/tela. Mostra
    risco, nome do achado, parametro, o ataque enviado (quando houve scan ativo) e a
    evidencia. No fim, lista as URLs vistas que nao tiveram nenhum achado.
    """
    threshold = risk_rank(min_risk)
    by_ep: dict[tuple[str, str], list[dict]] = {}
    for a in alerts:
        if risk_rank(a.get("risk")) < threshold:
            continue
        method = (a.get("method") or "GET").upper()
        url = (a.get("url") or "").split("?", 1)[0]
        by_ep.setdefault((method, url), []).append(a)

    counts = risk_counts([a for a in alerts if risk_rank(a.get("risk")) >= threshold])
    stamp = _dt.datetime.now().strftime("%d/%m/%Y %H:%M")
    lines = [
        "# Relatorio de ataque por endpoint (ZAP)",
        "",
        f"Gerado em {stamp}.",
        "",
        "Resumo: " + ", ".join(f"{k} {v}" for k, v in counts.items())
        + f"  —  {len(by_ep)} endpoint(s) com achados.",
        "",
        "> 'Ataque' = payload enviado pelo scan ativo. Sem o scan ativo, os achados"
        " sao passivos (cabecalhos, divulgacao de info, etc.).",
        "",
    ]

    # endpoints com mais risco primeiro
    def ep_rank(item):
        (_m, _u), al = item
        return max((risk_rank(a.get("risk")) for a in al), default=0)

    for (method, url), al in sorted(by_ep.items(), key=ep_rank, reverse=True):
        top = max((risk_rank(a.get("risk")) for a in al), default=0)
        lines.append(f"## `{method}` {url}")
        lines.append(f"Pior risco: **{_RISK_LABEL.get(top, '?')}** — {len(al)} achado(s).")
        lines.append("")
        # agrupa por tipo de achado dentro do endpoint
        seen_types: dict[str, dict] = {}
        for a in al:
            key = a.get("alert") or a.get("name") or "?"
            b = seen_types.setdefault(key, {"risk": a.get("risk"), "params": set(),
                                            "attack": a.get("attack") or "",
                                            "evidence": a.get("evidence") or "",
                                            "cweid": a.get("cweid")})
            if a.get("param"):
                b["params"].add(a["param"])
        for name, b in sorted(seen_types.items(),
                              key=lambda kv: risk_rank(kv[1]["risk"]), reverse=True):
            risk = (b["risk"] or "").split(" ")[0]
            lines.append(f"- **[{risk}] {name}**")
            if b["params"]:
                lines.append(f"  - Parametro(s): {', '.join(sorted(b['params']))}")
            if b["attack"]:
                lines.append(f"  - Ataque enviado: `{b['attack'][:200]}`")
            if b["evidence"]:
                lines.append(f"  - Evidencia: `{b['evidence'][:200]}`")
            if b["cweid"] and b["cweid"] not in ("-1", "", None):
                lines.append(f"  - CWE: {b['cweid']}")
        lines.append("")

    # endpoints/urls sem nenhum achado (foram vistos, mas nada saltou)
    if urls:
        hit = {u for (_m, u) in by_ep}
        clean = sorted({u.split("?", 1)[0] for u in urls} - hit)
        if clean:
            lines.append(f"## Endpoints vistos sem achados ({len(clean)})")
            lines.append("")
            for u in clean:
                lines.append(f"- {u}")
            lines.append("")

    return "\n".join(lines)


def write_report(report_dir: str, fmt: str, content: str) -> str:
    ext = _EXT.get(fmt, "txt")
    os.makedirs(report_dir, exist_ok=True)
    stamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.abspath(os.path.join(report_dir, f"zap-report_{stamp}.{ext}"))
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path
