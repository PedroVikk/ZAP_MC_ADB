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


def write_report(report_dir: str, fmt: str, content: str) -> str:
    ext = _EXT.get(fmt, "txt")
    os.makedirs(report_dir, exist_ok=True)
    stamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.abspath(os.path.join(report_dir, f"zap-report_{stamp}.{ext}"))
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path
