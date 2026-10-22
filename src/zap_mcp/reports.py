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


def write_report(report_dir: str, fmt: str, content: str) -> str:
    ext = _EXT.get(fmt, "txt")
    os.makedirs(report_dir, exist_ok=True)
    stamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.abspath(os.path.join(report_dir, f"zap-report_{stamp}.{ext}"))
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path
