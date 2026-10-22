"""Ferramentas MCP do ZAP.

Fluxo: descobrir (spider) -> escanear (active) -> ler (alerts) -> relatorio.
Scans sao assincronos: as ferramentas de scan devolvem um scan_id e o progresso
e consultado por scan_status. Toda excecao vira um dict de erro (nunca derruba
o servidor).
"""
from __future__ import annotations

import functools
from typing import Callable

from mcp.server.mcpserver import MCPServer

from .client import ZapClient, ZapUnavailable
from .config import Config
from .reports import (
    group_alerts,
    markdown_from_alerts,
    risk_counts,
    summarize_endpoints,
    write_report,
)
from .safety import ScanRegistry, TargetNotAllowed, ensure_allowed, normalize_allowlist

mcp = MCPServer("zap-mcp")

_config = Config.from_env()
_allowlist = normalize_allowlist(_config.allowed_targets)
_client = ZapClient(_config)
_registry = ScanRegistry()


def guarded(fn: Callable) -> Callable:
    """Converte qualquer falha num dict de erro, preservando a assinatura."""

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except TargetNotAllowed as exc:
            return {"error": "alvo_nao_autorizado", "detail": str(exc)}
        except ZapUnavailable as exc:
            return {"error": "zap_indisponivel", "detail": str(exc)}
        except Exception as exc:  # noqa: BLE001 - fronteira do servidor
            return {"error": "falha", "detail": f"{type(exc).__name__}: {exc}"}

    return wrapper


@mcp.tool()
@guarded
def zap_status() -> dict:
    """Versao do ZAP, URL base, alvos autorizados e scans em andamento."""
    running = [
        {
            "scan_id": r.scan_id,
            "kind": r.kind,
            "target": r.target,
            "elapsed_s": int(_registry.elapsed(r)),
        }
        for r in _registry.all()
    ]
    return {
        "zap_version": _client.version(),
        "base_url": _config.base_url,
        "max_scan_seconds": _config.max_scan_seconds,
        "allowed_targets": sorted(_allowlist),
        "running_scans": running,
    }


@mcp.tool()
@guarded
def spider_scan(target: str) -> dict:
    """Inicia o crawling tradicional do alvo. Devolve um scan_id.

    O alvo precisa estar em ZAP_ALLOWED_TARGETS.
    """
    ensure_allowed(target, _allowlist)
    scan_id = _client.spider_scan(target)
    _registry.add(scan_id, "spider", target)
    return {"scan_id": scan_id, "kind": "spider", "target": target, "status": "iniciado"}


@mcp.tool()
@guarded
def ajax_spider_scan(target: str) -> dict:
    """Inicia o AJAX Spider (apps com muito JavaScript). Devolve um scan_id.

    O alvo precisa estar em ZAP_ALLOWED_TARGETS.
    """
    ensure_allowed(target, _allowlist)
    _client.ajax_scan(target)
    scan_id = _registry.next_ajax_id()
    _registry.add(scan_id, "ajax", target)
    return {"scan_id": scan_id, "kind": "ajax", "target": target, "status": "iniciado"}


@mcp.tool()
@guarded
def scan_status(scan_id: str) -> dict:
    """Progresso de um scan. Para o scan se ele passar do limite de tempo."""
    record = _registry.get(scan_id)
    if record is None:
        return {"error": "scan_desconhecido", "detail": f"scan_id '{scan_id}' nao encontrado"}

    elapsed = _registry.elapsed(record)
    over_limit = elapsed > _config.max_scan_seconds
    base = {"scan_id": scan_id, "kind": record.kind, "target": record.target, "elapsed_s": int(elapsed)}

    if record.kind == "spider":
        progress = _client.spider_status(scan_id)
        if over_limit and progress < 100:
            _client.spider_stop(scan_id)
            return {**base, "progress": progress, "status": "parado_por_limite_de_tempo"}
        return {**base, "progress": progress, "status": "concluido" if progress >= 100 else "em_andamento"}

    if record.kind == "active":
        progress = _client.active_status(scan_id)
        if over_limit and progress < 100:
            _client.active_stop(scan_id)
            return {**base, "progress": progress, "status": "parado_por_limite_de_tempo"}
        return {**base, "progress": progress, "status": "concluido" if progress >= 100 else "em_andamento"}

    # ajax: status textual global ("running"/"stopped")
    state = _client.ajax_status()
    if over_limit and state == "running":
        _client.ajax_stop()
        return {**base, "status": "parado_por_limite_de_tempo"}
    return {**base, "status": "concluido" if state != "running" else "em_andamento", "ajax_state": state}


@mcp.tool()
@guarded
def active_scan(target: str, confirm: bool = False) -> dict:
    """Scan ATIVO: envia ataques reais contra o alvo.

    Exige confirm=True (confirmacao explicita) e o alvo em ZAP_ALLOWED_TARGETS.
    Use so em sistemas que voce esta autorizado a testar.
    """
    ensure_allowed(target, _allowlist)
    if not confirm:
        return {
            "status": "confirmacao_necessaria",
            "target": target,
            "message": (
                "O scan ativo envia requisicoes de ataque reais ao alvo. "
                "Rechame com confirm=True para autorizar."
            ),
        }
    scan_id = _client.active_scan(target)
    _registry.add(scan_id, "active", target)
    return {"scan_id": scan_id, "kind": "active", "target": target, "status": "iniciado"}


@mcp.tool()
@guarded
def get_alerts(min_risk: str = "Low", group_by_type: bool = True, base_url: str | None = None) -> dict:
    """Resumo das vulnerabilidades, agrupadas por tipo e risco.

    min_risk: Informational | Low | Medium | High (filtra abaixo do nivel).
    base_url: limita a um site especifico (opcional).
    """
    alerts = _client.alerts(base_url)
    return group_alerts(alerts, min_risk=min_risk, group_by_type=group_by_type)


@mcp.tool()
@guarded
def get_urls(site: str | None = None, only_endpoints: bool = False) -> dict:
    """URLs e endpoints que o ZAP capturou (spider + trafego que passou pelo proxy).

    Separa paginas de chamadas de API/XHR (metodo que muda estado, resposta
    JSON/XML, ou path tipico de API). Para um SPA, os endpoints de API so
    aparecem se o trafego passou pelo ZAP (AJAX Spider ou navegacao proxied).
    site: limita a um site especifico (ex.: https://host). only_endpoints foca
    nas chamadas de API/XHR.
    """
    summary = summarize_endpoints(_client.messages(site))
    if only_endpoints:
        return {"total_urls": summary["total_urls"], "endpoints": summary["endpoints"]}
    return summary


@mcp.tool()
@guarded
def get_alert_details(alert_id: str) -> dict:
    """Detalhe de um alerta: evidencia, request/response e solucao sugerida."""
    a = _client.alert(alert_id)
    detail = {
        "id": a.get("id"),
        "name": a.get("alert"),
        "risk": a.get("risk"),
        "confidence": a.get("confidence"),
        "url": a.get("url"),
        "param": a.get("param"),
        "attack": a.get("attack"),
        "evidence": a.get("evidence"),
        "cweid": a.get("cweid"),
        "wascid": a.get("wascid"),
        "description": a.get("description"),
        "solution": a.get("solution"),
        "reference": a.get("reference"),
    }
    message_id = a.get("messageId") or a.get("message_id")
    if message_id:
        try:
            m = _client.message(message_id)
            detail["request"] = {
                "header": m.get("requestHeader"),
                "body": (m.get("requestBody") or "")[:4000],
            }
            detail["response"] = {
                "header": m.get("responseHeader"),
                "body": (m.get("responseBody") or "")[:4000],
            }
        except Exception:  # noqa: BLE001 - mensagem e opcional
            pass
    return detail


@mcp.tool()
@guarded
def import_openapi(url: str, target: str | None = None) -> dict:
    """Importa uma especificacao OpenAPI para popular a arvore de sites e testar a API.

    O host da API (target, ou o host da propria URL) precisa estar autorizado.
    """
    ensure_allowed(target or url, _allowlist)
    result = _client.import_openapi(url)
    return {"status": "importado", "spec": url, "result": result}


@mcp.tool()
@guarded
def generate_report(format: str = "html") -> dict:
    """Gera o relatorio do scan atual (html, json ou md) e grava em arquivo.

    Devolve o caminho do arquivo e a contagem por risco (nao despeja o relatorio
    inteiro no contexto).
    """
    fmt = format.lower()
    if fmt not in ("html", "json", "md", "markdown"):
        return {"error": "formato_invalido", "detail": "use html, json ou md"}

    content = _client.report(fmt)
    if content is None and fmt in ("md", "markdown"):
        content = markdown_from_alerts(group_alerts(_client.alerts(None)))
    if content is None:
        return {"error": "relatorio_vazio", "detail": f"ZAP nao retornou relatorio em {fmt}"}

    path = write_report(_config.report_dir, fmt, content)
    return {"format": fmt, "path": path, "by_risk": risk_counts(_client.alerts(None))}
