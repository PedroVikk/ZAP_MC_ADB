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
from .nuclei import NucleiUnavailable, check as nuclei_check, run_blocking as nuclei_run
from .odata import ODataError, run_plan
from .reports import (
    group_alerts,
    markdown_from_alerts,
    report_by_endpoint,
    risk_counts,
    summarize_endpoints,
    summarize_urls,
    write_report,
)
from .safety import (
    ScanRegistry,
    TargetNotAllowed,
    ensure_allowed,
    is_allowed,
    normalize_allowlist,
)

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
        except ODataError as exc:
            return {"error": "odata", "detail": str(exc)}
        except NucleiUnavailable as exc:
            return {"error": "nuclei_indisponivel", "detail": str(exc)}
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
    site: limita a um site especifico (ex.: https://host). Sem site, AGREGA todos
    os hosts autorizados (o SPA e seu backend costumam estar em origens diferentes —
    ex.: :5001 e :5000 —, entao filtrar por uma so origem perderia endpoints), e
    descarta CDNs/terceiros fora da allowlist. only_endpoints foca nas chamadas API/XHR.

    Usa a lista leve de URLs do ZAP (`core.urls`): buscar as mensagens inteiras de um
    site grande (depois do Spider) estoura o proxy com a resposta gigante e trava a
    leitura. A lista de URLs e rapida e cobre tudo que o ZAP viu.
    """
    if site:
        urls = _client.urls(site)
    else:
        # agrega so os hosts autorizados (deny-by-default); fora CDNs/terceiros.
        # Um host que falhe (externo fora do ar, etc.) nao zera o resultado.
        urls = []
        for s in _client.sites():
            if not is_allowed(s, _allowlist):
                continue
            try:
                urls.extend(_client.urls(s))
            except Exception:  # noqa: BLE001
                continue
    summary = summarize_urls(urls)
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
def odata_discover(metadata_url: str, target: str | None = None) -> dict:
    """Le o $metadata de um servico OData e lista os EntitySets e as requisicoes
    que daria para testar — SEM enviar nada ao alvo.

    E o passo de reconhecimento para um app SAPUI5: o contrato do servico diz
    quais colecoes, chaves e propriedades existem. O host (target, ou o host da
    propria URL) precisa estar autorizado. Nada passa pelo ZAP aqui: so busca o
    $metadata para planejar.
    """
    ensure_allowed(target or metadata_url, _allowlist)
    return run_plan(metadata_url, _config.base_url, send=False)


@mcp.tool()
@guarded
def odata_probe(
    metadata_url: str,
    include_writes: bool = False,
    confirm: bool = False,
    username: str = "",
    password: str = "",
    target: str | None = None,
) -> dict:
    """Monta as requisicoes do servico OData e as ENVIA pelo proxy do ZAP, para o
    ZAP registrar cada endpoint e poder escanear depois (get_urls, active_scan).

    Por padrao so leitura (GET de colecao, por chave, $filter/$select/$expand).
    include_writes=True tambem manda POST/PATCH/DELETE — altera dados de verdade,
    entao exige confirm=True e busca o CSRF token (X-CSRF-Token: Fetch) antes.
    username/password: Basic auth, se o servico pedir. O host precisa estar
    autorizado. Depois disto, rode um active_scan no host para fuzzar os params.
    """
    ensure_allowed(target or metadata_url, _allowlist)
    if include_writes and not confirm:
        return {
            "status": "confirmacao_necessaria",
            "metadata_url": metadata_url,
            "message": (
                "include_writes envia POST/PATCH/DELETE reais ao servico OData "
                "(cria, altera e apaga registros). Rechame com confirm=True para "
                "autorizar — so em base de teste."
            ),
        }
    return run_plan(metadata_url, _config.base_url, username=username,
                    password=password, include_writes=include_writes, send=True)


@mcp.tool()
@guarded
def nuclei_status() -> dict:
    """Diz se o Nuclei esta instalado e qual a versao (NUCLEI_PATH)."""
    return {"available": True, "version": nuclei_check(_config.nuclei_path),
            "path": _config.nuclei_path}


@mcp.tool()
@guarded
def nuclei_scan(
    target: str,
    severity: str = "",
    tags: str = "",
    templates: str = "",
    through_zap: bool = False,
    max_seconds: int = 300,
) -> dict:
    """Roda o Nuclei contra o alvo e devolve os achados agrupados por severidade.

    Complementa o ZAP com assinaturas conhecidas (CVEs, misconfig, templates de
    SAP) e pouquissimo falso positivo. Bloqueante ate o fim ou max_seconds.
    severity: critical,high,medium,low,info (lista separada por virgula).
    tags: ex. 'sap,cve'. templates: caminho/-t especifico. through_zap=True manda
    pelo proxy do ZAP para os achados tambem ficarem registrados la. O host
    precisa estar autorizado.
    """
    ensure_allowed(target, _allowlist)
    proxy = _config.base_url if through_zap else ""
    return nuclei_run(_config.nuclei_path, [target], severity=severity, tags=tags,
                      templates=templates, proxy=proxy, cap_seconds=float(max_seconds))


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


def _walk_plugins(node, out: list) -> None:
    """Acha os plugins (tipos de ataque) no scan_progress, seja qual for o aninhamento."""
    if isinstance(node, dict):
        if "name" in node and ("status" in node or "reqCount" in node):
            out.append({
                "ataque": node.get("name"),
                "status": node.get("status"),
                "reqs": node.get("reqCount"),
                "alertas": node.get("alertCount"),
            })
        for v in node.values():
            _walk_plugins(v, out)
    elif isinstance(node, list):
        for v in node:
            _walk_plugins(v, out)


@mcp.tool()
@guarded
def active_scan_feed(scan_id: str, recent: int = 0) -> dict:
    """Snapshot ao vivo do scan ativo: progresso, ataques enviados, alertas e qual
    tipo de ataque esta rodando agora. Chamado em loop pelo painel.

    So faz chamadas LEVES (status/contadores/progresso): buscar o corpo de cada
    mensagem pelo proxy trava, porque durante o scan o proxy do ZAP fica saturado.
    recent>0 tenta trazer as ultimas requisicoes (metodo+URL), mas e opcional e pode
    ficar lento — por isso vem desligado por padrao.
    """
    progress = _client.active_status(scan_id)
    msg_ids = _client.active_messages_ids(scan_id)
    alert_ids = _client.active_alerts_ids(scan_id)

    plugins: list = []
    _walk_plugins(_client.active_progress(scan_id), plugins)
    rodando = [p for p in plugins
               if (p.get("status") or "").lower().startswith(("running", "em", "andamento"))]

    ultimos = []
    for mid in (msg_ids[-recent:][::-1] if recent else []):
        try:
            m = _client.message(mid)
            first = (m.get("requestHeader", "") or "").split("\n", 1)[0].split(" ")
            resp = (m.get("responseHeader", "") or "").split("\n", 1)[0].split(" ")
            ultimos.append({
                "metodo": first[0] if first else "?",
                "url": first[1] if len(first) > 1 else "",
                "status": resp[1] if len(resp) > 1 else "",
            })
        except Exception:  # noqa: BLE001
            continue

    return {
        "progresso": progress,
        "ataques_enviados": len(msg_ids),
        "alertas": len(alert_ids),
        "rodando": rodando[:6],
        "ultimos_ataques": ultimos,
        "concluido": progress >= 100,
    }


@mcp.tool()
@guarded
def report_endpoints(site: str | None = None, min_risk: str = "Informational") -> dict:
    """Documento (Markdown) do que o ZAP testou/achou em CADA tela/endpoint.

    Agrupa os alertas por metodo+URL, mostra risco, parametro, o ataque enviado
    (quando houve scan ativo) e a evidencia, e lista os endpoints vistos sem achados.
    Sem site, usa os hosts autorizados. Grava em arquivo e devolve o caminho.
    """
    if site:
        alerts = _client.alerts(site)
        urls = _client.urls(site)
    else:
        alerts, urls = [], []
        for s in _client.sites():
            if not is_allowed(s, _allowlist):
                continue
            try:
                alerts.extend(_client.alerts(s))
                urls.extend(_client.urls(s))
            except Exception:  # noqa: BLE001
                continue
    content = report_by_endpoint(alerts, urls, min_risk=min_risk)
    path = write_report(_config.report_dir, "md", content)
    return {"path": path, "endpoints_com_achados": content.count("\n## `"),
            "by_risk": risk_counts(alerts)}
