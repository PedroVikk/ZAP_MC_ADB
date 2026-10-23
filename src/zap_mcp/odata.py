"""Gera requisicoes a partir do $metadata de um servico OData (ex.: SAP Gateway).

Por que: num app SAPUI5 a superficie de teste de verdade e o servico OData, nao
as telas. O crawler/AJAX Spider raramente alcanca as chamadas certas. Aqui a
gente le o $metadata (o contrato do servico), monta as requisicoes de cada
EntitySet — GET de colecao, por chave, com $filter/$select/$expand e, se pedido,
POST/PATCH/DELETE — e as manda PELO proxy do ZAP, para o ZAP registrar cada uma e
poder escanear (injecao, IDOR/autorizacao, etc.) sem depender do spider.

Escrita altera dados de verdade: so com include_writes=True. O SAP protege
escrita com CSRF; a gente busca o token (X-CSRF-Token: Fetch) e reaproveita o
cookie de sessao. Este modulo so monta e envia — os guard-rails (allowlist,
confirmacao) ficam no server.
"""
from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit


class ODataError(Exception):
    """Falha ao buscar ou interpretar o $metadata."""


# ---------------- parsing do EDMX ----------------

def _local(tag: str) -> str:
    """Nome da tag sem o namespace ({ns}Name -> Name) — V2 e V4 usam namespaces
    diferentes, entao a gente casa pelo nome local."""
    return tag.rsplit("}", 1)[-1]


def _iter(node: ET.Element, name: str):
    for el in node.iter():
        if _local(el.tag) == name:
            yield el


@dataclass
class EntitySet:
    name: str
    entity_type: str
    keys: list[dict] = field(default_factory=list)  # {name, type}
    props: list[dict] = field(default_factory=list)  # {name, type, nullable}
    navs: list[str] = field(default_factory=list)


def parse_metadata(xml_text: str) -> dict:
    """Le o EDMX e devolve {version, entitysets:[EntitySet...]}.

    Casa tags pelo nome local, entao funciona para OData V2 (SAP) e V4.
    """
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ODataError(f"$metadata nao e XML valido: {exc}") from exc

    version = root.attrib.get("Version") or ""
    # tipos por nome qualificado e por nome curto, para resolver o EntityType do set
    types: dict[str, ET.Element] = {}
    for et in _iter(root, "EntityType"):
        name = et.attrib.get("Name")
        if name:
            types[name] = et

    sets: list[EntitySet] = []
    for es in _iter(root, "EntitySet"):
        es_name = es.attrib.get("Name")
        type_ref = es.attrib.get("EntityType", "")
        if not es_name:
            continue
        short = type_ref.rsplit(".", 1)[-1]
        et = types.get(short)
        entry = EntitySet(name=es_name, entity_type=type_ref)
        if et is not None:
            key_names = [
                pr.attrib.get("Name")
                for k in _iter(et, "Key")
                for pr in _iter(k, "PropertyRef")
                if pr.attrib.get("Name")
            ]
            for p in et:
                if _local(p.tag) == "Property":
                    pname = p.attrib.get("Name")
                    if not pname:
                        continue
                    info = {
                        "name": pname,
                        "type": p.attrib.get("Type", ""),
                        "nullable": p.attrib.get("Nullable", "true") != "false",
                    }
                    entry.props.append(info)
                    if pname in key_names:
                        entry.keys.append({"name": pname, "type": info["type"]})
                elif _local(p.tag) == "NavigationProperty":
                    nname = p.attrib.get("Name")
                    if nname:
                        entry.navs.append(nname)
        sets.append(entry)

    if not sets:
        raise ODataError("Nenhum EntitySet encontrado no $metadata.")
    return {"version": version, "entitysets": sets}


# ---------------- valores de exemplo por tipo EDM ----------------

def sample_value(edm_type: str, v2: bool) -> str:
    """Valor de exemplo (ja formatado para a URL/corpo) para um tipo EDM.

    v2 muda a sintaxe de data/guid: no V2 e datetime'...'/guid'...', no V4 e cru.
    """
    t = (edm_type or "").replace("Edm.", "")
    if t in ("Int16", "Int32", "Int64", "Byte", "SByte"):
        return "1"
    if t in ("Decimal", "Double", "Single"):
        return "1.0"
    if t == "Boolean":
        return "true"
    if t == "Guid":
        g = "00000000-0000-0000-0000-000000000001"
        return f"guid'{g}'" if v2 else g
    if t in ("DateTime", "DateTimeOffset"):
        return "datetime'2026-01-01T00:00:00'" if v2 else "2026-01-01T00:00:00Z"
    # String e o resto: texto curto e inofensivo
    return "'ZAP'"


def _body_value(edm_type: str):
    """Valor JSON (nao formatado para URL) para o corpo de POST/PATCH."""
    t = (edm_type or "").replace("Edm.", "")
    if t in ("Int16", "Int32", "Int64", "Byte", "SByte"):
        return 1
    if t in ("Decimal", "Double", "Single"):
        return 1.0
    if t == "Boolean":
        return True
    return "ZAP"


def key_predicate(keys: list[dict], v2: bool) -> str:
    """Monta o predicado de chave: (123), ('x') ou (K1='x',K2=123)."""
    if not keys:
        return ""
    if len(keys) == 1:
        return f"({sample_value(keys[0]['type'], v2)})"
    parts = [f"{k['name']}={sample_value(k['type'], v2)}" for k in keys]
    return "(" + ",".join(parts) + ")"


# ---------------- montagem das requisicoes ----------------

def build_requests(model: dict, base: str, include_writes: bool) -> list[dict]:
    """Lista de requisicoes {method, path, kind, entityset, body} por EntitySet.

    'base' e a raiz do servico (ex.: https://host/sap/opu/odata/sap/MEU_SRV).
    So leitura, a menos que include_writes=True.
    """
    v2 = model["version"].startswith("1.") or model["version"].startswith("2.") or not model["version"]
    base = base.rstrip("/")
    out: list[dict] = []

    def add(method, path, kind, es, body=None):
        out.append({"method": method, "path": path, "kind": kind,
                    "entityset": es, "body": body})

    for es in model["entitysets"]:
        name = es.name
        non_key = [p for p in es.props if p["name"] not in {k["name"] for k in es.keys}]
        select = ",".join(p["name"] for p in es.props[:3])
        pred = key_predicate(es.keys, v2)
        fmt = "&$format=json"

        # leitura
        add("GET", f"{base}/{name}?$top=2{fmt}", "colecao", name)
        if select:
            add("GET", f"{base}/{name}?$top=2&$select={select}{fmt}", "select", name)
        if es.navs:
            add("GET", f"{base}/{name}?$top=1&$expand={es.navs[0]}{fmt}", "expand", name)
        # $filter numa propriedade string (alvo tipico de injecao)
        str_prop = next((p for p in non_key if "String" in p["type"]), None)
        if str_prop:
            add("GET", f"{base}/{name}?$filter={str_prop['name']} eq 'ZAP'{fmt}", "filter", name)
        if pred:
            add("GET", f"{base}/{name}{pred}?{fmt[1:]}", "por_chave", name)

        if not include_writes:
            continue
        # escrita: corpo com um valor por propriedade (melhor esforco)
        body = {p["name"]: _body_value(p["type"]) for p in es.props
                if p["name"] not in es.navs}
        add("POST", f"{base}/{name}", "create", name, body)
        if pred:
            add("MERGE" if v2 else "PATCH", f"{base}/{name}{pred}", "update", name, body)
            add("DELETE", f"{base}/{name}{pred}", "delete", name)

    return out


# ---------------- orquestracao (envio pelo proxy do ZAP) ----------------

def service_root(metadata_url: str) -> str:
    """Tira o /$metadata do fim da URL para achar a raiz do servico."""
    split = urlsplit(metadata_url)
    path = split.path
    for suffix in ("/$metadata", "/%24metadata"):
        if path.endswith(suffix):
            path = path[: -len(suffix)]
            break
    return urlunsplit((split.scheme, split.netloc, path, "", ""))


def run_plan(
    metadata_url: str,
    zap_proxy: str,
    username: str = "",
    password: str = "",
    include_writes: bool = False,
    send: bool = True,
    timeout: float = 15.0,
    cookie: str = "",
    use_proxy: bool = True,
) -> dict:
    """Busca o $metadata, monta as requisicoes e (se send) as manda pelo ZAP.

    Com send=True tudo passa pelo proxy do ZAP, para o ZAP registrar e escanear.
    use_proxy=False busca direto (sem ZAP) — usado no 'descobrir', que so le o
    contrato e nao precisa do ZAP no caminho. cookie: sessao ja autenticada
    (Cookie header) reaproveitada, para nao colar nada na mao. Em escrita, busca
    o CSRF token antes. Resumo enxuto (sem corpos de resposta).
    """
    import requests
    import urllib3

    urllib3.disable_warnings()  # o proxy do ZAP usa cert proprio; host do usuario

    root = service_root(metadata_url)
    session = requests.Session()
    session.verify = False
    if use_proxy:
        session.proxies = {"http": zap_proxy, "https": zap_proxy}
    if cookie:
        session.headers["Cookie"] = cookie
    elif username:
        session.auth = (username, password)

    # 1) $metadata
    try:
        resp = session.get(metadata_url, headers={"Accept": "application/xml"}, timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        via = "via ZAP" if use_proxy else "direto"
        raise ODataError(f"nao consegui buscar o $metadata ({via}): {exc}") from exc
    if resp.status_code in (502, 503, 504):
        via = "o ZAP nao alcancou o alvo" if use_proxy else "o alvo nao respondeu"
        raise ODataError(
            f"$metadata deu HTTP {resp.status_code}: {via}. O app esta no ar e a "
            f"URL/host sao alcancaveis a partir daqui?")
    if resp.status_code in (401, 403):
        raise ODataError(
            f"$metadata deu HTTP {resp.status_code}: sem autorizacao. Capture a "
            f"sessao (botao Entrar) ou informe usuario/senha.")
    if resp.status_code >= 400:
        raise ODataError(f"$metadata respondeu HTTP {resp.status_code} (URL certa?)")
    model = parse_metadata(resp.text)
    requests_plan = build_requests(model, root, include_writes)

    discovered = [
        {"entityset": es.name, "keys": [k["name"] for k in es.keys],
         "props": len(es.props), "navs": len(es.navs)}
        for es in model["entitysets"]
    ]
    summary = {
        "service_root": root,
        "odata_version": model["version"] or "desconhecida",
        "entitysets": len(model["entitysets"]),
        "requests_planned": len(requests_plan),
        "includes_writes": include_writes,
        "discovered": discovered,
    }
    if not send:
        summary["requests"] = [
            {k: r[k] for k in ("method", "kind", "entityset", "path")} for r in requests_plan
        ]
        return summary

    # 2) CSRF: busca o token na raiz e reaproveita cookie + token nas escritas
    csrf = ""
    if include_writes:
        try:
            r = session.get(root, headers={"X-CSRF-Token": "Fetch"}, timeout=timeout)
            csrf = r.headers.get("x-csrf-token", "")
        except Exception:  # noqa: BLE001
            csrf = ""

    # 3) envia cada requisicao pelo ZAP
    sent, failed = [], 0
    by_status: dict[str, int] = {}
    for r in requests_plan:
        headers = {"Accept": "application/json"}
        data = None
        if r["method"] in ("POST", "PATCH", "MERGE", "PUT"):
            headers["Content-Type"] = "application/json"
            data = json.dumps(r["body"] or {})
            if csrf:
                headers["X-CSRF-Token"] = csrf
        try:
            rp = session.request(r["method"], r["path"], headers=headers,
                                  data=data, timeout=timeout)
            status = rp.status_code
        except Exception:  # noqa: BLE001
            failed += 1
            continue
        by_status[str(status)] = by_status.get(str(status), 0) + 1
        sent.append({"method": r["method"], "kind": r["kind"],
                     "entityset": r["entityset"], "status": status,
                     "path": r["path"]})

    summary.update({
        "sent": len(sent),
        "failed": failed,
        "csrf_token": "obtido" if csrf else ("nao obtido" if include_writes else "n/a"),
        "by_status": by_status,
        "results": sent,
    })
    return summary
