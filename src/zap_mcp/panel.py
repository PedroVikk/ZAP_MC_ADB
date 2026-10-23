"""Painel de controle do ZAP MCP (Streamlit).

Rode com:  streamlit run src/zap_mcp/panel.py

Mostra os alvos autorizados (quem pode ser atacado), as opcoes de scan, a
estimativa de tempo, e deixa escolher headless x ver o navegador ao vivo.
So opera dentro da allowlist; o scan ativo exige confirmacao.
"""
from __future__ import annotations

import asyncio
import threading
import time
from urllib.parse import urlparse

import streamlit as st

from zap_mcp import server as S
from zap_mcp.config import Config
from zap_mcp.explorer import explore
from zap_mcp.safety import is_allowed, normalize_allowlist

st.set_page_config(page_title="ZAP MCP - Painel", layout="wide")
st.title("ZAP MCP - Painel de controle")

cfg = Config.from_env()


def origin_of(url: str) -> str:
    parsed = urlparse(url if "://" in url else "http://" + url)
    return f"{parsed.scheme}://{parsed.netloc}"


@st.cache_resource
def stop_signal() -> threading.Event:
    """Bandeira de parada compartilhada entre as execucoes do script.

    Clicar em Parar dispara uma nova execucao; a que esta rodando o teste segue no
    meio do explorador (sem chamadas de tela, o Streamlit nao consegue interrompe-la).
    Por isso o botao so liga esta bandeira, e o explorador/polling conferem a cada passo.
    """
    return threading.Event()


STOP = stop_signal()


def run_active_feed(scan_id, cap_seconds=None):
    """Mostra o scan ativo acontecendo: progresso, ataques enviados e os ultimos
    disparos, atualizando a cada ~2s. Para no botao Parar (cancela no ZAP)."""
    cap = cap_seconds or cfg.max_scan_seconds
    bar = st.progress(0.0, text="Scan ativo")
    m1, m2, m3 = st.columns(3)
    enviados_ph, alertas_ph, prog_ph = m1.empty(), m2.empty(), m3.empty()
    rodando_ph = st.empty()
    ultimos_ph = st.empty()
    end = time.time() + cap
    while time.time() < end:
        if STOP.is_set():
            try:
                S._client.active_stop(scan_id)
            except Exception:  # noqa: BLE001
                pass
            bar.progress(1.0, text="Scan ativo - parado")
            rodando_ph.warning("Scan ativo parado pelo botao Parar.")
            return
        feed = S.active_scan_feed(scan_id)
        if "error" in feed:
            rodando_ph.error(f"Falha ao ler o scan ativo: {feed['error']}")
            break
        pct = min(100, int(feed.get("progresso", 0)))
        bar.progress(pct / 100, text=f"Scan ativo - {pct}%")
        enviados_ph.metric("Ataques enviados", feed.get("ataques_enviados", 0))
        alertas_ph.metric("Alertas achados", feed.get("alertas", 0))
        prog_ph.metric("Progresso", f"{pct}%")
        rodando = feed.get("rodando", [])
        if rodando:
            rodando_ph.write("**Atacando agora:** " + ", ".join(
                f"{p.get('ataque')} ({p.get('reqs', 0)} reqs)" for p in rodando))
        ultimos = feed.get("ultimos_ataques", [])
        if ultimos:
            ultimos_ph.dataframe(
                [{"Metodo": u["metodo"], "URL": u["url"], "Resposta": u.get("status", "")}
                 for u in ultimos], use_container_width=True)
        if feed.get("concluido"):
            break
        time.sleep(2)
    bar.progress(1.0, text="Scan ativo - concluido")


def poll(scan_id, cap_seconds, label, stop_fn=None):
    bar = st.progress(0.0, text=label)
    end = time.time() + cap_seconds
    while scan_id is not None and time.time() < end:
        if STOP.is_set():
            if stop_fn:
                try:
                    stop_fn(scan_id)
                except Exception:  # noqa: BLE001
                    pass
            bar.progress(1.0, text=f"{label} - parado")
            return
        status = S.scan_status(scan_id)
        bar.progress(min(100, int(status.get("progress", 0))) / 100, text=label)
        if status.get("status") != "em_andamento":
            break
        time.sleep(2)
    bar.progress(1.0, text=label)


# ---------------- Sidebar: conexao ZAP ----------------
with st.sidebar:
    st.header("Conexao ZAP")
    st.text_input("ZAP base URL", cfg.base_url, disabled=True, help="Definida no .env (ZAP_BASE_URL).")
    st.caption("API key: " + ("definida" if cfg.api_key else "NAO definida") + " (via .env)")
    if st.button("Testar conexao"):
        try:
            sites = list(S._client._zap_api().core.sites)
            st.success(f"ZAP {S._client.version()} - {len(sites)} site(s)")
        except Exception as exc:  # noqa: BLE001
            st.error(str(exc))
    st.divider()
    st.caption("So opera dentro dos alvos autorizados. O scan ativo envia "
               "ataques reais - use so em alvo seu e descartavel.")


# ---------------- Alvos autorizados (o freio) ----------------
st.subheader("🔒 Onde pode explorar e atacar (allowlist)")
st.caption("Este e o freio. Deny by default: **lista vazia bloqueia TUDO**. O "
           "explorador e o scan ativo so rodam contra estes hosts (subdominios "
           "incluidos). Para barrar: esvazie a lista (bloqueia tudo), ou remova um host; "
           "para nao explorar/atacar, desmarque 'Rodar explorador' / 'Scan ATIVO' abaixo.")
allow_text = st.text_area(
    "Hosts autorizados (um por linha ou separados por virgula) — apague para bloquear",
    value="\n".join(sorted(normalize_allowlist(cfg.allowed_targets))),
    height=90,
)
allow = normalize_allowlist(allow_text.replace(",", "\n").splitlines())
if allow:
    st.success("Liberados agora: " + ", ".join(sorted(allow)))
else:
    st.error("Allowlist vazia — tudo bloqueado. Nenhum scan vai rodar.")


# ---------------- Scan ----------------
st.subheader("Scan")
stop_col, stop_msg = st.columns([1, 4])
with stop_col:
    if st.button("⏹ Parar teste", help="Para o explorador e cancela spider/scan ativo no ZAP."):
        STOP.set()
with stop_msg:
    if STOP.is_set():
        st.warning("Parada pedida — o teste em andamento encerra no proximo passo "
                   "(fecha o navegador e cancela o scan no ZAP).")
# Formulario: tudo (alvo, opcoes e LOGIN) e enviado junto ao clicar Rodar. Fora de um
# form, o Streamlit as vezes ainda nao tinha recebido o usuario/senha digitados quando
# o Rodar disparava — o explorador rodava "sem credenciais" e nao entrava no sistema.
with st.form("scan"):
    target = st.text_input("Alvo (URL)", "https://localhost:5001/index.html")

    left, right = st.columns(2)
    with left:
        st.markdown("**Explorador (Playwright)**")
        do_explore = st.checkbox("Rodar explorador", value=True)
        headless = st.checkbox("Headless (sem janela)", value=False,
                               help="Desmarque para VER o navegador explorando ao vivo.")
        route_sweep = st.checkbox("Varredura por rotas (UI5)", value=True,
                                  help="Le o manifest e visita cada tela do SPA.")
        do_crud = st.checkbox("Testar CRUD (cria/edita/exclui)", value=False,
                              help="Em cada tela: cria, abre, edita e exclui um registro "
                                   "(dispara POST/PUT/DELETE). So em base de teste — mexe "
                                   "em dados de verdade.")
        max_seconds = st.slider("Orcamento de tempo (s)", 30, 600, 150, 10)
        max_actions = st.slider("Maximo de acoes", 50, 1000, 300, 50)
        login_user = st.text_input("Login - usuario (opcional)", "")
        login_pass = st.text_input("Login - senha", "", type="password")
    with right:
        st.markdown("**ZAP**")
        do_spider = st.checkbox("Spider (crawler classico)", value=False)
        do_active = st.checkbox("Scan ATIVO (ataques reais)", value=False,
                                help="Envia payloads de ataque. So em alvo descartavel.")
        min_risk = st.selectbox("Risco minimo nos alertas",
                                ["Informational", "Low", "Medium", "High"], index=1)
        report_fmt = st.selectbox("Formato do relatorio", ["html", "md", "json"], index=0)

    submitted = st.form_submit_button("Rodar", type="primary")


# ---------------- Estimativa de tempo ----------------
estimate = 0
if do_explore:
    estimate += int(max_seconds) + 20
if do_spider:
    estimate += 60
if do_active:
    estimate += cfg.max_scan_seconds
mins, secs = divmod(estimate, 60)
note = f"Tempo estimado: ~{mins} min {secs:02d}s"
if do_active:
    note += "  (o scan ativo varia muito com o tamanho do site)"
st.info(note)


# ---------------- Rodar ----------------
if submitted:
    if not (do_explore or do_spider or do_active):
        st.warning("Marque pelo menos uma acao: explorador, spider ou scan ativo.")
        st.stop()
    if do_explore and login_user and not login_pass:
        st.warning("Usuario preenchido sem senha — o explorador nao vai conseguir entrar.")
    STOP.clear()  # rodada nova comeca sem parada pendente
    # a allowlist editada na tela passa a valer para os guard-rails do servidor
    S._allowlist = allow
    if not is_allowed(target, allow):
        st.error(f"'{target}' nao esta nos alvos autorizados. Adicione o host na lista acima.")
        st.stop()

    origin = origin_of(target)

    if do_explore:
        with st.spinner("Explorando o alvo..."):
            res = asyncio.run(explore(
                target, cfg.base_url, float(max_seconds), int(max_actions),
                login_user, login_pass, headless=headless, route_sweep=route_sweep,
                should_stop=STOP.is_set, crud=do_crud))
        if res.get("stopped"):
            st.warning("Explorador parado pelo botao Parar.")
        st.success(
            f"Explorador: login {res.get('login_status')} - "
            f"rotas {res.get('routes_found', 0)} (visitadas {len(res.get('routes_visited', []))}) - "
            f"{res.get('actions')} acoes - {res.get('requests_total')} requests")
        crud_rows = [r for r in res.get("crud", [])
                     if any(r.get(k) for k in ("create", "view", "edit", "delete")) or r.get("erro")]
        if crud_rows:
            st.markdown("**CRUD por tela**")
            st.dataframe([{
                "Tela": r.get("tela"),
                "Campos": r.get("campos_preenchidos", 0),
                "Create": r.get("create") or "-",
                "View": r.get("view") or "-",
                "Edit": r.get("edit") or "-",
                "Delete": r.get("delete") or "-",
                "Erro": r.get("erro", ""),
            } for r in crud_rows], use_container_width=True)

    if do_spider:
        with st.spinner("Spider..."):
            if not STOP.is_set():
                poll(S.spider_scan(origin).get("scan_id"), 120, "Spider",
                     stop_fn=S._client.spider_stop)
        st.success("Spider concluido")

    if do_active and not STOP.is_set():
        st.subheader("Scan ATIVO — ataques ao vivo")
        started = S.active_scan(origin, confirm=True)
        sid = started.get("scan_id")
        if sid is None:
            st.warning(started.get("message") or started)
        else:
            run_active_feed(sid)
        st.success("Scan ativo concluido")

    st.subheader("Alertas")
    alerts = S.get_alerts(min_risk=min_risk, base_url=origin)
    groups = alerts.get("groups", [])
    if groups:
        st.table([{"Risco": g["risk"], "Alerta": g["name"], "Qtd": g["count"]} for g in groups])
    else:
        st.write("Nenhum alerta no risco escolhido.")

    st.subheader("Endpoints capturados")
    # sem 'site': agrega todos os hosts autorizados (SPA + backend em origens diferentes).
    # Retry curto: logo apos o scan o ZAP as vezes devolve a lista vazia por um instante.
    summary = {}
    for _ in range(3):
        summary = S.get_urls()
        if summary.get("endpoints") or summary.get("pages"):
            break
        time.sleep(1.5)
    if "error" in summary:
        st.error(f"Falha ao ler as URLs do ZAP: {summary['error']}")
    endpoints = summary.get("endpoints", [])
    pages = summary.get("pages", [])
    hosts = sorted({origin_of(e["url"]) for e in endpoints + pages})
    st.write(f"**{len(endpoints)}** endpoint(s) de API · **{summary.get('total_urls', 0)}** "
             f"URLs no total · {len(hosts)} host(s): " + (", ".join(hosts) or "-"))
    tab_api, tab_all = st.tabs(["Endpoints de API", "Todas as URLs"])
    with tab_api:
        if endpoints:
            st.dataframe([{"URL": e["url"], "Com parametros": e["has_params"]}
                          for e in endpoints], use_container_width=True)
        else:
            st.write("Nenhum endpoint de API.")
    with tab_all:
        st.dataframe([{"URL": e["url"], "API": e["is_api"]} for e in endpoints + pages],
                     use_container_width=True)

    report = S.generate_report(report_fmt)
    if "path" in report:
        st.success(f"Relatorio gerado: {report['path']}")
        st.write("Por risco:", report.get("by_risk"))
    else:
        st.warning(report)
