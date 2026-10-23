"""Auto-explorador: dirige um navegador real pelo proxy do ZAP.

O objetivo e exercitar o app (SPA) para que todo o trafego (navegacao + XHR +
OData/REST) passe pelo ZAP e fique registrado. Depois, get_urls/get_alerts do
MCP leem tudo isso. E a ideia de "testes E2E como spider", no modo agressivo.

AVISO: no modo agressivo ele CLICA em tudo (menos logout). Use so em instancia
de staging/descartavel - num app com dados reais isso pode criar/alterar/apagar.
"""
from __future__ import annotations

import asyncio
import os
import sys
import time
from urllib.parse import urlparse

# textos que NAO devem ser clicados: encerram a sessao OU apagam dados. O modo
# agressivo clica para descobrir endpoints, mas deletar em massa destruiria a staging
# (e o endpoint de exclusao ja aparece ao abrir a tela de detalhe/lista).
_SKIP_TEXT = (
    "logout", "sair", "sign out", "log out", "encerrar sessao", "deslogar",
    "excluir", "remover", "apagar", "deletar", "delete",
)

# elementos clicaveis (inclui controles do SAPUI5 e os itens do menu lateral sap.tnt)
_CLICKABLE = (
    "a[href], button, [role=button], [role=menuitem], [role=menuitemradio], [role=tab], "
    ".sapMBtn, .sapMLIB, .sapMStdTile, .sapMObjLItem, .sapMListModeMultiSelect, "
    ".sapTntNLI, .sapTntNLIText, "
    "[tabindex]:not([tabindex='-1'])"
)


# modais que BLOQUEIAM e precisam ser fechados antes do proximo clique. Popover NAO
# entra aqui de proposito: os grupos do menu lateral (Atividades, Cadastros...) abrem
# um popover com os subitens, que o explorador PRECISA clicar — fecha-lo mataria o menu.
_OVERLAY = (
    ".sapMDialog, .sapMMessageBox, .sapMMessageDialog, "
    "[role=alertdialog]"
)
# botoes que FECHAM sem confirmar nada (nunca Salvar/Confirmar/OK de uma pergunta)
_CLOSE_TEXT = ("Cancelar", "Fechar", "Voltar", "Não", "Nao", "Cancel", "Close", "No")


async def _open_overlays(page) -> list:
    found = []
    for el in await page.query_selector_all(_OVERLAY):
        try:
            if await el.is_visible():
                found.append(el)
        except Exception:
            continue
    return found


async def _settle(page, idle_ms: int = 3000, pause_ms: int = 700) -> None:
    """Espera a tela assentar: rede ociosa + uma pausa para a animacao do UI5.

    O teto de rede ociosa e curto de proposito: o UI5 quase nunca fica 100% parado
    (polling), entao um teto alto vira espera cheia em todo clique."""
    try:
        await page.wait_for_load_state("networkidle", timeout=idle_ms)
    except Exception:
        pass
    await page.wait_for_timeout(pause_ms)


async def _close_overlays(page, tries: int = 4) -> bool:
    """Fecha o modal/popover de cima, um de cada vez. True se nao sobrou nenhum."""
    for _ in range(tries):
        overlays = await _open_overlays(page)
        if not overlays:
            return True
        top = overlays[-1]  # o ultimo no DOM e o que esta por cima
        closed = False
        for label in _CLOSE_TEXT:
            try:
                btn = await top.query_selector(f"button:has-text('{label}')")
                if btn and await btn.is_visible():
                    await btn.click(timeout=2000)
                    closed = True
                    break
            except Exception:
                continue
        if not closed:
            try:
                await page.keyboard.press("Escape")
            except Exception:
                pass
        await _settle(page, idle_ms=3000, pause_ms=500)
    return not await _open_overlays(page)


async def expand_sidenav(page) -> bool:
    """Abre o menu lateral recolhido (so icones) no botao ☰ do cabecalho, para os
    rotulos e subitens aparecerem. Best-effort: o menu recolhido tambem e clicavel."""
    for sel in (
        ".sapTntToolHeader button[title*='Menu' i]",
        "button[aria-label*='Menu' i]",
        ".sapTntToolHeader .sapMBtn",
        "button:has(.sapUiIcon[data-sap-ui-icon-content])",
    ):
        try:
            btn = page.locator(sel).first
            if await btn.is_visible(timeout=1500):
                await btn.click(timeout=2000)
                await _settle(page, idle_ms=2000, pause_ms=400)
                if await page.locator(".sapTntNL:not(.sapTntNLCollapsed)").count():
                    return True
        except Exception:
            continue
    return bool(await page.locator(".sapTntNL:not(.sapTntNLCollapsed)").count())


async def select_company(page, company: str = "") -> str:
    """Passa da tela 'Empresas Vinculadas ao Usuario' (aparece depois do login).

    O sistema so abre depois de escolher uma linha da tabela e clicar em Selecionar
    (que nasce desabilitado). Sem isso o explorador ficava do lado de fora, sem
    menu lateral. Escolhe a empresa pelo nome, ou a primeira da lista.
    """
    try:
        btn = page.locator("button:has-text('Selecionar')").first
        if not await btn.is_visible(timeout=2000):
            return "sem tela de empresa"
    except Exception:
        return "sem tela de empresa"
    rows = page.locator("tbody tr, .sapMListTblRow, [role=row]")
    target_row = None
    try:
        count = await rows.count()
        for i in range(count):
            row = rows.nth(i)
            txt = ((await row.inner_text()) or "").strip()
            if not txt or "Quantidade de Filiais" in txt:  # cabecalho
                continue
            if not company or company.lower() in txt.lower():
                target_row = row
                break
    except Exception:
        pass
    if target_row is None:
        return "empresa nao encontrada na lista"
    try:
        # clica na celula do nome (a 1a), longe dos botoes de editar/imagem da linha
        cell = target_row.locator("td, [role=gridcell]").first
        await (cell if await cell.count() else target_row).click(timeout=3000)
        await _settle(page)
        await btn.click(timeout=3000)
        await _settle(page, idle_ms=6000, pause_ms=1500)
    except Exception as exc:
        return f"falha ao selecionar empresa: {exc}"
    # Entrou = apareceu o menu lateral do sistema. Nao da para olhar o botao
    # Selecionar: a tela seguinte (opcoes da filial) tem outro com o mesmo texto.
    for _ in range(10):
        try:
            if await page.locator(".sapTntSideNavigation").first.is_visible():
                return "empresa selecionada"
        except Exception:
            pass
        await page.wait_for_timeout(500)
    return "menu lateral nao apareceu (empresa nao entrou)"


async def _visible_pwd(page):
    for el in await page.query_selector_all("input[type=password]"):
        try:
            if await el.is_visible():
                return el
        except Exception:
            continue
    return None


async def try_login(page, username: str, password: str) -> tuple[bool, str]:
    """Abre a tela de login (se preciso), preenche usuario/senha e submete."""
    pwd = await _visible_pwd(page)
    if pwd is None:
        # a landing provavelmente tem um botao/link "Login/Entrar/Acessar"
        for sel in ("a:has-text('Login')", "button:has-text('Login')",
                    "a:has-text('Entrar')", "button:has-text('Entrar')",
                    "a:has-text('Acessar')", "button:has-text('Acessar')",
                    "a:has-text('Acesso')", "button:has-text('Acesso')",
                    "[href*='login' i]", ".sapMBtn:has-text('Entrar')"):
            try:
                b = await page.query_selector(sel)
                if b and await b.is_visible():
                    await b.click()
                    await page.wait_for_load_state("networkidle", timeout=8000)
                    break
            except Exception:
                continue
        for _ in range(12):
            pwd = await _visible_pwd(page)
            if pwd:
                break
            await page.wait_for_timeout(700)
    if pwd is None:
        types, btns = [], []
        for el in await page.query_selector_all("input"):
            try:
                types.append((await el.get_attribute("type")) or "text")
            except Exception:
                continue
        for el in await page.query_selector_all("button, a"):
            try:
                if await el.is_visible():
                    t = ((await el.inner_text()) or "").strip()
                    if t:
                        btns.append(t[:30])
            except Exception:
                continue
        return False, f"senha nao encontrada | inputs={types[:8]} | botoes={btns[:12]}"

    user_el = None
    for el in await page.query_selector_all("input"):
        try:
            t = (await el.get_attribute("type") or "text").lower()
            if t in ("text", "email") and await el.is_visible():
                user_el = el
                break
        except Exception:
            continue
    if user_el is None:
        return False, "campo de usuario nao encontrado"
    try:
        await user_el.fill(username)
        await pwd.fill(password)
    except Exception as exc:
        return False, f"falha ao preencher: {exc}"
    clicked = False
    for sel in ("button:has-text('Entrar')", "button:has-text('Login')",
                "button:has-text('Acessar')", "button:has-text('Sign in')"):
        try:
            btn = await page.query_selector(sel)
            if btn and await btn.is_visible():
                await btn.click()
                clicked = True
                break
        except Exception:
            continue
    if not clicked:
        try:
            await pwd.press("Enter")
        except Exception:
            pass
    try:
        await page.wait_for_load_state("networkidle", timeout=15000)
    except Exception:
        pass
    # o SPA demora para trocar de tela depois do login: espera o form sumir antes de
    # concluir que falhou (antes checava na hora e dava falso negativo)
    for _ in range(20):
        if await _visible_pwd(page) is None:
            return True, "login submetido"
        await page.wait_for_timeout(500)
    return False, "login nao confirmado (form ainda visivel)"


def _route_base(pattern: str) -> str:
    """Prefixo estatico de uma rota UI5 (ate o 1o segmento com parametro).

    No UI5 ':id:' e parametro OPCIONAL: 'userList/:id:' pode ser aberto como
    'userList' (sem id) e mostra a LISTA — e e justamente a lista que dispara o
    GET da entidade (/v1/User, /v1/Employee...). Antes pulavamos toda rota com
    ':' e perdiamos metade das entidades. Aqui cortamos o parametro e visitamos
    a lista. 'passwordRecovery/?:email:' -> 'passwordRecovery'; ':id:' -> ''.
    """
    out: list[str] = []
    for seg in pattern.split("/"):
        if any(c in seg for c in ":{*?"):
            break
        out.append(seg)
    return "/".join(out)


async def sweep_ui5_routes(page, app_root: str, stopped=lambda: False) -> tuple[list, list]:
    """Le as rotas do manifest.json do UI5 e visita o prefixo estatico de cada uma.

    Navegar #/<rota> faz o UI5 montar a tela e disparar suas chamadas, que o
    ZAP registra — cobertura deterministica, nao dependente de clique.
    """
    manifest = await page.evaluate(
        "async (u) => { try { const r = await fetch(u);"
        " if (!r.ok) return null; return await r.json(); } catch (e) { return null; } }",
        app_root + "/manifest.json",
    )
    patterns: list[str] = []
    try:
        routing = (((manifest or {}).get("sap.ui5") or {}).get("routing") or {})
        for r in routing.get("routes") or []:
            pat = r.get("pattern")
            if isinstance(pat, str):
                patterns.append(pat)
    except Exception:
        pass
    # prefixos estaticos unicos (inclui as listas atras de parametro opcional)
    bases: list[str] = []
    seen: set[str] = set()
    for pat in patterns:
        base = _route_base(pat)
        if base and base not in seen:
            seen.add(base)
            bases.append(base)
    visited: list[str] = []
    for base in bases:
        if stopped():
            break
        try:
            await page.evaluate("(h) => { window.location.hash = h; }", "#/" + base)
            await page.wait_for_load_state("networkidle", timeout=6000)
            visited.append(base)
        except Exception:
            continue
    return patterns, visited


async def explore(target: str, proxy: str, max_seconds: float, max_actions: int,
                  username: str = "", password: str = "",
                  headless: bool = True, route_sweep: bool = True,
                  should_stop=None, company: str = "", crud: bool = False) -> dict:
    # Sinal de parada vindo de fora (botao Parar do painel): conferido a cada passo.
    def stopped() -> bool:
        try:
            return bool(should_stop and should_stop())
        except Exception:
            return False

    from playwright.async_api import async_playwright

    from .crud import crud_screen

    requests: list[tuple[str, str]] = []
    host = urlparse(target).netloc
    clicked: set[tuple] = set()
    actions = 0
    crud_report: list[dict] = []

    async with async_playwright() as p:
        # --proxy-bypass-list=<-loopback> forca o Chromium a mandar tambem
        # localhost/127.0.0.1 para o proxy do ZAP (por padrao ele faz bypass).
        browser = await p.chromium.launch(
            headless=headless, args=["--proxy-bypass-list=<-loopback>"]
        )
        ctx = await browser.new_context(
            proxy={"server": proxy},
            ignore_https_errors=True,
            extra_http_headers={"X-Tunnel-Skip-AntiPhishing-Page": "true"},
        )
        # window.open abre uma janela por clique (SAPUI5 usa para links externos) — era a
        # fonte da "sobrecarga de telas". Forcamos a navegacao na mesma aba.
        await ctx.add_init_script(
            "window.open = function(u){ try { if (u) location.href = u; } catch(e){} return null; };"
        )

        # Captura em nivel de CONTEXTO: pega os requests de TODAS as paginas (popups) e de
        # todos os frames/iframes, nao so da aba principal — senao perdemos endpoints do SPA.
        ctx.on("request", lambda r: requests.append((r.method, r.url)))
        login_ok = {"v": False}

        def _on_resp(r):
            try:
                if "authentication/login" in r.url.lower() and r.status == 200:
                    login_ok["v"] = True
            except Exception:
                pass

        ctx.on("response", _on_resp)

        page = await ctx.new_page()
        main_page = page

        # Popups/novas abas sobrecarregam o sistema (uma janela por clique) e desviam o
        # explorador da aba principal. O trafego do popup ja passou pelo proxy do ZAP (e foi
        # capturado acima pelo ctx), entao damos um respiro para as chamadas sairem e fechamos.
        async def _close_popup(p):
            try:
                await p.wait_for_timeout(1500)
            except Exception:
                pass
            try:
                if p is not main_page and not p.is_closed():
                    await p.close()
            except Exception:
                pass

        ctx.on("page", lambda p: asyncio.create_task(_close_popup(p)))

        async def goto_base():
            try:
                await page.goto(target, wait_until="domcontentloaded", timeout=30000)
                await page.wait_for_load_state("networkidle", timeout=12000)
            except Exception:
                pass
            # Dev Tunnels: pular a pagina anti-phishing ("Continue")
            try:
                btn = await page.query_selector("button:has-text('Continue'), a:has-text('Continue')")
                if btn and await btn.is_visible():
                    body = ((await page.inner_text("body")) or "").lower()
                    if "report unsafe page" in body or "tunnel" in body:
                        await btn.click()
                        await page.wait_for_load_state("networkidle", timeout=12000)
            except Exception:
                pass

        await goto_base()
        title = await page.title()

        login_status = "sem credenciais"
        # sem credenciais a app pode ser publica: seguimos como "logado" para varrer as rotas.
        logged_in = not (username and password)
        if username and password:
            ok, login_status = await try_login(page, username, password)
            await page.wait_for_timeout(2000)
            if login_ok["v"]:
                login_status = "login ok (200)"
            # Confirmado pelo backend (200), OU o try_login reportou sucesso, OU o campo de
            # senha sumiu depois de submeter: qualquer um conta como logado. Antes, so o 200
            # liberava a varredura, e quando ele nao casava o SPA inteiro ficava sem explorar.
            logged_in = login_ok["v"] or ok or (await _visible_pwd(page) is None)
            if logged_in:
                # depois do login vem a tela de empresas: sem passar por ela o sistema
                # (e o menu lateral) nunca abre
                company_status = await select_company(page, company)
                login_status = f"{login_status} | {company_status}"

        if logged_in:
            await expand_sidenav(page)

        routes_found, routes_visited = [], []
        if route_sweep and logged_in:
            app_root = f"{urlparse(target).scheme}://{urlparse(target).netloc}"
            routes_found, routes_visited = await sweep_ui5_routes(page, app_root, stopped)

        async def candidates():
            found = []
            try:
                els = await page.query_selector_all(_CLICKABLE)
            except Exception:
                return found
            for el in els:
                try:
                    if not await el.is_visible():
                        continue
                    txt = ((await el.inner_text()) or "").strip()[:48]
                    if any(s in txt.lower() for s in _SKIP_TEXT):
                        continue
                    box = await el.bounding_box()
                    sig = (txt, (int(box["x"]), int(box["y"])) if box else None)
                    found.append((sig, el))
                except Exception:
                    continue
            return found

        async def goto_route(pat: str):
            try:
                await page.evaluate("(h) => { window.location.hash = h; }", "#/" + pat)
                await page.wait_for_load_state("networkidle", timeout=6000)
            except Exception:
                pass

        # Pontos de partida do clicker: cada tela que a varredura abriu (home + as listas
        # das entidades). Antes o clicker rodava uma vez so, logo apos a varredura, que
        # deixava a pagina parada na ultima rota (muitas vezes vazia) — dava 0 acoes. Agora
        # ele parte de cada lista e clica as linhas, abrindo as telas de DETALHE, que e onde
        # estao os endpoints mais ricos (e os POST/PUT atras dos botoes).
        seeds: list = list(routes_visited) if routes_visited else ["home"]
        if logged_in and "home" not in seeds:
            seeds = ["home"] + seeds
        if not logged_in:
            seeds = [None]  # sem login: explora a propria landing, sem navegar por hash

        # Parado tempo demais na mesma tela, sem trafego novo -> da um "voltar" e segue.
        # Evita ficar preso num detalhe/modal que nao gera mais requests.
        stall_limit = max(12.0, min(30.0, max_seconds / 6))

        deadline = time.time() + max_seconds
        for seed in seeds:
            if time.time() > deadline or actions >= max_actions or stopped():
                break
            if seed is not None:
                await goto_route(seed)
            await _settle(page)
            last_url = page.url
            reqs_mark = len(requests)
            last_activity = time.time()
            # Um item por vez: fecha o que estiver aberto, rele a tela, clica UM item
            # ainda nao visitado, espera assentar e fecha o modal que ele abriu. Antes
            # clicava a lista inteira de uma vez (lida antes do primeiro clique) e ia
            # atropelando modais abertos, abrindo tudo por cima.
            while time.time() < deadline and actions < max_actions and not stopped():
                if not await _close_overlays(page):
                    # modal que nao fecha (sem Cancelar e sem Esc): sai da tela
                    try:
                        await page.go_back(wait_until="networkidle", timeout=8000)
                    except Exception:
                        pass
                    break
                nxt = next(((s, e) for s, e in await candidates() if s not in clicked), None)
                if nxt is None:
                    break  # nada novo nesta tela: proxima semente
                sig, el = nxt
                clicked.add(sig)
                try:
                    await el.click(timeout=2500)
                except Exception:
                    continue
                actions += 1
                await _settle(page)
                # abriu um modal: da tempo dele carregar (e disparar as chamadas) e fecha
                if await _open_overlays(page):
                    await _settle(page, pause_ms=1000)
                    await _close_overlays(page)
                # houve atividade? (mudou de tela ou gerou requests novos)
                if page.url != last_url or len(requests) != reqs_mark:
                    last_url = page.url
                    reqs_mark = len(requests)
                    last_activity = time.time()
                # saiu do host (link externo): volta sem deslogar quando autenticado
                try:
                    if host not in urlparse(page.url).netloc:
                        if logged_in:
                            await page.go_back(wait_until="networkidle", timeout=8000)
                        else:
                            await goto_base()
                        await _settle(page)
                except Exception:
                    pass
                # travado na mesma tela ha tempo demais: volta e passa pra proxima
                if time.time() - last_activity > stall_limit:
                    try:
                        await page.go_back(wait_until="networkidle", timeout=8000)
                    except Exception:
                        pass
                    break

            # CRUD: depois de explorar a tela, exercita create/view/edit/delete nela
            # (dispara POST/PUT/DELETE — os endpoints de escrita). So com crud=True.
            if crud and logged_in and seed is not None and not stopped():
                if seed is not None:
                    await goto_route(seed)
                    await _settle(page)
                try:
                    res_crud = await crud_screen(page, requests, host,
                                                 _settle, _close_overlays)
                    crud_report.append({"tela": seed, **res_crud})
                except Exception as exc:  # noqa: BLE001
                    crud_report.append({"tela": seed, "erro": str(exc)[:120]})

        await browser.close()

    uniq = sorted({(m, u.split("?", 1)[0]) for (m, u) in requests if host in urlparse(u).netloc})
    return {
        "target": target,
        "page_title": title,
        "login_status": login_status,
        "actions": actions,
        "requests_total": len(requests),
        "routes_found": len(routes_found),
        "routes_visited": routes_visited,
        "endpoints_host": uniq,
        "stopped": stopped(),
        "crud": crud_report,
    }


def main() -> None:
    target = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("EXPLORE_TARGET", "")
    if not target:
        print("uso: python -m zap_mcp.explorer <url> [max_seconds] [max_actions]")
        raise SystemExit(2)
    proxy = os.environ.get("ZAP_BASE_URL", "http://localhost:8080")
    max_seconds = float(sys.argv[2]) if len(sys.argv) > 2 else 120.0
    max_actions = int(sys.argv[3]) if len(sys.argv) > 3 else 200
    username = os.environ.get("EXPLORE_USER", "")
    password = os.environ.get("EXPLORE_PASS", "")
    headless = os.environ.get("EXPLORE_HEADLESS", "1") != "0"
    result = asyncio.run(explore(target, proxy, max_seconds, max_actions,
                                 username, password, headless=headless))
    print("titulo:", result["page_title"], "| login:", result["login_status"])
    print("rotas UI5:", result.get("routes_found", 0),
          "| visitadas:", len(result.get("routes_visited", [])))
    print("acoes:", result["actions"], "| requests:", result["requests_total"],
          "| endpoints unicos (host):", len(result["endpoints_host"]))
    for method, url in result["endpoints_host"][:80]:
        print("  ", method, url)


if __name__ == "__main__":
    main()
