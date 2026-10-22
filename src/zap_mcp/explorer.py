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

# textos que NAO devem ser clicados (encerram a sessao)
_SKIP_TEXT = ("logout", "sair", "sign out", "log out", "encerrar sessao", "deslogar")

# elementos clicaveis (inclui controles do SAPUI5)
_CLICKABLE = (
    "a[href], button, [role=button], [role=menuitem], [role=tab], "
    ".sapMBtn, .sapMLIB, .sapMStdTile, .sapMObjLItem, .sapMListModeMultiSelect, "
    "[tabindex]:not([tabindex='-1'])"
)


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
    if await _visible_pwd(page) is not None:
        return False, "login nao confirmado (form ainda visivel)"
    return True, "login submetido"


async def sweep_ui5_routes(page, app_root: str) -> tuple[list, list]:
    """Le as rotas do manifest.json do UI5 e visita cada uma (sem parametro).

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
    visited: list[str] = []
    for pat in patterns:
        if any(c in pat for c in "{:*"):  # precisa de parametro: pula na v1
            continue
        try:
            await page.evaluate("(h) => { window.location.hash = h; }", "#/" + pat)
            await page.wait_for_load_state("networkidle", timeout=6000)
            visited.append(pat)
        except Exception:
            continue
    return patterns, visited


async def explore(target: str, proxy: str, max_seconds: float, max_actions: int,
                  username: str = "", password: str = "") -> dict:
    from playwright.async_api import async_playwright

    requests: list[tuple[str, str]] = []
    host = urlparse(target).netloc
    clicked: set[tuple] = set()
    actions = 0

    async with async_playwright() as p:
        # --proxy-bypass-list=<-loopback> forca o Chromium a mandar tambem
        # localhost/127.0.0.1 para o proxy do ZAP (por padrao ele faz bypass).
        browser = await p.chromium.launch(
            headless=True, args=["--proxy-bypass-list=<-loopback>"]
        )
        ctx = await browser.new_context(
            proxy={"server": proxy},
            ignore_https_errors=True,
            extra_http_headers={"X-Tunnel-Skip-AntiPhishing-Page": "true"},
        )
        page = await ctx.new_page()
        page.on("request", lambda r: requests.append((r.method, r.url)))
        login_ok = {"v": False}

        def _on_resp(r):
            try:
                if "authentication/login" in r.url.lower() and r.status == 200:
                    login_ok["v"] = True
            except Exception:
                pass

        page.on("response", _on_resp)

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
        if username and password:
            ok, login_status = await try_login(page, username, password)
            await page.wait_for_timeout(2000)
            if login_ok["v"]:
                login_status = "login ok (200)"
                # selecao de empresa, se o app pedir
                for sel in (".sapMDialog .sapMLIB", ".sapMList .sapMLIB", ".sapMLIB"):
                    try:
                        item = await page.query_selector(sel)
                        if item and await item.is_visible():
                            await item.click()
                            await page.wait_for_load_state("networkidle", timeout=8000)
                            break
                    except Exception:
                        continue
                await page.wait_for_timeout(1500)

        routes_found, routes_visited = [], []
        if login_ok["v"]:
            app_root = f"{urlparse(target).scheme}://{urlparse(target).netloc}"
            routes_found, routes_visited = await sweep_ui5_routes(page, app_root)

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

        deadline = time.time() + max_seconds
        passes = 0
        while time.time() < deadline and actions < max_actions:
            progressed = False
            for sig, el in await candidates():
                if sig in clicked:
                    continue
                clicked.add(sig)
                progressed = True
                try:
                    await el.click(timeout=2500)
                    await page.wait_for_load_state("networkidle", timeout=7000)
                except Exception:
                    pass
                actions += 1
                # se saiu do host, volta (sem deslogar quando ja autenticado)
                try:
                    if host not in urlparse(page.url).netloc:
                        if login_ok["v"]:
                            await page.go_back(wait_until="networkidle", timeout=8000)
                        else:
                            await goto_base()
                except Exception:
                    pass
                if time.time() > deadline or actions >= max_actions:
                    break
            passes += 1
            if not progressed:
                # logado: nao volta pra raiz (deslogaria); so encerra
                if passes > 2 or login_ok["v"]:
                    break
                await goto_base()

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
    result = asyncio.run(explore(target, proxy, max_seconds, max_actions, username, password))
    print("titulo:", result["page_title"], "| login:", result["login_status"])
    print("rotas UI5:", result.get("routes_found", 0),
          "| visitadas:", len(result.get("routes_visited", [])))
    print("acoes:", result["actions"], "| requests:", result["requests_total"],
          "| endpoints unicos (host):", len(result["endpoints_host"]))
    for method, url in result["endpoints_host"][:80]:
        print("  ", method, url)


if __name__ == "__main__":
    main()
