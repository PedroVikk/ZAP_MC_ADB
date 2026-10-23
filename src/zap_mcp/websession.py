"""Captura uma sessao autenticada uma vez e deixa OData e Nuclei reusarem.

Entrar num SAPUI5 na mao (copiar cookie + CSRF do devtools) e chato e expira
rapido. Aqui a gente reaproveita o login que o explorador ja faz (Playwright):
abre a tela, loga com usuario/senha, passa a tela de empresa (se houver) e
guarda os cookies. Depois o OData e o Nuclei mandam esses cookies sozinhos — sem
colar nada. Tudo passa pelo proxy do ZAP, entao o ZAP tambem ve o login.
"""
from __future__ import annotations


async def capture(login_url: str, proxy: str, username: str, password: str,
                  company: str = "", headless: bool = True) -> dict:
    """Loga via Playwright e devolve os cookies da sessao (header pronto).

    Reusa try_login/select_company do explorador. Nao levanta: em falha, devolve
    ok=False com o motivo. O cookie_header so e util se ok (ou se ja havia
    cookies de sessao mesmo sem confirmar a troca de tela).
    """
    from playwright.async_api import async_playwright

    from .explorer import _settle, select_company, try_login

    result = {"ok": False, "login_status": "", "company_status": "",
              "cookie_header": "", "cookie_names": [], "cookie_count": 0}
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=headless, args=["--proxy-bypass-list=<-loopback>"])
        ctx = await browser.new_context(
            proxy={"server": proxy}, ignore_https_errors=True,
            extra_http_headers={"X-Tunnel-Skip-AntiPhishing-Page": "true"})
        try:
            page = await ctx.new_page()
            await page.goto(login_url, wait_until="domcontentloaded", timeout=30000)
            await _settle(page)
            ok, status = await try_login(page, username, password)
            result["login_status"] = status
            result["ok"] = ok
            if ok:
                await _settle(page)
                result["company_status"] = await select_company(page, company)
            cookies = await ctx.cookies()
        except Exception as exc:  # noqa: BLE001 - fronteira do Playwright
            result["login_status"] = f"erro: {type(exc).__name__}: {exc}"
            cookies = []
        finally:
            await browser.close()

    result["cookie_count"] = len(cookies)
    result["cookie_names"] = sorted({c.get("name", "") for c in cookies if c.get("name")})
    result["cookie_header"] = "; ".join(
        f"{c['name']}={c['value']}" for c in cookies if c.get("name"))
    return result
