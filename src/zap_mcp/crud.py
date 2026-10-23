"""Passo de CRUD: exercita Create/View/Edit/Delete em cada tela de lista.

O explorador normal so clica (GET de leitura). Aqui a gente preenche formulario e
dispara as operacoes de escrita, que e onde estao os endpoints POST/PUT/DELETE.

AVISO: cria, altera e APAGA registros de verdade. Use so em base de teste.
"""
from __future__ import annotations

import time
from urllib.parse import urlparse

# botoes que ABREM o formulario de criar
_CREATE_TEXT = ("Novo", "Nova", "Adicionar", "Incluir", "Criar", "Cadastrar", "Registrar")
# botoes que SALVAM o formulario
_SAVE_TEXT = ("Salvar", "Gravar", "Confirmar", "Criar", "Adicionar", "Cadastrar", "OK", "Concluir")
# confirmacao de exclusao
_CONFIRM_TEXT = ("Sim", "Confirmar", "Excluir", "Remover", "OK", "Deletar", "Apagar")
# acoes por linha (icones/titulos)
_EDIT_SEL = ("[title*='Editar' i]", "[aria-label*='Editar' i]", "button:has(.sapUiIcon)")
_DELETE_SEL = ("[title*='Excluir' i]", "[title*='Remover' i]", "[aria-label*='Excluir' i]",
               "[aria-label*='Remover' i]")


def _stamp() -> str:
    return time.strftime("%H%M%S")


async def fill_form(page, prefix: str = "QA") -> int:
    """Preenche, do jeito possivel, os campos visiveis do formulario aberto.

    Melhor esforco: texto em campo de texto, numero em numerico, data valida,
    primeira opcao em select. Devolve quantos campos preencheu."""
    filled = 0
    value = f"{prefix}-teste-{_stamp()}"

    # inputs padrao e inner do UI5
    inputs = await page.query_selector_all(
        "input:not([type=hidden]):not([type=checkbox]):not([type=radio]):not([type=file])"
        ":not([type=password]):not([readonly]):not([disabled])")
    for el in inputs:
        try:
            if not await el.is_visible():
                continue
            typ = (await el.get_attribute("type") or "text").lower()
            cur = await el.input_value()
            if cur:  # ja tem valor (nao sobrescreve)
                continue
            if typ in ("number",):
                await el.fill("1")
            elif typ in ("date",):
                await el.fill("2026-10-22")
            elif typ in ("email",):
                await el.fill(f"{prefix.lower()}.teste@example.com")
            elif typ in ("tel",):
                await el.fill("11999990000")
            else:
                ph = (await el.get_attribute("placeholder") or "").lower()
                if "data" in ph or "/" in ph:
                    await el.fill("22/10/2026")
                elif "mail" in ph:
                    await el.fill(f"{prefix.lower()}.teste@example.com")
                else:
                    await el.fill(value)
            filled += 1
        except Exception:
            continue

    # textarea
    for el in await page.query_selector_all("textarea:not([readonly]):not([disabled])"):
        try:
            if await el.is_visible() and not await el.input_value():
                await el.fill(value)
                filled += 1
        except Exception:
            continue

    # selects HTML e UI5 (sap.m.Select abre uma lista)
    for el in await page.query_selector_all("select:not([disabled])"):
        try:
            if await el.is_visible():
                opts = await el.query_selector_all("option")
                for o in opts:
                    v = await o.get_attribute("value")
                    if v:
                        await el.select_option(value=v)
                        filled += 1
                        break
        except Exception:
            continue
    for el in await page.query_selector_all(".sapMSlt:not(.sapMSltDsbl)"):
        try:
            if not await el.is_visible():
                continue
            await el.click(timeout=1500)
            await page.wait_for_timeout(400)
            item = await page.query_selector(".sapMSltPicker li, .sapMSelectList li")
            if item and await item.is_visible():
                await item.click(timeout=1500)
                filled += 1
        except Exception:
            continue

    return filled


async def _click_text(page, scope, texts, timeout=2000) -> bool:
    for t in texts:
        try:
            btn = (scope or page).locator(f"button:has-text('{t}'), a:has-text('{t}')").first
            if await btn.is_visible(timeout=timeout):
                await btn.click(timeout=timeout)
                return True
        except Exception:
            continue
    return False


async def _requests_since(requests, mark, host) -> dict:
    """Metodos de escrita capturados desde 'mark' (no host do alvo)."""
    out = {"POST": 0, "PUT": 0, "PATCH": 0, "DELETE": 0}
    for method, url in requests[mark:]:
        if method in out and host in urlparse(url).netloc:
            out[method] += 1
    return out


async def crud_screen(page, requests, host, settle, close_overlays) -> dict:
    """Roda um ciclo de CRUD na tela atual. Devolve o que cada operacao disparou."""
    result = {"create": None, "view": None, "edit": None, "delete": None,
              "campos_preenchidos": 0}

    # -------- CREATE --------
    mark = len(requests)
    if await _click_text(page, None, _CREATE_TEXT):
        await settle(page)
        result["campos_preenchidos"] = await fill_form(page)
        await _click_text(page, None, _SAVE_TEXT)
        await settle(page, pause_ms=1200)
        await close_overlays(page)
        w = await _requests_since(requests, mark, host)
        result["create"] = "ok" if (w["POST"] or w["PUT"]) else "sem POST (validacao?)"

    # -------- VIEW (clica a 1a linha) --------
    mark = len(requests)
    try:
        row = page.locator(".sapMLIB, tbody tr, [role=row]").first
        if await row.is_visible(timeout=1500):
            await row.click(timeout=2000)
            await settle(page)
            g = sum(1 for m, u in requests[mark:] if m == "GET" and host in urlparse(u).netloc)
            result["view"] = f"{g} GET" if g else "sem request"
    except Exception:
        pass

    # -------- EDIT (icone de editar da 1a linha) --------
    mark = len(requests)
    edited = False
    for sel in _EDIT_SEL:
        try:
            btn = page.locator(sel).first
            if await btn.is_visible(timeout=1200):
                await btn.click(timeout=2000)
                await settle(page)
                if await page.locator("input:not([type=hidden]), textarea").count():
                    await fill_form(page, prefix="QAedit")
                    await _click_text(page, None, _SAVE_TEXT)
                    await settle(page, pause_ms=1200)
                    await close_overlays(page)
                    edited = True
                    break
        except Exception:
            continue
    if edited:
        w = await _requests_since(requests, mark, host)
        result["edit"] = "ok" if (w["PUT"] or w["PATCH"] or w["POST"]) else "sem PUT"

    # -------- DELETE (icone de excluir da 1a linha + confirmar) --------
    mark = len(requests)
    deleted = False
    for sel in _DELETE_SEL:
        try:
            btn = page.locator(sel).first
            if await btn.is_visible(timeout=1200):
                await btn.click(timeout=2000)
                await settle(page, pause_ms=800)
                await _click_text(page, None, _CONFIRM_TEXT)  # dialogo de confirmacao
                await settle(page, pause_ms=1200)
                deleted = True
                break
        except Exception:
            continue
    if deleted:
        w = await _requests_since(requests, mark, host)
        result["delete"] = "ok" if w["DELETE"] else "sem DELETE"

    return result
