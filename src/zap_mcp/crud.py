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
# botoes que AVANCAM um wizard (passo a passo) — tela "Passo 1 de 2" etc.
_NEXT_TEXT = ("Seguinte", "Proximo", "Próximo", "Avancar", "Avançar", "Continuar", "Next")
# botoes que SALVAM/CONCLUEM o formulario (ultimo passo do wizard, ou form simples)
_SAVE_TEXT = ("Salvar", "Gravar", "Confirmar", "Concluir", "Finalizar", "Criar",
              "Adicionar", "Cadastrar", "Finish", "OK")
# confirmacao de exclusao
_CONFIRM_TEXT = ("Sim", "Confirmar", "Excluir", "Remover", "OK", "Deletar", "Apagar")
# acoes por linha (icones/titulos)
_EDIT_SEL = ("[title*='Editar' i]", "[aria-label*='Editar' i]", "button:has(.sapUiIcon)")
_DELETE_SEL = ("[title*='Excluir' i]", "[title*='Remover' i]", "[aria-label*='Excluir' i]",
               "[aria-label*='Remover' i]")


def _stamp() -> str:
    return time.strftime("%H%M%S")


def _dv(nums: list[int], weights: list[int]) -> int:
    """Digito verificador (modulo 11) de CPF/CNPJ."""
    r = sum(a * b for a, b in zip(nums, weights)) % 11
    return 0 if r < 2 else 11 - r


def _valid_cnpj() -> str:
    """CNPJ valido (14 digitos, so numeros) — campos que validam o DV aceitam."""
    import random
    n = [random.randint(0, 9) for _ in range(12)]
    d1 = _dv(n, [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2])
    d2 = _dv(n + [d1], [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2])
    return "".join(map(str, n + [d1, d2]))


def _valid_cpf() -> str:
    """CPF valido (11 digitos, so numeros)."""
    import random
    n = [random.randint(0, 9) for _ in range(9)]
    d1 = _dv(n, list(range(10, 1, -1)))
    d2 = _dv(n + [d1], list(range(11, 1, -1)))
    return "".join(map(str, n + [d1, d2]))


async def _hint(page, el) -> str:
    """Pistas do que o campo pede: name/id/placeholder/aria + o <label> ligado a ele.

    E o que deixa a gente preencher CNPJ/CPF/CEP com valor valido (senao o wizard
    nao habilita o 'Seguinte')."""
    parts = []
    for attr in ("name", "id", "placeholder", "aria-label", "data-name"):
        v = await el.get_attribute(attr)
        if v:
            parts.append(v)
    eid = await el.get_attribute("id")
    if eid:
        try:
            lbl = await page.query_selector(f"label[for='{eid}']")
            if lbl:
                parts.append(await lbl.inner_text())
        except Exception:
            pass
    return " ".join(parts).lower()


async def _type_masked(el, digits: str) -> None:
    """Digita digito a digito (com delay) para a mascara do campo rodar — fill()
    seta o valor direto e muitas mascaras (CNPJ/CPF/CEP/telefone) nao disparam."""
    await el.click()
    await el.type(digits, delay=15)


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
            if await el.input_value():  # ja tem valor (nao sobrescreve)
                continue
            typ = (await el.get_attribute("type") or "text").lower()
            hint = await _hint(page, el)
            ph = (await el.get_attribute("placeholder") or "").lower()
            # documentos/campos mascarados: valor valido, digitado para a mascara rodar
            if "cnpj" in hint:
                await _type_masked(el, _valid_cnpj())
            elif "cpf" in hint:
                await _type_masked(el, _valid_cpf())
            elif "cep" in hint:
                await _type_masked(el, "01310100")
            elif typ == "tel" or any(k in hint for k in ("telefone", "fone", "celular", "whats")):
                await _type_masked(el, "11999990000")
            elif typ == "number" or any(k in hint for k in ("valor", "preco", "preço", "quantidade")):
                await el.fill("1")
            elif typ == "date":
                await el.fill("2026-10-22")
            elif typ == "email" or "mail" in hint:
                await el.fill(f"{prefix.lower()}.teste@example.com")
            elif "data" in hint or "data" in ph or "/" in ph:
                await el.fill("22/10/2026")
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


async def _fill_wizard(page, settle, close_overlays, prefix, max_steps=6):
    """Preenche e AVANCA um formulario que pode ser um wizard de varios passos.

    Em cada passo: preenche os campos; se houver botao de proximo (Seguinte/
    Proximo/Avancar...), clica e vai para o proximo passo; senao, clica no de
    concluir/salvar e encerra. Sem isto, o CRUD so procurava 'Salvar' e as telas
    com wizard (sem Salvar no 1o passo) eram ignoradas.

    Devolve (campos_preenchidos, passos_avancados, concluiu)."""
    total_fields = 0
    steps = 0
    finished = False
    for _ in range(max_steps):
        total_fields += await fill_form(page, prefix=prefix)
        if await _click_text(page, None, _NEXT_TEXT):
            steps += 1
            await settle(page, pause_ms=1000)
            continue
        if await _click_text(page, None, _SAVE_TEXT):
            finished = True
            break
        break  # nem proximo nem salvar: para de avancar
    await settle(page, pause_ms=1200)
    await close_overlays(page)
    return total_fields, steps, finished


def _write_label(w: dict, steps: int, finished: bool) -> str:
    """Rotulo do resultado de create/edit a partir do que foi capturado."""
    if w["POST"] or w["PUT"] or w["PATCH"]:
        return "ok" + (f" (wizard, {steps + 1} passos)" if steps else "")
    if steps and not finished:
        return f"wizard parou no passo {steps + 1} (validacao?)"
    return "sem POST (validacao?)"


async def crud_screen(page, requests, host, settle, close_overlays) -> dict:
    """Roda um ciclo de CRUD na tela atual. Devolve o que cada operacao disparou."""
    result = {"create": None, "view": None, "edit": None, "delete": None,
              "campos_preenchidos": 0, "wizard_passos": 0}

    # -------- CREATE (trata wizard de varios passos) --------
    mark = len(requests)
    if await _click_text(page, None, _CREATE_TEXT):
        await settle(page)
        fields, steps, finished = await _fill_wizard(page, settle, close_overlays, "QA")
        result["campos_preenchidos"] = fields
        result["wizard_passos"] = steps
        w = await _requests_since(requests, mark, host)
        result["create"] = _write_label(w, steps, finished)

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
                    _, e_steps, e_fin = await _fill_wizard(
                        page, settle, close_overlays, "QAedit")
                    edited = True
                    break
        except Exception:
            continue
    if edited:
        w = await _requests_since(requests, mark, host)
        result["edit"] = _write_label(w, e_steps, e_fin)

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
