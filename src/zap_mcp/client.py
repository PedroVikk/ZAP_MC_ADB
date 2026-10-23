"""Camada fina sobre a API REST do ZAP (pacote `zaproxy`).

Nenhuma chamada arbitraria e exposta: so os metodos que as ferramentas usam.
A conexao e preguicosa para o modulo poder ser importado sem o ZAP no ar.
"""
from __future__ import annotations

from typing import Any

from .config import Config


class ZapUnavailable(Exception):
    """ZAP nao instalado/alcancavel."""


class ZapClient:
    def __init__(self, config: Config) -> None:
        self._config = config
        self._zap: Any = None

    @property
    def config(self) -> Config:
        return self._config

    def _zap_api(self):
        if self._zap is not None:
            return self._zap
        try:
            from zapv2 import ZAPv2
        except ImportError as exc:  # pragma: no cover
            raise ZapUnavailable(
                "pacote 'zaproxy' nao instalado. Rode: pip install zaproxy"
            ) from exc
        base = self._config.base_url
        self._zap = ZAPv2(
            apikey=self._config.api_key or None,
            proxies={"http": base, "https": base},
        )
        return self._zap

    # --- estado -----------------------------------------------------------
    def version(self) -> str:
        return self._zap_api().core.version

    # --- spider -----------------------------------------------------------
    def spider_scan(self, target: str) -> str:
        return str(self._zap_api().spider.scan(target))

    def spider_status(self, scan_id: str) -> int:
        return int(self._zap_api().spider.status(scan_id))

    def spider_stop(self, scan_id: str) -> None:
        self._zap_api().spider.stop(scan_id)

    # --- ajax spider ------------------------------------------------------
    def ajax_scan(self, target: str) -> None:
        self._zap_api().ajaxSpider.scan(target)

    def ajax_status(self) -> str:
        return str(self._zap_api().ajaxSpider.status)

    def ajax_stop(self) -> None:
        self._zap_api().ajaxSpider.stop()

    # --- active scan ------------------------------------------------------
    def active_scan(self, target: str) -> str:
        return str(self._zap_api().ascan.scan(target))

    def active_status(self, scan_id: str) -> int:
        return int(self._zap_api().ascan.status(scan_id))

    def active_stop(self, scan_id: str) -> None:
        self._zap_api().ascan.stop(scan_id)

    def active_messages_ids(self, scan_id: str) -> list[str]:
        """IDs das requisicoes de ataque que o scan ativo ja enviou."""
        try:
            return list(self._zap_api().ascan.messages_ids(scan_id))
        except Exception:  # noqa: BLE001
            return []

    def active_alerts_ids(self, scan_id: str) -> list[str]:
        """IDs dos alertas que o scan ativo ja levantou."""
        try:
            return list(self._zap_api().ascan.alerts_ids(scan_id))
        except Exception:  # noqa: BLE001
            return []

    def active_progress(self, scan_id: str) -> list:
        """Progresso por tipo de ataque (plugin) do scan ativo."""
        try:
            return list(self._zap_api().ascan.scan_progress(scan_id))
        except Exception:  # noqa: BLE001
            return []

    # --- alertas ----------------------------------------------------------
    def alerts(self, base_url: str | None = None) -> list[dict]:
        return list(self._zap_api().core.alerts(baseurl=base_url or ""))

    def alert(self, alert_id: str) -> dict:
        return dict(self._zap_api().core.alert(alert_id))

    def message(self, message_id: str) -> dict:
        return dict(self._zap_api().core.message(message_id))

    # --- openapi ----------------------------------------------------------
    def import_openapi(self, url: str) -> Any:
        return self._zap_api().openapi.import_url(url)

    # --- certificado CA (para o modulo ADB) ------------------------------
    def root_ca_pem(self) -> str:
        """Baixa o certificado raiz da CA do ZAP (PEM) pela API OTHER.

        Vai direto na API do ZAP (nao passa pelo proxy) para o ADB instalar no
        aparelho e o ZAP conseguir inspecionar o HTTPS do app.
        """
        import urllib.parse
        import urllib.request

        url = f"{self._config.base_url}/OTHER/core/other/rootcert/"
        if self._config.api_key:
            url += "?" + urllib.parse.urlencode({"apikey": self._config.api_key})
        with urllib.request.urlopen(url, timeout=15) as resp:  # noqa: S310 - host local do usuario
            return resp.read().decode("utf-8", "replace")

    # --- relatorios -------------------------------------------------------
    def report(self, fmt: str) -> str | None:
        core = self._zap_api().core
        if fmt == "html":
            return core.htmlreport()
        if fmt == "json":
            return core.jsonreport()
        if fmt in ("md", "markdown"):
            mdreport = getattr(core, "mdreport", None)
            return mdreport() if callable(mdreport) else None
        return None

    # --- mensagens (para extrair endpoints e urls vistos) ----------------
    def sites(self) -> list[str]:
        """Hosts que o ZAP registrou (ex.: https://host:porta)."""
        return list(self._zap_api().core.sites)

    def urls(self, site: str | None = None) -> list[str]:
        """Lista de URLs que o ZAP viu (spider + proxy). Chamada leve: devolve so
        as strings, nao as mensagens inteiras — rapida mesmo com o site grande."""
        return list(self._zap_api().core.urls(baseurl=site or ""))

    def messages_paged(self, site: str, page: int = 200) -> list[dict]:
        """Mensagens de UM site, em lotes. Buscar tudo de uma vez estoura o proxy
        quando o site tem muitas mensagens (ex.: depois do Spider) — a resposta
        gigante derruba a conexao. Em lotes pequenos a leitura e sempre leve."""
        core = self._zap_api().core
        out: list[dict] = []
        start = 0
        while True:
            batch = list(core.messages(baseurl=site, start=str(start), count=str(page)))
            if not batch:
                break
            out.extend(batch)
            if len(batch) < page:
                break
            start += page
        return out

    def messages(self, site: str | None = None) -> list[dict]:
        """Requisicoes que passaram pelo ZAP de um site (paginado).

        Sem site, consulta cada site separadamente e junta: o ZAP falha/estoura
        ao pedir TODAS as mensagens de uma vez (baseurl vazio), entao agregamos
        por site. Um site problematico nao derruba o resto.
        """
        if site:
            return self.messages_paged(site)
        out: list[dict] = []
        for s in self.sites():
            try:
                out.extend(self.messages_paged(s))
            except Exception:  # noqa: BLE001
                continue
        return out
