# zap-mcp

Servidor MCP que deixa o Claude operar o **OWASP ZAP** (hoje *ZAP by Checkmarx*)
em testes de seguranca **autorizados**: descobrir, escanear, ler os achados e
gerar o relatorio. Camada fina em Python (`FastMCP` + cliente `zaproxy`) sobre a
API REST do ZAP.

> **Uso autorizado apenas.** Rode contra sistemas que voce tem permissao
> expressa para testar (ex.: o OWASP Juice Shop local). O scan ativo envia
> ataques reais.

## Protecoes

- **Lista de alvos** (`ZAP_ALLOWED_TARGETS`): *deny by default* — lista vazia
  bloqueia tudo. Subdominios de um host liberado tambem passam.
- **Confirmacao explicita**: `active_scan` so roda com `confirm=True`.
- **Sem chamada livre**: nenhuma ferramenta repassa chamadas arbitrarias ao ZAP.
- **Segredos fora do codigo**: a `api.key` do ZAP vive em variavel de ambiente/`.env`.
- **Limite de tempo**: `scan_status` para o scan que passar de `ZAP_MAX_SCAN_SECONDS`.
- **Menos tokens**: `get_alerts` devolve os achados agrupados por tipo e risco;
  `generate_report` grava em arquivo e devolve so o caminho + contagem por risco.

## Ferramentas

| Ferramenta | O que faz |
| --- | --- |
| `zap_status` | Versao do ZAP e scans em andamento |
| `spider_scan(target)` | Crawling tradicional; devolve `scan_id` |
| `ajax_spider_scan(target)` | Crawling de apps JS; devolve `scan_id` |
| `scan_status(scan_id)` | Progresso de um scan (e aplica o limite de tempo) |
| `active_scan(target, confirm=True)` | Scan ativo; recusado sem confirmacao ou fora da lista |
| `get_alerts(min_risk, group_by_type)` | Resumo das vulnerabilidades |
| `get_alert_details(alert_id)` | Evidencia, request/response e solucao |
| `import_openapi(url, target)` | Importa uma spec OpenAPI para testar APIs |
| `generate_report(format)` | Relatorio em html, json ou md (grava em `reports/`) |

## SAPUI5, OData, Nuclei e mobile

Alem do fluxo classico do ZAP, o projeto cobre o que trava num app SAPUI5:

- **OData (`odata_discover`, `odata_probe`, aba OData):** le o `$metadata` do
  servico, descobre os EntitySets e monta as requisicoes (GET de colecao, por
  chave, `$filter/$select/$expand` e, opcional, POST/PATCH/DELETE) mandando tudo
  pelo proxy do ZAP. Testa a API direto, sem depender do spider. Escrita busca o
  CSRF token (`X-CSRF-Token: Fetch`) e exige confirmacao.
- **Nuclei (`nuclei_scan`, `nuclei_status`, aba Nuclei):** roda o Nuclei contra
  os alvos autorizados para CVEs, configuracoes erradas e templates de SAP, com
  pouquissimo falso positivo. Precisa do binario (`NUCLEI_PATH`).
- **Mobile/Flutter (`mobile_*`, aba Mobile):** prepara um aparelho via ADB —
  lista aparelhos, instala a CA do ZAP, seta o proxy e (com root) redireciona o
  trafego (iptables). O Flutter ignora o proxy e so confia na CA do sistema, por
  isso a aba traz o passo a passo (system store + redirect transparente +
  reFlutter/Frida). Precisa do `adb` (`ADB_PATH`). Experimental.

## Quickstart

### 1. Subir o ZAP

```bash
cp .env.example .env         # edite ZAP_API_KEY e ZAP_ALLOWED_TARGETS
docker compose up -d         # usa ZAP_API_KEY do .env
```

### 2. Instalar o servidor

```bash
python -m venv .venv
. .venv/Scripts/activate     # Windows (PowerShell: .venv\Scripts\Activate.ps1)
pip install -e .
```

### 3. Registrar no Claude

```bash
claude mcp add zap \
  -e ZAP_BASE_URL=http://localhost:8080 \
  -e ZAP_API_KEY=a-mesma-chave-do-compose \
  -e ZAP_ALLOWED_TARGETS=localhost,127.0.0.1 \
  -e ZAP_MAX_SCAN_SECONDS=900 \
  -- zap-mcp
```

(`zap-mcp` e o script instalado pelo `pip install -e .`; precisa estar no PATH
do ambiente onde o Claude abre o servidor — por isso o venv.)

## Painel web (React)

Front em `web/` (Vite + React) sobre uma API HTTP fina (`src/zap_mcp/web.py`,
Starlette) que reaproveita as mesmas funcoes e protecoes do servidor MCP:
allowlist editavel, confirmacao do scan ativo, botao Parar, log ao vivo,
alertas com detalhe, endpoints capturados e relatorios.

```bash
pip install -e ".[web]"
playwright install chromium
cd web && npm install && npm run build && cd ..
python -m zap_mcp.web        # http://127.0.0.1:8765
```

Para mexer no front com hot reload: deixe `python -m zap_mcp.web` rodando e,
em outro terminal, `cd web && npm run dev` (http://localhost:5173, que
repassa `/api` para a porta 8765). A API escuta so em 127.0.0.1.

## Testar contra o OWASP Juice Shop

```bash
docker run --rm -p 3000:3000 bkimminich/juice-shop
```

Com `ZAP_ALLOWED_TARGETS=localhost,127.0.0.1`, peca ao Claude:

1. `zap_status` — confere que o ZAP responde.
2. `spider_scan("http://localhost:3000")` -> `scan_id`; acompanhe com `scan_status`.
3. `active_scan("http://localhost:3000", confirm=True)` -> acompanhe ate 100%.
4. `get_alerts(min_risk="Low")` — resumo por tipo/risco.
5. `generate_report("html")` — caminho do arquivo em `reports/`.

## Desenvolvimento

```bash
pip install -e ".[dev]"
pytest
```

## Roadmap

- **Fase 1 (este MVP):** ZAP MCP.
- **Fase 2:** modulo ADB (apontar aparelho Android para o proxy do ZAP).
- **Fase 3:** integracao com o QA Evidence — na pratica, export HTML/PDF/JSON por
  scan para anexar como evidencia (o QA Evidence hoje nao tem API de ingestao).
