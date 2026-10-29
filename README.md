# zap-mcp

Servidor MCP que deixa o Claude operar o **OWASP ZAP** (hoje *ZAP by Checkmarx*)
em testes de seguranca **autorizados**: descobrir, escanear, ler os achados e
gerar o relatorio. Camada fina em Python (SDK `mcp` + cliente `zaproxy`) sobre a
API REST do ZAP, com explorador de SPA (SAPUI5), OData, Nuclei, mobile e um
painel web.

> **Uso autorizado apenas.** Rode contra sistemas que voce tem permissao
> expressa para testar (ex.: o OWASP Juice Shop local, ou a sua staging). O scan
> ativo e o teste de CRUD enviam ataques reais e mexem em dados.

---

## Passo a passo — baixar e instalar tudo

O que **tem que** ter: Python, o OWASP ZAP e o Git. Node, Nuclei e ADB so para
recursos especificos (painel web, scan de CVE e teste mobile). Os passos abaixo
sao para **Windows**; em Linux/macOS os links trazem os pacotes equivalentes.

### Obrigatorio

1. **Python 3.10 ou mais novo** — https://www.python.org/downloads/
   No instalador, marque **"Add python.exe to PATH"**. Confira: `python --version`.
   (No Windows, use sempre `python`, nao `python3` — o `python3` e um stub da
   Store que falha calado.)

2. **OWASP ZAP** (o proxy que faz a varredura) — https://www.zaproxy.org/download/
   Baixe o **instalador do Windows** (ja vem com o Java embutido, nao precisa
   instalar Java a parte). Depois de instalar, abra o ZAP uma vez e deixe-o
   rodando — ele e quem escuta em `http://localhost:8080`.
   - **Ligar a API e pegar a chave:** no ZAP, menu **Tools -> Options -> API**.
     Deixe marcado *Enable* e copie o valor de **API Key** (ou gere um). Esse
     mesmo valor vai no `.env` (`ZAP_API_KEY`).

3. **Git** (para clonar o projeto) — https://git-scm.com/download/win

### Opcional (so se for usar o recurso)

4. **Node.js LTS** — https://nodejs.org/  *(so para RECONSTRUIR o painel web)*
   O front ja vem **pronto** em `web/dist/`, entao para so *usar* o painel voce
   **nao precisa** de Node. So instale se for mexer no React e rebuildar.

5. **Nuclei** (scan de CVE/misconfig) — https://github.com/projectdiscovery/nuclei/releases
   Baixe o `.zip` do Windows, extraia o `nuclei.exe` e: ou coloque numa pasta do
   `PATH`, ou aponte `NUCLEI_PATH=C:\caminho\nuclei.exe` no `.env`.

6. **Android platform-tools (ADB)** (teste mobile/Flutter) —
   https://developer.android.com/tools/releases/platform-tools
   Extraia e aponte `ADB_PATH=C:\caminho\platform-tools\adb.exe` no `.env` (ou
   coloque no `PATH`).

---

## Passo a passo — instalar e rodar

### 1. Clonar o projeto

```bash
git clone https://github.com/PedroVikk/ZAP_MC_ADB.git zap-mcp
cd zap-mcp
```

### 2. Criar o ambiente e instalar

```bash
python -m venv .venv
.venv\Scripts\activate          # PowerShell: .venv\Scripts\Activate.ps1

pip install -e ".[web,panel]"    # servidor + paineis + explorador
playwright install chromium      # navegador que o explorador dirige
```

> `-e ".[web,panel]"` instala tudo que os paineis precisam (Starlette/uvicorn,
> Streamlit e Playwright). So o servidor MCP: `pip install -e .`.

### 3. Configurar o `.env`

```bash
copy .env.example .env           # Linux/macOS: cp .env.example .env
```

Edite o `.env` e ajuste **pelo menos**:
- `ZAP_API_KEY` = a mesma chave que voce copiou do ZAP (Tools -> Options -> API).
- `ZAP_ALLOWED_TARGETS` = os hosts que voce PODE testar (deny by default: vazio
  bloqueia tudo). Ex.: `localhost,127.0.0.1,staging.suaempresa.com`.

Opcionais: `ZAP_BASE_URL` (default `http://localhost:8080`),
`ZAP_MAX_SCAN_SECONDS`, `ZAP_REPORT_DIR`, `NUCLEI_PATH`, `ADB_PATH`.

### 4. Rodar

Com o **ZAP aberto** (passo 2 dos pre-requisitos), escolha como usar:

**a) Painel web (interface grafica, recomendado):**
```bash
python -m zap_mcp.web            # abre em http://127.0.0.1:8765
```
Alvos autorizados, login (SAPUI5 + selecao de empresa), explorador, scan ativo
ao vivo, botao Parar, CRUD, OData, Nuclei, alertas e relatorios — tudo na tela.

**b) Como ferramenta do Claude (MCP):**
```bash
claude mcp add zap \
  -e ZAP_BASE_URL=http://localhost:8080 \
  -e ZAP_API_KEY=a-mesma-chave-do-zap \
  -e ZAP_ALLOWED_TARGETS=localhost,127.0.0.1 \
  -e ZAP_MAX_SCAN_SECONDS=900 \
  -- zap-mcp
```
(`zap-mcp` e o script instalado pelo `pip install -e .`; precisa estar no PATH do
venv onde o Claude abre o servidor.)

**c) Painel Streamlit (alternativa mais simples):**
```bash
streamlit run src/zap_mcp/panel.py   # http://localhost:8501
```

### Alternativa: ZAP via Docker (em vez do app)

Se preferir nao instalar o app do ZAP e tiver Docker:
```bash
docker compose up -d             # usa ZAP_API_KEY do .env
```

---

## Protecoes

- **Lista de alvos** (`ZAP_ALLOWED_TARGETS`): *deny by default* — lista vazia
  bloqueia tudo. Subdominios de um host liberado tambem passam.
- **Confirmacao explicita**: `active_scan` e as escritas de CRUD/OData so rodam
  com confirmacao.
- **Sem chamada livre**: nenhuma ferramenta repassa chamadas arbitrarias ao ZAP.
- **Segredos fora do codigo**: a chave da API do ZAP vive em `.env` (fora do git).
- **Limite de tempo**: `scan_status` para o scan que passar de `ZAP_MAX_SCAN_SECONDS`.
- **Menos tokens**: `get_alerts` agrupa por tipo e risco; `generate_report` grava
  em arquivo e devolve so o caminho + contagem por risco.

## Ferramentas (MCP)

| Ferramenta | O que faz |
| --- | --- |
| `zap_status` | Versao do ZAP e scans em andamento |
| `spider_scan(target)` | Crawling tradicional; devolve `scan_id` |
| `ajax_spider_scan(target)` | Crawling de apps JS; devolve `scan_id` |
| `scan_status(scan_id)` | Progresso de um scan (e aplica o limite de tempo) |
| `active_scan(target, confirm=True)` | Scan ativo; recusado sem confirmacao ou fora da lista |
| `active_scan_feed(scan_id)` | Snapshot ao vivo do scan ativo (ataques enviados, progresso) |
| `get_alerts(min_risk, group_by_type)` | Resumo das vulnerabilidades |
| `get_alert_details(alert_id)` | Evidencia, request/response e solucao |
| `get_urls(site, only_endpoints)` | URLs/endpoints capturados, agregando os hosts autorizados |
| `report_endpoints(site)` | Documento (Markdown) do que foi testado/achado em CADA tela/endpoint |
| `import_openapi(url, target)` | Importa uma spec OpenAPI para testar APIs |
| `generate_report(format)` | Relatorio em html, json ou md (grava em `reports/`) |
| `session_login / session_status / session_clear` | Loga uma vez (SAPUI5 + empresa) e reusa a sessao |
| `odata_discover / odata_probe` | Le o `$metadata` do OData e monta/dispara requisicoes |
| `nuclei_scan / nuclei_status` | Roda o Nuclei (CVEs, misconfig, templates de SAP) |
| `mobile_*` | Prepara um aparelho via ADB (CA do ZAP, proxy, redirect transparente) |

## SAPUI5, OData, Nuclei e mobile

Alem do fluxo classico do ZAP, o projeto cobre o que trava num app SAPUI5:

- **Explorador autenticado:** loga (inclusive a tela de selecao de empresa),
  varre as rotas do UI5 pelo `manifest.json`, acessa o menu lateral, clica um
  item por vez (fecha modais, volta ao travar) e, com CRUD ligado, cria/abre/
  edita/exclui registros e avanca os wizards — para disparar POST/PUT/DELETE.
- **OData (`odata_discover`, `odata_probe`):** le o `$metadata`, descobre os
  EntitySets e monta as requisicoes (GET de colecao, por chave, `$filter/$select/
  $expand` e, opcional, POST/PATCH/DELETE) pelo proxy do ZAP. Escrita busca o
  CSRF token (`X-CSRF-Token: Fetch`) e exige confirmacao.
- **Nuclei (`nuclei_scan`, `nuclei_status`):** CVEs, configuracoes erradas e
  templates de SAP, com pouco falso positivo. Precisa do binario (`NUCLEI_PATH`).
- **Mobile/Flutter (`mobile_*`):** prepara um aparelho via ADB — lista aparelhos,
  instala a CA do ZAP, seta o proxy e (com root) redireciona o trafego. O Flutter
  ignora o proxy e so confia na CA do sistema, por isso ha um passo a passo
  (system store + redirect transparente + reFlutter/Frida). Precisa do `adb`
  (`ADB_PATH`). Experimental.

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

# mexer no front React com hot reload (precisa de Node):
cd web && npm install && npm run dev   # http://localhost:5173 (repassa /api p/ 8765)
# e deixe, em outro terminal: python -m zap_mcp.web
# para publicar o front: cd web && npm run build
```

## Roadmap

- **Fase 1 (feito):** ZAP MCP + explorador de SPA + painel web.
- **Fase 2 (feito):** OData, Nuclei, CRUD com wizard, sessao reaproveitada, mobile/ADB.
- **Fase 3:** explorador por perfis salvos (config + sessao por app) para outros QAs.
- **Fase 4:** integracao com o QA Evidence — export por scan para anexar como evidencia.
