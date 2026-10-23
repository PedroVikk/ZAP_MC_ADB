// Aba OData: le o $metadata de um servico (SAPUI5/SAP Gateway), lista os
// EntitySets e manda as requisicoes pelo ZAP para ele registrar e escanear.
import { useState } from "react";
import { Database, KeyRound, Loader2, Search, Send, ShieldAlert } from "lucide-react";
import { api, type ODataResult } from "./api";
import { Card, Empty, Metric, Toggle } from "./ui";

export function ODataView() {
  const [url, setUrl] = useState("https://localhost:5001/sap/opu/odata/sap/MEU_SRV/$metadata");
  const [user, setUser] = useState("");
  const [pass, setPass] = useState("");
  const [writes, setWrites] = useState(false);
  const [confirm, setConfirm] = useState(false);
  const [busy, setBusy] = useState<"discover" | "probe" | null>(null);
  const [res, setRes] = useState<ODataResult | null>(null);
  const [err, setErr] = useState("");

  const run = async (kind: "discover" | "probe") => {
    setBusy(kind);
    setErr("");
    try {
      const data =
        kind === "discover"
          ? await api.odataDiscover(url)
          : await api.odataProbe({
              metadata_url: url,
              include_writes: writes,
              confirm,
              username: user,
              password: pass,
            });
      if (data.error) setErr(data.detail || data.error);
      setRes(data);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const needsConfirm = res?.status === "confirmacao_necessaria";
  const rows: { method: string; kind: string; path: string; status?: number }[] =
    res?.results ?? res?.requests ?? [];

  return (
    <div className="stack">
      <Card title="Serviço OData" icon={<Database size={16} />}>
        <p className="muted">
          Lê o <code>$metadata</code> e monta as requisições de cada EntitySet. <b>Descobrir</b> só
          planeja; <b>Enviar pelo ZAP</b> manda o tráfego pelo proxy para o ZAP registrar e depois
          escanear. É o caminho para testar um SAPUI5 sem depender do spider.
        </p>
        <label className="field">
          <span>URL do $metadata</span>
          <input className="input" value={url} onChange={(e) => setUrl(e.target.value)} spellCheck={false} />
        </label>
        <div className="row">
          <input
            className="input"
            placeholder="usuário (opcional)"
            autoComplete="off"
            value={user}
            onChange={(e) => setUser(e.target.value)}
          />
          <input
            className="input"
            type="password"
            placeholder="senha"
            autoComplete="new-password"
            value={pass}
            onChange={(e) => setPass(e.target.value)}
          />
        </div>

        <div className="group">
          <Toggle
            checked={writes}
            onChange={(v) => {
              setWrites(v);
              setConfirm(false);
            }}
            label="Incluir escrita (POST/PATCH/DELETE)"
            hint="Cria, altera e apaga registros — busca o CSRF token antes"
            danger
          />
          {writes && (
            <label className="confirm">
              <input type="checkbox" checked={confirm} onChange={(e) => setConfirm(e.target.checked)} />
              <ShieldAlert size={16} />
              <span>Confirmo que é uma base de teste descartável.</span>
            </label>
          )}
        </div>

        <div className="row wrap">
          <button className="btn" disabled={!!busy || !url.trim()} onClick={() => run("discover")}>
            {busy === "discover" ? <Loader2 size={15} className="spin" /> : <Search size={15} />} Descobrir
          </button>
          <button
            className="btn primary"
            disabled={!!busy || !url.trim() || (writes && !confirm)}
            onClick={() => run("probe")}
          >
            {busy === "probe" ? <Loader2 size={15} className="spin" /> : <Send size={15} />} Enviar pelo ZAP
          </button>
        </div>
        {err && <p className="error-text">{err}</p>}
        {needsConfirm && <p className="warn-text">{res?.message}</p>}
      </Card>

      {res && !res.error && !needsConfirm && (
        <>
          <Card title="Serviço" icon={<Database size={16} />}>
            <div className="metrics">
              <Metric label="EntitySets" value={res.entitysets ?? 0} tone="accent" />
              <Metric label="Requisições" value={res.requests_planned ?? 0} />
              {res.sent !== undefined && <Metric label="Enviadas" value={res.sent} tone="good" />}
              {res.sent !== undefined && <Metric label="Falhas" value={res.failed ?? 0} tone={res.failed ? "danger" : undefined} />}
            </div>
            <dl className="kv">
              <dt>Versão</dt>
              <dd>{res.odata_version}</dd>
              <dt>Raiz</dt>
              <dd className="mono break">{res.service_root}</dd>
              {res.csrf_token && res.csrf_token !== "n/a" && (
                <>
                  <dt>CSRF</dt>
                  <dd>{res.csrf_token}</dd>
                </>
              )}
              {res.by_status && (
                <>
                  <dt>Por status</dt>
                  <dd className="mono">
                    {Object.entries(res.by_status)
                      .map(([s, n]) => `${s}: ${n}`)
                      .join("  ·  ")}
                  </dd>
                </>
              )}
            </dl>
          </Card>

          <Card title="EntitySets" icon={<KeyRound size={16} />}>
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>EntitySet</th>
                    <th>Chaves</th>
                    <th>Props</th>
                    <th>Navs</th>
                  </tr>
                </thead>
                <tbody>
                  {(res.discovered ?? []).map((e) => (
                    <tr key={e.entityset}>
                      <td className="mono">{e.entityset}</td>
                      <td className="mono">{e.keys.join(", ") || "—"}</td>
                      <td>{e.props}</td>
                      <td>{e.navs}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>

          <Card title={res.results ? "Requisições enviadas" : "Requisições planejadas"} icon={<Send size={16} />}>
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Método</th>
                    <th>Tipo</th>
                    {res.results && <th>Status</th>}
                    <th>URL</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r, i) => (
                    <tr key={i}>
                      <td>
                        <span className={`tag ${r.method === "GET" ? "" : "accent"}`}>{r.method}</span>
                      </td>
                      <td>{r.kind}</td>
                      {res.results && (
                        <td className={r.status && r.status >= 400 ? "dim" : "ok"}>{r.status}</td>
                      )}
                      <td className="mono break">{r.path}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        </>
      )}

      {!res && (
        <Card>
          <Empty icon={<Database size={28} />} title="Sem serviço lido ainda">
            Cole a URL do <code>$metadata</code> do serviço OData e clique em <b>Descobrir</b>.
          </Empty>
        </Card>
      )}
    </div>
  );
}
