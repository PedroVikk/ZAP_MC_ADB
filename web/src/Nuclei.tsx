// Aba Nuclei: roda o Nuclei contra os alvos autorizados e mostra os achados
// chegando, agrupados por severidade. Complementa o ZAP (CVEs, misconfig, SAP).
import { useEffect, useRef, useState } from "react";
import { Loader2, Radiation, Square, Terminal } from "lucide-react";
import { api, type NucleiRun } from "./api";
import { Card, Empty, Progress, Toggle } from "./ui";

const SEV = ["critical", "high", "medium", "low", "info"] as const;
const SEV_LABEL: Record<string, string> = {
  critical: "Crítico",
  high: "Alto",
  medium: "Médio",
  low: "Baixo",
  info: "Info",
  unknown: "?",
};

export function NucleiView({ allowlist }: { allowlist: string[] }) {
  const [avail, setAvail] = useState<{ available: boolean; version?: string; detail?: string } | null>(null);
  const [target, setTarget] = useState("");
  const [severity, setSeverity] = useState<Record<string, boolean>>({ critical: true, high: true, medium: true, low: false, info: false });
  const [tags, setTags] = useState("");
  const [session, setSession] = useState("");
  const [throughZap, setThroughZap] = useState(false);
  const [run, setRun] = useState<NucleiRun | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const logRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    api.nucleiStatus().then(setAvail).catch(() => setAvail({ available: false }));
    api.nucleiRun().then(setRun).catch(() => undefined);
  }, []);

  useEffect(() => {
    if (!run?.running) return;
    const t = setInterval(() => api.nucleiRun().then(setRun).catch(() => undefined), 1500);
    return () => clearInterval(t);
  }, [run?.running]);

  useEffect(() => {
    const el = logRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [run?.log.length]);

  const start = async () => {
    setBusy(true);
    setErr("");
    try {
      const sev = SEV.filter((s) => severity[s]).join(",");
      const headers = session
        .split("\n")
        .map((l) => l.trim())
        .filter((l) => l.includes(":"));
      setRun(await api.nucleiStart({
        targets: [target.trim()],
        severity: sev,
        tags,
        templates: "",
        through_zap: throughZap,
        headers,
        max_seconds: 300,
      }));
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const running = !!run?.running;
  const defaultTarget = allowlist[0] ? `https://${allowlist[0]}` : "";

  return (
    <div className="stack">
      <Card title="Nuclei" icon={<Radiation size={16} />}>
        <p className="muted">
          Casa assinaturas conhecidas (CVEs, configurações erradas, templates de SAP) com
          pouquíssimo falso positivo. Complementa o ZAP. Só roda contra os alvos autorizados.
        </p>
        {avail && !avail.available ? (
          <p className="warn-text">
            Nuclei não encontrado ({avail.detail}). Instale o Nuclei ou defina <code>NUCLEI_PATH</code>.
          </p>
        ) : (
          avail?.version && <p className="muted">Versão: {avail.version}</p>
        )}

        <label className="field">
          <span>Alvo (URL ou host)</span>
          <input
            className="input"
            placeholder={defaultTarget || "https://host"}
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            spellCheck={false}
          />
        </label>
        <div className="field">
          <span>Severidade</span>
          <div className="chips">
            {SEV.map((s) => (
              <button
                key={s}
                className={`sev-chip risk-${s} ${severity[s] ? "on" : ""}`}
                onClick={() => setSeverity((o) => ({ ...o, [s]: !o[s] }))}
                type="button"
              >
                {SEV_LABEL[s]}
              </button>
            ))}
          </div>
        </div>
        <label className="field">
          <span>Tags (opcional)</span>
          <input className="input" placeholder="ex.: sap,cve,misconfiguration" value={tags} onChange={(e) => setTags(e.target.value)} />
        </label>
        <label className="field">
          <span>Sessão / cabeçalhos — para testar atrás do login (opcional)</span>
          <textarea
            className="input mono"
            rows={3}
            spellCheck={false}
            placeholder={"Cookie: SAP_SESSIONID_XYZ=...\nx-csrf-token: ...\nAuthorization: Bearer ..."}
            value={session}
            onChange={(e) => setSession(e.target.value)}
          />
          <small className="muted">
            Um cabeçalho por linha (copie de uma sessão já logada no devtools). Cada linha vira um{" "}
            <code>-H</code> do Nuclei.
          </small>
        </label>
        <Toggle
          checked={throughZap}
          onChange={setThroughZap}
          label="Passar pelo proxy do ZAP"
          hint="Os achados também ficam registrados no ZAP"
        />

        {running ? (
          <button className="btn danger block" onClick={() => api.nucleiStop().then(setRun)}>
            <Square size={16} /> Parar
          </button>
        ) : (
          <button
            className="btn primary block"
            onClick={start}
            disabled={busy || !target.trim() || (avail != null && !avail.available)}
          >
            {busy ? <Loader2 size={16} className="spin" /> : <Radiation size={16} />} Rodar Nuclei
          </button>
        )}
        {err && <p className="error-text">{err}</p>}
      </Card>

      {run && (
        <>
          <Card title={running ? "Rodando" : "Resultado"} icon={<Radiation size={16} />}>
            {running && <Progress />}
            <div className="risk-tiles nuclei">
              {SEV.map((s) => (
                <div key={s} className={`risk-tile risk-${s}`}>
                  <span className="risk-count">{run.by_severity[s] ?? 0}</span>
                  <span>{SEV_LABEL[s]}</span>
                </div>
              ))}
            </div>
            {run.error && <p className="error-text">{run.error}</p>}
          </Card>

          <Card title={`Achados (${run.total})`} icon={<Radiation size={16} />}>
            {run.findings.length === 0 ? (
              <Empty icon={<Radiation size={28} />} title={running ? "Procurando…" : "Nenhum achado"} />
            ) : (
              <div className="table-wrap">
                <table className="table">
                  <thead>
                    <tr>
                      <th>Severidade</th>
                      <th>Template</th>
                      <th>Onde</th>
                    </tr>
                  </thead>
                  <tbody>
                    {run.findings.map((f, i) => (
                      <tr key={i}>
                        <td>
                          <span className={`badge risk-${f.severity}`}>{SEV_LABEL[f.severity] ?? f.severity}</span>
                        </td>
                        <td>
                          <div>{f.name || f.id}</div>
                          <small className="mono muted">{f.id}</small>
                        </td>
                        <td className="mono break">{f.matched_at}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>

          <Card title="Log" icon={<Terminal size={16} />}>
            <div className="log" ref={logRef}>
              {run.log.map((l, i) => (
                <div key={i} className="log-line">
                  <span>{l}</span>
                </div>
              ))}
            </div>
          </Card>
        </>
      )}
    </div>
  );
}
