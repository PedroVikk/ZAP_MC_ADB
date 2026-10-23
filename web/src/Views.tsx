// Abas da area principal: execucao ao vivo, alertas, endpoints e relatorios.
import { useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  CheckCircle2,
  ChevronDown,
  Circle,
  Compass,
  ExternalLink,
  FileText,
  Loader2,
  Radar,
  RefreshCw,
  Search,
  ShieldCheck,
  Swords,
  Terminal,
  XCircle,
} from "lucide-react";
import {
  api,
  type AlertDetail,
  type Alerts,
  type Job,
  type ReportFile,
  type Risk,
  type Urls,
} from "./api";
import { Card, Empty, Metric, Progress, RISK_LABEL, RiskBadge, fmtDuration } from "./ui";

const PHASE_LABEL: Record<string, string> = {
  explorador: "Explorador",
  spider: "Spider",
  ativo: "Scan ativo",
  relatorio: "Relatório",
};

function useNow(active: boolean) {
  const [now, setNow] = useState(Date.now() / 1000);
  useEffect(() => {
    if (!active) return;
    const t = setInterval(() => setNow(Date.now() / 1000), 1000);
    return () => clearInterval(t);
  }, [active]);
  return now;
}

/* ---------------- Execucao ---------------- */

export function RunView({ job }: { job: Job | null }) {
  const now = useNow(!!job?.running);
  const logRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = logRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [job?.log.length]);

  if (!job) {
    return (
      <Card>
        <Empty icon={<Radar size={28} />} title="Nenhum teste ainda">
          Libere o host do alvo, escolha o que rodar e clique em <b>Rodar teste</b>. O progresso
          aparece aqui ao vivo.
        </Empty>
      </Card>
    );
  }

  const elapsed = (job.finished_at ?? now) - job.started_at;
  const current = job.phases.indexOf(job.phase);
  const done = job.phase === "concluido";
  const ex = job.explore;
  const crudRows = (ex?.crud ?? []).filter(
    (r) => r.create || r.view || r.edit || r.delete || r.erro,
  );

  return (
    <div className="stack">
      <Card>
        <div className="run-head">
          <div>
            <div className="run-target">{job.params.target}</div>
            <div className="muted">
              {job.running ? "Rodando há " : job.phase === "erro" ? "Falhou após " : "Terminou em "}
              {fmtDuration(elapsed)}
              {job.stop_requested && job.running && " · parada pedida"}
            </div>
          </div>
          {job.running ? (
            <span className="pill live">Ao vivo</span>
          ) : job.phase === "erro" ? (
            <span className="pill bad">Erro</span>
          ) : job.failed.length ? (
            <span className="pill warn">Com falhas</span>
          ) : (
            <span className="pill good">Concluído</span>
          )}
        </div>
        <ol className="stepper">
          {job.phases.map((ph, i) => {
            const state = job.failed.includes(ph)
              ? "failed"
              : done || i < current
                ? "done"
                : i === current
                  ? "current"
                  : "pending";
            return (
              <li key={ph} className={state}>
                {state === "failed" ? (
                  <XCircle size={18} />
                ) : state === "done" ? (
                  <CheckCircle2 size={18} />
                ) : state === "current" && job.running ? (
                  <Loader2 size={18} className="spin" />
                ) : (
                  <Circle size={18} />
                )}
                <span>{PHASE_LABEL[ph] ?? ph}</span>
              </li>
            );
          })}
        </ol>
        {job.error && <p className="error-text">{job.error}</p>}
      </Card>

      {job.params.explore && (
        <Card title="Explorador" icon={<Compass size={16} />}>
          {job.phase === "explorador" && !ex && (
            <>
              <Progress />
              <p className="muted">
                Navegando o app pelo proxy do ZAP
                {job.params.headless ? "" : " — veja a janela do Chromium"}…
              </p>
            </>
          )}
          {ex && (
            <div className="metrics">
              <Metric
                label="Login"
                value={ex.login_status ?? "—"}
                tone={ex.login_status?.startsWith("ok") ? "good" : undefined}
              />
              <Metric label="Rotas UI5" value={`${ex.routes_visited?.length ?? 0}/${ex.routes_found ?? 0}`} />
              <Metric label="Ações" value={ex.actions ?? 0} />
              <Metric label="Requests" value={ex.requests_total ?? 0} />
            </div>
          )}
          {crudRows.length > 0 && (
            <table className="table compact">
              <thead>
                <tr>
                  <th>Tela</th>
                  <th>Campos</th>
                  <th>Create</th>
                  <th>View</th>
                  <th>Edit</th>
                  <th>Delete</th>
                </tr>
              </thead>
              <tbody>
                {crudRows.map((r) => (
                  <tr key={r.tela}>
                    <td className="mono">{r.tela}</td>
                    <td>{r.campos_preenchidos ?? 0}</td>
                    {(["create", "view", "edit", "delete"] as const).map((k) => (
                      <td key={k} className={r[k] === "ok" ? "ok" : "dim"}>
                        {r[k] ?? (r.erro && k === "create" ? r.erro : "—")}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      )}

      {job.params.spider && (
        <Card title="Spider" icon={<Activity size={16} />}>
          <Progress value={job.spider?.progress ?? 0} />
          <p className="muted">{phaseNote(job, "spider", job.spider && `${job.spider.progress}% · ${job.spider.status}`)}</p>
        </Card>
      )}

      {job.params.active && (
        <Card title="Scan ativo" icon={<Swords size={16} />} className="danger-edge">
          <Progress value={job.active?.progresso ?? 0} tone="danger" />
          {!job.active && <p className="muted">{phaseNote(job, "ativo", null)}</p>}
          <div className="metrics">
            <Metric label="Progresso" value={`${job.active?.progresso ?? 0}%`} />
            <Metric label="Ataques enviados" value={job.active?.ataques_enviados ?? 0} />
            <Metric label="Alertas" value={job.active?.alertas ?? 0} tone="danger" />
          </div>
          {!!job.active?.rodando.length && (
            <div className="chips">
              {job.active.rodando.map((r) => (
                <span key={r.ataque} className="chip attack">
                  {r.ataque} <small>{r.reqs ?? 0} reqs</small>
                </span>
              ))}
            </div>
          )}
        </Card>
      )}

      <Card title="Log" icon={<Terminal size={16} />}>
        <div className="log" ref={logRef}>
          {job.log.map((l, i) => (
            <div key={i} className={`log-line ${l.level}`}>
              <time>{new Date(l.t * 1000).toLocaleTimeString()}</time>
              <span>{l.msg}</span>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}

function phaseNote(job: Job, phase: string, live: string | null): string {
  if (job.failed.includes(phase)) return "Não iniciou — veja o log.";
  if (live) return live;
  if (job.phase === phase) return "Iniciando…";
  return job.running ? "Aguardando" : "Não rodou.";
}

/* ---------------- Alertas ---------------- */

const RISKS: Risk[] = ["High", "Medium", "Low", "Informational"];

export function AlertsView({ refreshKey }: { refreshKey: number }) {
  const [minRisk, setMinRisk] = useState<Risk>("Low");
  const [data, setData] = useState<Alerts | null>(null);
  const [loading, setLoading] = useState(false);
  const [open, setOpen] = useState<string | null>(null);
  const [details, setDetails] = useState<Record<string, AlertDetail>>({});

  const load = async () => {
    setLoading(true);
    try {
      setData(await api.alerts(minRisk));
    } catch (e) {
      setData({ total: 0, by_risk: {} as Alerts["by_risk"], groups: [], error: (e as Error).message });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [minRisk, refreshKey]);

  const toggle = async (key: string, id?: string) => {
    setOpen(open === key ? null : key);
    if (id && !details[id]) {
      const d = await api.alert(id).catch((e) => ({ error: (e as Error).message }) as AlertDetail);
      setDetails((o) => ({ ...o, [id]: d }));
    }
  };

  return (
    <div className="stack">
      <div className="risk-tiles">
        {RISKS.map((r) => (
          <button
            key={r}
            className={`risk-tile risk-${r} ${minRisk === r ? "selected" : ""}`}
            onClick={() => setMinRisk(r)}
            title={`Mostrar ${RISK_LABEL[r]} ou acima`}
          >
            <span className="risk-count">{data?.by_risk?.[r] ?? "–"}</span>
            <span>{RISK_LABEL[r]}</span>
          </button>
        ))}
      </div>

      <Card
        title={`Alertas · ${RISK_LABEL[minRisk]} ou acima`}
        icon={<ShieldCheck size={16} />}
        actions={
          <button className="btn ghost small" onClick={load} disabled={loading}>
            <RefreshCw size={14} className={loading ? "spin" : ""} /> Atualizar
          </button>
        }
      >
        {data?.error || data?.detail ? (
          <p className="error-text">{data.detail || data.error}</p>
        ) : !data?.groups?.length ? (
          <Empty icon={<ShieldCheck size={28} />} title="Nenhum alerta neste nível" />
        ) : (
          <ul className="alert-list">
            {data.groups.map((g) => {
              const key = `${g.risk}-${g.name}`;
              const d = g.example_alert_id ? details[g.example_alert_id] : undefined;
              return (
                <li key={key} className={open === key ? "open" : ""}>
                  <button className="alert-row" onClick={() => toggle(key, g.example_alert_id)}>
                    <RiskBadge risk={g.risk} />
                    <span className="alert-name">{g.name}</span>
                    {g.cweid && g.cweid !== "-1" && <span className="tag">CWE-{g.cweid}</span>}
                    <span className="count">{g.count}×</span>
                    <ChevronDown size={16} className="chev" />
                  </button>
                  {open === key && (
                    <div className="alert-detail">
                      {!d ? (
                        <Progress />
                      ) : d.error || d.detail ? (
                        <p className="error-text">{d.detail || d.error}</p>
                      ) : (
                        <AlertBody d={d} />
                      )}
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </Card>
    </div>
  );
}

function AlertBody({ d }: { d: AlertDetail }) {
  return (
    <>
      <dl className="kv">
        {d.url && (
          <>
            <dt>Exemplo</dt>
            <dd className="mono break">{d.url}</dd>
          </>
        )}
        {d.param && (
          <>
            <dt>Parâmetro</dt>
            <dd className="mono">{d.param}</dd>
          </>
        )}
        {d.confidence && (
          <>
            <dt>Confiança</dt>
            <dd>{d.confidence}</dd>
          </>
        )}
        {d.attack && (
          <>
            <dt>Ataque</dt>
            <dd className="mono break">{d.attack}</dd>
          </>
        )}
        {d.evidence && (
          <>
            <dt>Evidência</dt>
            <dd className="mono break">{d.evidence}</dd>
          </>
        )}
      </dl>
      {d.description && (
        <div className="prose">
          <h4>Descrição</h4>
          <p>{d.description}</p>
        </div>
      )}
      {d.solution && (
        <div className="prose">
          <h4>Solução</h4>
          <p>{d.solution}</p>
        </div>
      )}
      {(d.request || d.response) && (
        <details className="raw">
          <summary>Request / Response</summary>
          <pre>{[d.request?.header, d.request?.body].filter(Boolean).join("\n")}</pre>
          <pre>{[d.response?.header, d.response?.body].filter(Boolean).join("\n")}</pre>
        </details>
      )}
    </>
  );
}

/* ---------------- Endpoints ---------------- */

export function EndpointsView({ refreshKey }: { refreshKey: number }) {
  const [data, setData] = useState<Urls | null>(null);
  const [loading, setLoading] = useState(false);
  const [onlyApi, setOnlyApi] = useState(true);
  const [q, setQ] = useState("");

  const load = async () => {
    setLoading(true);
    try {
      setData(await api.urls());
    } catch (e) {
      setData({ total_urls: 0, endpoints: [], pages: [], error: (e as Error).message });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, [refreshKey]);

  const rows = useMemo(() => {
    const all = onlyApi ? data?.endpoints ?? [] : [...(data?.endpoints ?? []), ...(data?.pages ?? [])];
    const term = q.trim().toLowerCase();
    return term ? all.filter((e) => e.url.toLowerCase().includes(term)) : all;
  }, [data, onlyApi, q]);

  const hosts = useMemo(() => {
    const s = new Set<string>();
    [...(data?.endpoints ?? []), ...(data?.pages ?? [])].forEach((e) => {
      try {
        s.add(new URL(e.url).origin);
      } catch {
        /* url sem origem */
      }
    });
    return [...s];
  }, [data]);

  return (
    <Card
      title="Endpoints capturados"
      icon={<Activity size={16} />}
      actions={
        <button className="btn ghost small" onClick={load} disabled={loading}>
          <RefreshCw size={14} className={loading ? "spin" : ""} /> Atualizar
        </button>
      }
    >
      <div className="metrics">
        <Metric label="Endpoints de API" value={data?.endpoints.length ?? "–"} tone="accent" />
        <Metric label="URLs no total" value={data?.total_urls ?? "–"} />
        <Metric label="Hosts" value={hosts.length || "–"} />
      </div>
      <div className="row toolbar">
        <div className="search">
          <Search size={15} />
          <input className="input" placeholder="Filtrar URL…" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <div className="seg">
          <button className={onlyApi ? "on" : ""} onClick={() => setOnlyApi(true)}>
            Só API
          </button>
          <button className={!onlyApi ? "on" : ""} onClick={() => setOnlyApi(false)}>
            Tudo
          </button>
        </div>
      </div>
      {data?.error || data?.detail ? (
        <p className="error-text">{data.detail || data.error}</p>
      ) : rows.length === 0 ? (
        <Empty icon={<Search size={28} />} title="Nada capturado ainda">
          Endpoints de SPA só aparecem quando o tráfego passa pelo ZAP (explorador ou AJAX Spider).
        </Empty>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>URL</th>
                <th>Tipo</th>
                <th>Query</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((e) => (
                <tr key={e.url}>
                  <td className="mono break">{e.url}</td>
                  <td>{e.is_api ? <span className="tag accent">API</span> : <span className="tag">página</span>}</td>
                  <td>{e.has_params ? "sim" : ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

/* ---------------- Relatorios ---------------- */

export function ReportsView({ refreshKey }: { refreshKey: number }) {
  const [files, setFiles] = useState<ReportFile[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [msg, setMsg] = useState("");

  const load = () => api.reports().then(setFiles).catch(() => setFiles([]));
  useEffect(() => {
    load();
  }, [refreshKey]);

  const make = async (kind: "zap" | "endpoints", format = "html") => {
    setBusy(kind + format);
    setMsg("");
    try {
      const r = await api.makeReport(kind, format);
      setMsg(r.path ? `Gerado: ${r.path.split(/[\\/]/).pop()}` : r.detail || r.error || "Falhou");
      load();
    } catch (e) {
      setMsg((e as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const btn = (kind: "zap" | "endpoints", format: string, label: string) => (
    <button className="btn" disabled={!!busy} onClick={() => make(kind, format)}>
      {busy === kind + format ? <Loader2 size={15} className="spin" /> : <FileText size={15} />} {label}
    </button>
  );

  return (
    <div className="stack">
      <Card title="Gerar relatório" icon={<FileText size={16} />}>
        <div className="row wrap">
          {btn("zap", "html", "ZAP · HTML")}
          {btn("zap", "md", "ZAP · Markdown")}
          {btn("zap", "json", "ZAP · JSON")}
          {btn("endpoints", "md", "Por tela/endpoint")}
        </div>
        {msg && <p className="muted">{msg}</p>}
      </Card>
      <Card title="Relatórios gerados" icon={<FileText size={16} />}>
        {files.length === 0 ? (
          <Empty icon={<FileText size={28} />} title="Nenhum relatório na pasta" />
        ) : (
          <ul className="files">
            {files.map((f) => (
              <li key={f.name}>
                <span className={`tag ext-${f.name.split(".").pop()}`}>{f.name.split(".").pop()}</span>
                <span className="mono grow break">{f.name}</span>
                <span className="muted">{(f.size / 1024).toFixed(0)} KB</span>
                <span className="muted">{new Date(f.mtime * 1000).toLocaleString()}</span>
                <a className="btn ghost small" href={`/api/reports/${encodeURIComponent(f.name)}`} target="_blank" rel="noreferrer">
                  Abrir <ExternalLink size={13} />
                </a>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
