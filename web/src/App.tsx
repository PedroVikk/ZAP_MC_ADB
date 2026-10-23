import { useCallback, useEffect, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Database,
  FileText,
  Play,
  Radiation,
  RefreshCw,
  Shield,
  ShieldCheck,
  Smartphone,
} from "lucide-react";
import { api, type Job, type Status } from "./api";
import { Allowlist, RunForm } from "./Setup";
import { ODataView } from "./OData";
import { NucleiView } from "./Nuclei";
import { MobileView } from "./Mobile";
import { AlertsView, EndpointsView, ReportsView, RunView } from "./Views";

type Tab = "run" | "odata" | "nuclei" | "mobile" | "alerts" | "endpoints" | "reports";

const TABS: { id: Tab; label: string; icon: JSX.Element }[] = [
  { id: "run", label: "Execução", icon: <Play size={15} /> },
  { id: "odata", label: "OData", icon: <Database size={15} /> },
  { id: "nuclei", label: "Nuclei", icon: <Radiation size={15} /> },
  { id: "mobile", label: "Mobile", icon: <Smartphone size={15} /> },
  { id: "alerts", label: "Alertas", icon: <ShieldCheck size={15} /> },
  { id: "endpoints", label: "Endpoints", icon: <Activity size={15} /> },
  { id: "reports", label: "Relatórios", icon: <FileText size={15} /> },
];

export default function App() {
  const [status, setStatus] = useState<Status | null>(null);
  const [statusErr, setStatusErr] = useState("");
  const [job, setJob] = useState<Job | null>(null);
  const [tab, setTab] = useState<Tab>("run");
  // muda quando um teste termina: alertas/endpoints/relatorios recarregam sozinhos
  const [refreshKey, setRefreshKey] = useState(0);
  const wasRunning = useRef(false);

  const loadStatus = useCallback(async () => {
    try {
      setStatus(await api.status());
      setStatusErr("");
    } catch (e) {
      setStatusErr((e as Error).message);
    }
  }, []);

  const loadJob = useCallback(async () => {
    try {
      const j = await api.job();
      setJob(j);
      if (wasRunning.current && j && !j.running) setRefreshKey((k) => k + 1);
      wasRunning.current = !!j?.running;
    } catch {
      /* API fora do ar: o status mostra */
    }
  }, []);

  useEffect(() => {
    loadStatus();
    loadJob();
    const t = setInterval(loadStatus, 15000);
    return () => clearInterval(t);
  }, [loadStatus, loadJob]);

  useEffect(() => {
    if (!job?.running) return;
    const t = setInterval(loadJob, 1500);
    return () => clearInterval(t);
  }, [job?.running, loadJob]);

  const zapOk = !!status?.zap_version && !status.error;
  const running = !!job?.running;

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <Shield size={22} />
          <span>
            ZAP <b>MCP</b>
          </span>
          <small>painel de testes autorizados</small>
        </div>
        <div className="topbar-right">
          {running && (
            <span className="pill live">
              <span className="dot" /> Teste rodando
            </span>
          )}
          <span
            className={`pill ${statusErr ? "bad" : zapOk ? "good" : "warn"}`}
            title={statusErr || status?.detail || status?.base_url}
          >
            <span className="dot" />
            {statusErr
              ? "API offline"
              : zapOk
                ? `ZAP ${status!.zap_version}`
                : status
                  ? "ZAP indisponível"
                  : "Conectando…"}
          </span>
          {status && !status.api_key_set && <span className="pill warn">sem API key</span>}
          <button className="icon-btn" onClick={loadStatus} title="Testar conexão">
            <RefreshCw size={16} />
          </button>
        </div>
      </header>

      <div className="layout">
        <aside className="side">
          <Allowlist
            hosts={status?.allowed_targets ?? []}
            onChange={(hosts) => setStatus((s) => (s ? { ...s, allowed_targets: hosts } : s))}
          />
          <RunForm
            status={status}
            running={running}
            stopRequested={!!job?.stop_requested}
            onStarted={() => {
              setTab("run");
              loadJob();
            }}
            onStop={() => api.stop().then(setJob).catch(() => undefined)}
          />
        </aside>

        <main className="main">
          {statusErr ? (
            <div className="banner bad">
              <AlertTriangle size={18} />
              <span>
                A API do painel não respondeu ({statusErr}). Rode <code>python -m zap_mcp.web</code>.
              </span>
            </div>
          ) : (
            status &&
            !zapOk && (
              <div className="banner warn">
                <AlertTriangle size={18} />
                <span>
                  O ZAP não respondeu em <code>{status.base_url}</code>. Abra o ZAP (ou{" "}
                  <code>docker compose up -d</code>) e clique em atualizar.
                </span>
                <button className="btn ghost small" onClick={loadStatus}>
                  <RefreshCw size={14} /> Atualizar
                </button>
              </div>
            )
          )}
          <nav className="tabs">
            {TABS.map((t) => (
              <button key={t.id} className={tab === t.id ? "on" : ""} onClick={() => setTab(t.id)}>
                {t.icon}
                {t.label}
                {t.id === "run" && running && <span className="dot live" />}
              </button>
            ))}
          </nav>
          {tab === "run" && <RunView job={job} />}
          {tab === "odata" && <ODataView />}
          {tab === "nuclei" && <NucleiView allowlist={status?.allowed_targets ?? []} />}
          {tab === "mobile" && <MobileView />}
          {tab === "alerts" && <AlertsView refreshKey={refreshKey} />}
          {tab === "endpoints" && <EndpointsView refreshKey={refreshKey} />}
          {tab === "reports" && <ReportsView refreshKey={refreshKey} />}
        </main>
      </div>
    </div>
  );
}
