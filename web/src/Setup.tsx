// Coluna da esquerda: alvos autorizados (o freio) e o formulario do teste.
import { useState } from "react";
import {
  Bug,
  Clock,
  Compass,
  KeyRound,
  Lock,
  Play,
  Plus,
  Radar,
  ShieldAlert,
  Square,
  X,
} from "lucide-react";
import { api, type RunParams, type Status } from "./api";
import { Card, Toggle, fmtDuration } from "./ui";

function hostOf(url: string): string {
  try {
    return new URL(url.includes("://") ? url : `http://${url}`).hostname.toLowerCase();
  } catch {
    return "";
  }
}

function isAllowed(target: string, allow: string[]): boolean {
  const h = hostOf(target);
  return !!h && allow.some((a) => h === a || h.endsWith(`.${a}`));
}

export function Allowlist({
  hosts,
  onChange,
}: {
  hosts: string[];
  onChange: (hosts: string[]) => void;
}) {
  const [draft, setDraft] = useState("");
  const [err, setErr] = useState("");

  const save = async (next: string[]) => {
    try {
      setErr("");
      const r = await api.setAllowlist(next);
      onChange(r.allowed_targets);
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  const add = () => {
    const h = hostOf(draft.trim());
    if (!h) return;
    setDraft("");
    if (!hosts.includes(h)) save([...hosts, h]);
  };

  return (
    <Card
      title="Alvos autorizados"
      icon={<Lock size={16} />}
      actions={
        hosts.length > 0 && (
          <button className="btn ghost small" onClick={() => save([])} title="Bloqueia tudo">
            Bloquear tudo
          </button>
        )
      }
    >
      <p className="muted">
        Bloqueado por padrão: o teste só roda contra estes hosts (e subdomínios). Vale só nesta
        sessão; o <code>.env</code> não é alterado.
      </p>
      <div className="chips">
        {hosts.length === 0 && <span className="chip blocked">Lista vazia — tudo bloqueado</span>}
        {hosts.map((h) => (
          <span key={h} className="chip">
            {h}
            <button aria-label={`Remover ${h}`} onClick={() => save(hosts.filter((x) => x !== h))}>
              <X size={12} />
            </button>
          </span>
        ))}
      </div>
      <div className="row">
        <input
          className="input"
          placeholder="host.exemplo.com"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && add()}
        />
        <button className="btn" onClick={add} disabled={!draft.trim()}>
          <Plus size={16} /> Adicionar
        </button>
      </div>
      {err && <p className="error-text">{err}</p>}
    </Card>
  );
}

const DEFAULTS: RunParams = {
  target: "https://localhost:5001/index.html",
  explore: true,
  headless: false,
  route_sweep: true,
  crud: false,
  max_seconds: 150,
  max_actions: 300,
  login_user: "",
  login_pass: "",
  spider: false,
  active: false,
  confirm_active: false,
  report_format: "html",
};

export function RunForm({
  status,
  running,
  stopRequested,
  onStarted,
  onStop,
}: {
  status: Status | null;
  running: boolean;
  stopRequested: boolean;
  onStarted: () => void;
  onStop: () => void;
}) {
  const [p, setP] = useState<RunParams>(DEFAULTS);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const set = <K extends keyof RunParams>(k: K, v: RunParams[K]) => setP((o) => ({ ...o, [k]: v }));

  const allow = status?.allowed_targets ?? [];
  const allowed = isAllowed(p.target, allow);
  const nothing = !p.explore && !p.spider && !p.active;

  let estimate = 0;
  if (p.explore) estimate += p.max_seconds + 20;
  if (p.spider) estimate += 60;
  if (p.active) estimate += status?.max_scan_seconds ?? 900;

  const blocker = !p.target.trim()
    ? "Informe o alvo."
    : !allowed
      ? `${hostOf(p.target) || "Alvo"} não está nos alvos autorizados.`
      : nothing
        ? "Marque pelo menos uma ação."
        : p.active && !p.confirm_active
          ? "Confirme o scan ativo."
          : "";

  const start = async () => {
    setBusy(true);
    setErr("");
    try {
      await api.start(p);
      onStarted();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card title="Novo teste" icon={<Radar size={16} />}>
      <label className="field">
        <span>Alvo (URL)</span>
        <input
          className={`input ${p.target && !allowed ? "invalid" : ""}`}
          value={p.target}
          onChange={(e) => set("target", e.target.value)}
          spellCheck={false}
        />
      </label>

      <div className="group">
        <div className="group-head">
          <Compass size={15} /> Explorador <small>Playwright · navega o SPA pelo proxy</small>
        </div>
        <Toggle checked={p.explore} onChange={(v) => set("explore", v)} label="Rodar explorador" />
        <div className={`group-body ${p.explore ? "" : "off"}`}>
          <Toggle
            checked={!p.headless}
            onChange={(v) => set("headless", !v)}
            label="Ver o navegador ao vivo"
            hint="Desligado = headless"
            disabled={!p.explore}
          />
          <Toggle
            checked={p.route_sweep}
            onChange={(v) => set("route_sweep", v)}
            label="Varredura por rotas (UI5)"
            hint="Lê o manifest e visita cada tela"
            disabled={!p.explore}
          />
          <Toggle
            checked={p.crud}
            onChange={(v) => set("crud", v)}
            label="Testar CRUD"
            hint="Cria, edita e exclui registros — só em base de teste"
            danger
            disabled={!p.explore}
          />
          <div className="sliders">
            <label className="field">
              <span>
                Orçamento de tempo <b>{p.max_seconds}s</b>
              </span>
              <input
                type="range"
                min={30}
                max={600}
                step={10}
                value={p.max_seconds}
                disabled={!p.explore}
                onChange={(e) => set("max_seconds", Number(e.target.value))}
              />
            </label>
            <label className="field">
              <span>
                Máximo de ações <b>{p.max_actions}</b>
              </span>
              <input
                type="range"
                min={50}
                max={1000}
                step={50}
                value={p.max_actions}
                disabled={!p.explore}
                onChange={(e) => set("max_actions", Number(e.target.value))}
              />
            </label>
          </div>
          <div className="group-sub">
            <KeyRound size={14} /> Login (opcional)
          </div>
          <div className="row">
            <input
              className="input"
              placeholder="usuário"
              autoComplete="off"
              value={p.login_user}
              disabled={!p.explore}
              onChange={(e) => set("login_user", e.target.value)}
            />
            <input
              className="input"
              type="password"
              placeholder="senha"
              autoComplete="new-password"
              value={p.login_pass}
              disabled={!p.explore}
              onChange={(e) => set("login_pass", e.target.value)}
            />
          </div>
          {p.explore && p.login_user && !p.login_pass && (
            <p className="warn-text">Usuário sem senha — o explorador não vai conseguir entrar.</p>
          )}
        </div>
      </div>

      <div className="group">
        <div className="group-head">
          <Bug size={15} /> ZAP
        </div>
        <Toggle checked={p.spider} onChange={(v) => set("spider", v)} label="Spider" hint="Crawler clássico" />
        <Toggle
          checked={p.active}
          onChange={(v) => setP((o) => ({ ...o, active: v, confirm_active: false }))}
          label="Scan ATIVO"
          hint="Envia ataques reais"
          danger
        />
        {p.active && (
          <label className="confirm">
            <input
              type="checkbox"
              checked={p.confirm_active}
              onChange={(e) => set("confirm_active", e.target.checked)}
            />
            <ShieldAlert size={16} />
            <span>
              Confirmo que tenho autorização para atacar <b>{hostOf(p.target) || "este alvo"}</b> e
              que ele é descartável.
            </span>
          </label>
        )}
        <label className="field inline">
          <span>Relatório</span>
          <select
            className="input"
            value={p.report_format}
            onChange={(e) => set("report_format", e.target.value as RunParams["report_format"])}
          >
            <option value="html">HTML</option>
            <option value="md">Markdown</option>
            <option value="json">JSON</option>
          </select>
        </label>
      </div>

      <div className="estimate">
        <Clock size={14} /> Tempo estimado: <b>~{fmtDuration(estimate)}</b>
        {p.active && <small> · o scan ativo varia com o tamanho do site</small>}
      </div>

      {running ? (
        <button className="btn danger block" onClick={onStop} disabled={stopRequested}>
          <Square size={16} /> {stopRequested ? "Parando…" : "Parar teste"}
        </button>
      ) : (
        <button className="btn primary block" onClick={start} disabled={!!blocker || busy}>
          <Play size={16} /> Rodar teste
        </button>
      )}
      {!running && blocker && <p className="muted center">{blocker}</p>}
      {err && <p className="error-text">{err}</p>}
    </Card>
  );
}
