// Card de Sessão (sidebar): loga uma vez e o OData e o Nuclei reusam os cookies,
// sem colar nada na mão. Fica visível em todas as abas.
import { useEffect, useState } from "react";
import { KeyRound, LogIn, LogOut, Loader2, Check } from "lucide-react";
import { api, type SessionStatus } from "./api";
import { Card } from "./ui";

export function SessionCard({ defaultUrl }: { defaultUrl: string }) {
  const [st, setSt] = useState<SessionStatus | null>(null);
  const [open, setOpen] = useState(false);
  const [url, setUrl] = useState(defaultUrl);
  const [user, setUser] = useState("");
  const [pass, setPass] = useState("");
  const [company, setCompany] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const load = () => api.session().then(setSt).catch(() => undefined);
  useEffect(() => {
    load();
  }, []);
  useEffect(() => {
    if (!url && defaultUrl) setUrl(defaultUrl);
  }, [defaultUrl, url]);

  const active = !!st?.sessao_ativa;

  const login = async () => {
    setBusy(true);
    setErr("");
    try {
      const r = await api.sessionLogin({ login_url: url, username: user, password: pass, company });
      setSt(r);
      if (r.error) setErr(r.detail || r.error);
      else if (r.sessao_ativa) setOpen(false);
      else setErr(`Login não confirmado: ${r.login_status || "sem cookies"}`);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
      load();
    }
  };

  const logout = async () => {
    await api.sessionClear().then(setSt).catch(() => undefined);
    setOpen(false);
  };

  return (
    <Card title="Sessão" icon={<KeyRound size={16} />}>
      <div className="session-status">
        <span className={`dot ${active ? "" : "off"}`} />
        {active ? (
          <span>
            Autenticado · <b>{st?.cookie_names.length ?? 0}</b> cookies
          </span>
        ) : (
          <span className="muted">Sem sessão — OData e Nuclei vão sem login</span>
        )}
      </div>
      {active && (
        <p className="muted small">
          OData e Nuclei usam esta sessão automaticamente.
          {st?.login_status ? ` (${st.login_status})` : ""}
        </p>
      )}

      {!open && !active && (
        <button className="btn block" onClick={() => setOpen(true)}>
          <LogIn size={15} /> Entrar
        </button>
      )}
      {active && (
        <div className="row">
          <button className="btn ghost small" onClick={() => setOpen((o) => !o)}>
            Entrar de novo
          </button>
          <button className="btn ghost small" onClick={logout}>
            <LogOut size={14} /> Sair
          </button>
        </div>
      )}

      {open && (
        <div className="session-form">
          <label className="field">
            <span>URL de login</span>
            <input className="input" value={url} onChange={(e) => setUrl(e.target.value)} spellCheck={false} />
          </label>
          <div className="row">
            <input className="input" placeholder="usuário" autoComplete="off" value={user} onChange={(e) => setUser(e.target.value)} />
            <input className="input" type="password" placeholder="senha" autoComplete="new-password" value={pass} onChange={(e) => setPass(e.target.value)} />
          </div>
          <input className="input" placeholder="empresa (opcional)" value={company} onChange={(e) => setCompany(e.target.value)} />
          <div className="row">
            <button className="btn primary" onClick={login} disabled={busy || !url.trim() || !user.trim()}>
              {busy ? <Loader2 size={15} className="spin" /> : <Check size={15} />} Entrar e capturar
            </button>
            <button className="btn ghost small" onClick={() => setOpen(false)} disabled={busy}>
              Cancelar
            </button>
          </div>
          <p className="muted small">
            Abre o navegador, loga e guarda os cookies (em memória). Passa a tela de empresa, se houver.
          </p>
        </div>
      )}
      {err && <p className="error-text">{err}</p>}
    </Card>
  );
}
