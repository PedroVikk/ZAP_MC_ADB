// Aba Mobile: prepara um aparelho Android (ADB) para o ZAP inspecionar o app —
// inclusive Flutter, que ignora o proxy e so confia na CA do sistema.
import { useEffect, useState } from "react";
import {
  Check,
  RefreshCw,
  Shield,
  Smartphone,
  TriangleAlert,
  Wifi,
  WifiOff,
} from "lucide-react";
import { api, type MobileGuidance, type MobileResult, type MobileStatus } from "./api";
import { Card, Empty } from "./ui";

export function MobileView() {
  const [status, setStatus] = useState<MobileStatus | null>(null);
  const [guide, setGuide] = useState<MobileGuidance | null>(null);
  const [host, setHost] = useState("");
  const [port, setPort] = useState(8080);
  const [serial, setSerial] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [out, setOut] = useState<MobileResult | null>(null);
  const [err, setErr] = useState("");

  const loadStatus = () => {
    api.mobileStatus().then(setStatus).catch(() => setStatus({ available: false }));
  };

  useEffect(() => {
    loadStatus();
    api.mobileGuidance().then(setGuide).catch(() => undefined);
  }, []);

  const act = async (name: string, fn: () => Promise<MobileResult>) => {
    setBusy(name);
    setErr("");
    setOut(null);
    try {
      const r = await fn();
      if (r.error) setErr(r.detail || r.error);
      else setOut(r);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(null);
      loadStatus();
    }
  };

  const devices = status?.devices ?? [];
  const hasDevice = devices.some((d) => d.state === "device");

  return (
    <div className="stack">
      <Card
        title="Aparelho (ADB)"
        icon={<Smartphone size={16} />}
        actions={
          <button className="btn ghost small" onClick={loadStatus}>
            <RefreshCw size={14} /> Atualizar
          </button>
        }
      >
        {status && !status.available ? (
          <p className="warn-text">
            <TriangleAlert size={14} /> ADB não encontrado ({status.detail}). Instale o
            platform-tools do Android ou defina <code>ADB_PATH</code>.
          </p>
        ) : (
          <>
            {status?.version && <p className="muted">{status.version}</p>}
            {devices.length === 0 ? (
              <Empty icon={<Smartphone size={28} />} title="Nenhum aparelho conectado">
                Conecte um aparelho com depuração USB, ou abra um emulador, e clique em Atualizar.
              </Empty>
            ) : (
              <table className="table compact">
                <thead>
                  <tr>
                    <th>Serial</th>
                    <th>Estado</th>
                    <th>Modelo</th>
                  </tr>
                </thead>
                <tbody>
                  {devices.map((d) => (
                    <tr key={d.serial}>
                      <td className="mono">{d.serial}</td>
                      <td className={d.state === "device" ? "ok" : "dim"}>{d.state}</td>
                      <td>{d.model || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </>
        )}
      </Card>

      {status?.available && (
        <Card title="Preparar o aparelho" icon={<Shield size={16} />}>
          {devices.length > 1 && (
            <label className="field">
              <span>Serial do aparelho</span>
              <input className="input" value={serial} onChange={(e) => setSerial(e.target.value)} placeholder="ex.: emulator-5554" />
            </label>
          )}
          <div className="row wrap">
            <button
              className="btn"
              disabled={!hasDevice || !!busy}
              onClick={() => act("ca", () => api.mobileInstallCa(serial))}
            >
              <Shield size={15} /> {busy === "ca" ? "Enviando…" : "Instalar CA do ZAP"}
            </button>
          </div>

          <div className="group">
            <div className="group-head">
              <Wifi size={15} /> Proxy global <small>WebViews / apps nativos (Flutter ignora)</small>
            </div>
            <div className="row">
              <input className="input" placeholder="IP da sua máquina (ex.: 192.168.0.10)" value={host} onChange={(e) => setHost(e.target.value)} />
              <input className="input" style={{ width: 90 }} type="number" value={port} onChange={(e) => setPort(Number(e.target.value))} />
            </div>
            <div className="row wrap">
              <button
                className="btn"
                disabled={!hasDevice || !!busy}
                onClick={() => act("proxy-on", () => api.mobileProxy({ enable: true, host, port, serial }))}
              >
                <Wifi size={15} /> Ativar proxy
              </button>
              <button
                className="btn ghost"
                disabled={!hasDevice || !!busy}
                onClick={() => act("proxy-off", () => api.mobileProxy({ enable: false, host, port, serial }))}
              >
                <WifiOff size={15} /> Remover proxy
              </button>
            </div>
          </div>

          {err && <p className="error-text">{err}</p>}
          {out && (
            <div className="prose">
              {out.http_proxy && (
                <p>
                  <Check size={14} /> Proxy: <b>{out.http_proxy}</b>
                  {out.nota && <> — {out.nota}</>}
                </p>
              )}
              {out.pushed_to && (
                <>
                  <p>
                    <Check size={14} /> CA enviada para <code>{out.pushed_to}</code>
                    {out.system_store_name && (
                      <> · nome no system store: <code>{out.system_store_name}</code></>
                    )}
                  </p>
                  <ol>
                    {(out.passos ?? []).map((p, i) => (
                      <li key={i}>{p}</li>
                    ))}
                  </ol>
                </>
              )}
            </div>
          )}
        </Card>
      )}

      {guide && (
        <Card title={guide.titulo} icon={<Smartphone size={16} />}>
          <p className="muted">{guide.porque}</p>
          <ol className="steps">
            {guide.passos.map((p, i) => (
              <li key={i}>{p}</li>
            ))}
          </ol>
          <div className="chips">
            {guide.ferramentas_externas.map((t) => (
              <span key={t} className="chip">
                {t}
              </span>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}
