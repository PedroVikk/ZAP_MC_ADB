// Pecas pequenas reaproveitadas pelas telas.
import type { ReactNode } from "react";

export const RISK_LABEL: Record<string, string> = {
  High: "Alto",
  Medium: "Médio",
  Low: "Baixo",
  Informational: "Info",
};

export function riskKey(risk?: string): string {
  return (risk || "Informational").split(" ")[0];
}

export function RiskBadge({ risk }: { risk?: string }) {
  const k = riskKey(risk);
  return <span className={`badge risk-${k}`}>{RISK_LABEL[k] ?? k}</span>;
}

export function Card({
  title,
  icon,
  actions,
  children,
  className = "",
}: {
  title?: ReactNode;
  icon?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`card ${className}`}>
      {(title || actions) && (
        <header className="card-head">
          <h2>
            {icon}
            {title}
          </h2>
          {actions && <div className="card-actions">{actions}</div>}
        </header>
      )}
      {children}
    </section>
  );
}

export function Toggle({
  checked,
  onChange,
  label,
  hint,
  danger,
  disabled,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label: string;
  hint?: string;
  danger?: boolean;
  disabled?: boolean;
}) {
  return (
    <label className={`toggle ${danger ? "danger" : ""} ${disabled ? "disabled" : ""}`}>
      <input
        type="checkbox"
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
      />
      <span className="track">
        <span className="thumb" />
      </span>
      <span className="toggle-text">
        <span>{label}</span>
        {hint && <small>{hint}</small>}
      </span>
    </label>
  );
}

export function Progress({ value, tone = "accent" }: { value?: number; tone?: string }) {
  const indeterminate = value === undefined;
  return (
    <div className={`progress tone-${tone} ${indeterminate ? "indeterminate" : ""}`}>
      <div style={indeterminate ? undefined : { width: `${Math.min(100, value)}%` }} />
    </div>
  );
}

export function Metric({ label, value, tone }: { label: string; value: ReactNode; tone?: string }) {
  return (
    <div className={`metric ${tone ? `tone-${tone}` : ""}`}>
      <span className="metric-value">{value}</span>
      <span className="metric-label">{label}</span>
    </div>
  );
}

export function Empty({ icon, title, children }: { icon: ReactNode; title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <div className="empty-icon">{icon}</div>
      <h3>{title}</h3>
      {children && <p>{children}</p>}
    </div>
  );
}

export function fmtDuration(seconds: number): string {
  const s = Math.max(0, Math.round(seconds));
  const m = Math.floor(s / 60);
  return m ? `${m}min ${String(s % 60).padStart(2, "0")}s` : `${s}s`;
}
