// Cliente da API Python (src/zap_mcp/web.py).

export type Risk = "High" | "Medium" | "Low" | "Informational";

export interface Status {
  zap_version?: string;
  base_url: string;
  api_key_set: boolean;
  max_scan_seconds?: number;
  allowed_targets: string[];
  error?: string;
  detail?: string;
}

export interface RunParams {
  target: string;
  explore: boolean;
  headless: boolean;
  route_sweep: boolean;
  crud: boolean;
  max_seconds: number;
  max_actions: number;
  login_user: string;
  login_pass: string;
  spider: boolean;
  active: boolean;
  confirm_active: boolean;
  report_format: "html" | "json" | "md";
}

export interface LogLine {
  t: number;
  level: "info" | "ok" | "warn" | "error";
  msg: string;
}

export interface CrudRow {
  tela: string;
  campos_preenchidos?: number;
  create?: string | null;
  view?: string | null;
  edit?: string | null;
  delete?: string | null;
  erro?: string;
}

export interface Job {
  id: string;
  params: Omit<RunParams, "login_pass">;
  phase: string;
  phases: string[];
  failed: string[];
  running: boolean;
  stop_requested: boolean;
  started_at: number;
  finished_at: number | null;
  log: LogLine[];
  explore: {
    page_title?: string;
    login_status?: string;
    actions?: number;
    requests_total?: number;
    routes_found?: number;
    routes_visited?: string[];
    stopped?: boolean;
    crud?: CrudRow[];
  } | null;
  spider: { progress: number; status: string } | null;
  active: {
    progresso: number;
    ataques_enviados: number;
    alertas: number;
    rodando: { ataque: string; reqs?: number }[];
    concluido: boolean;
  } | null;
  report: { path?: string; by_risk?: Record<Risk, number>; detail?: string } | null;
  error: string | null;
}

export interface AlertGroup {
  name: string;
  risk: Risk;
  count: number;
  example_url?: string;
  cweid?: string;
  example_alert_id?: string;
}

export interface Alerts {
  total: number;
  by_risk: Record<Risk, number>;
  groups: AlertGroup[];
  error?: string;
  detail?: string;
}

export interface AlertDetail {
  name: string;
  risk: string;
  confidence?: string;
  url?: string;
  param?: string;
  attack?: string;
  evidence?: string;
  cweid?: string;
  description?: string;
  solution?: string;
  reference?: string;
  request?: { header?: string; body?: string };
  response?: { header?: string; body?: string };
  error?: string;
  detail?: string;
}

export interface UrlEntry {
  url: string;
  is_api: boolean;
  has_params: boolean;
}

export interface Urls {
  total_urls: number;
  endpoints: UrlEntry[];
  pages: UrlEntry[];
  error?: string;
  detail?: string;
}

export interface ReportFile {
  name: string;
  size: number;
  mtime: number;
}

export interface ODataEntitySet {
  entityset: string;
  keys: string[];
  props: number;
  navs: number;
}

export interface ODataResult {
  service_root?: string;
  odata_version?: string;
  entitysets?: number;
  requests_planned?: number;
  includes_writes?: boolean;
  discovered?: ODataEntitySet[];
  requests?: { method: string; kind: string; entityset: string; path: string }[];
  sent?: number;
  failed?: number;
  csrf_token?: string;
  by_status?: Record<string, number>;
  results?: { method: string; kind: string; entityset: string; status: number; path: string }[];
  status?: string;
  message?: string;
  error?: string;
  detail?: string;
}

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: init?.body ? { "Content-Type": "application/json" } : undefined,
  });
  const data = await res.json().catch(() => null);
  if (!res.ok) throw new Error(data?.error || `HTTP ${res.status}`);
  return data as T;
}

const json = (method: string, body: unknown): RequestInit => ({
  method,
  body: JSON.stringify(body),
});

export const api = {
  status: () => call<Status>("/api/status"),
  setAllowlist: (hosts: string[]) =>
    call<{ allowed_targets: string[] }>("/api/allowlist", json("PUT", { hosts })),
  job: () => call<Job | null>("/api/run"),
  start: (p: RunParams) => call<Job>("/api/run", json("POST", p)),
  stop: () => call<Job>("/api/run/stop", { method: "POST" }),
  alerts: (minRisk: string) =>
    call<Alerts>(`/api/alerts?min_risk=${encodeURIComponent(minRisk)}`),
  alert: (id: string) => call<AlertDetail>(`/api/alerts/${encodeURIComponent(id)}`),
  urls: () => call<Urls>("/api/urls"),
  reports: () => call<ReportFile[]>("/api/reports"),
  odataDiscover: (metadata_url: string) =>
    call<ODataResult>("/api/odata/discover", json("POST", { metadata_url })),
  odataProbe: (p: {
    metadata_url: string;
    include_writes: boolean;
    confirm: boolean;
    username: string;
    password: string;
  }) => call<ODataResult>("/api/odata/probe", json("POST", p)),
  makeReport: (kind: "zap" | "endpoints", format = "html") =>
    call<{ path?: string; error?: string; detail?: string }>(
      "/api/reports",
      json("POST", { kind, format }),
    ),
};
