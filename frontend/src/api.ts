export type Finding = {
  id: string;
  attack: string;
  title: string;
  status: "SUCCEEDED" | "BLOCKED" | "ERROR";
  severity: string;
  amount_at_risk: number;
  loss_kind: string;
  amount_basis: string;
  currency: string;
  summary: string;
  fix: string;
  invariant: string;
  transaction_ids: Record<string, any>;
  transcript: any[];
  api_calls: any[];
  evidence: Record<string, any>;
};

export type Stats = {
  total: number;
  succeeded: number;
  blocked: number;
  amount_at_risk: number;
  exposure_by_kind: Record<string, number>;
  exposure_by_basis: Record<string, number>;
};
export type Run = {
  id: string;
  created_at: number;
  posture: Record<string, boolean>;
  is_hardened: boolean;
  label: string;
  stats: Stats;
  findings?: Finding[];
};
export type Summary = { vulnerable: Run | null; hardened: Run | null };

// Dev: "" → relative /api via the Vite proxy. Prod: set VITE_API_BASE to the
// deployed API origin at build time.
const BASE = (import.meta.env.VITE_API_BASE ?? "").replace(/\/$/, "");

const j = async (r: Response) => {
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
  return r.json();
};

export const api = {
  runs: (): Promise<Run[]> => fetch(`${BASE}/api/runs`).then(j),
  run: (id: string): Promise<Run> => fetch(`${BASE}/api/runs/${id}`).then(j),
  summary: (): Promise<Summary> => fetch(`${BASE}/api/summary`).then(j),
  createRun: (target: "vulnerable" | "hardened", only?: string[]): Promise<Run> =>
    fetch(`${BASE}/api/runs`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, live: false, only }),
    }).then(j),
};
