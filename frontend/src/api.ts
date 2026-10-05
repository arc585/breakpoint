export type Finding = {
  id: string;
  attack: string;
  title: string;
  status: "SUCCEEDED" | "BLOCKED" | "ERROR";
  severity: string;
  amount_at_risk: number;
  currency: string;
  summary: string;
  fix: string;
  transcript: any[];
  api_calls: any[];
  evidence: Record<string, any>;
};

export type Stats = { total: number; succeeded: number; blocked: number; amount_at_risk: number };
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

const j = async (r: Response) => {
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
  return r.json();
};

export const api = {
  runs: (): Promise<Run[]> => fetch("/api/runs").then(j),
  run: (id: string): Promise<Run> => fetch(`/api/runs/${id}`).then(j),
  summary: (): Promise<Summary> => fetch("/api/summary").then(j),
  createRun: (target: "vulnerable" | "hardened", only?: string[]): Promise<Run> =>
    fetch("/api/runs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, live: false, only }),
    }).then(j),
};
