import { useEffect, useMemo, useState } from "react";
import { AgGridReact } from "ag-grid-react";
import type { ColDef } from "ag-grid-community";
import { api, type Finding, type Run, type Summary } from "./api";

const money = (n: number) => "$" + n.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });

const LOSS_LABELS: Record<string, string> = {
  underpayment: "Underpaid orders",
  excess_discount: "Excess discount (beyond cap)",
  goods_unpaid: "Goods shipped unpaid",
  duplicate_refund: "Duplicate refunds",
  misdirected_funds: "Misdirected payouts",
  data_leak: "Data disclosed (no $ loss)",
};

const BASIS_LABELS: Record<string, string> = {
  uncollected_order_value: "uncollected order value",
  captured_loss: "captured loss (cash out)",
  estimated_exposure: "estimated exposure (merchant logic; PayPal rail may block)",
};

const TIER_LABELS: Record<string, string> = {
  architectural: "architectural",
  ai_judgment: "AI-judgment",
};
const tierColor = (t: string) => (t === "architectural" ? "#d4537e" : "#378add");

function ExposureBreakdown({ by }: { by: Record<string, number> }) {
  const kinds = Object.entries(by).filter(([k]) => k !== "none");
  if (!kinds.length) return null;
  return (
    <div className="text-xs opacity-80 mb-4 flex flex-wrap gap-x-4 gap-y-1">
      <span className="opacity-50">Exposure is a sum of distinct categories, not one blended number:</span>
      {kinds.map(([k, v]) => (
        <span key={k}>
          <b>{LOSS_LABELS[k] ?? k}</b> {money(v)}
        </span>
      ))}
    </div>
  );
}

function Tile({ run, kind }: { run: Run | null; kind: "vuln" | "hard" }) {
  const good = kind === "hard";
  const s = run?.stats;
  return (
    <div
      className="flex-1 rounded-xl p-5 border"
      style={{
        background: good ? "rgba(34,197,94,.08)" : "rgba(239,68,68,.08)",
        borderColor: good ? "rgba(34,197,94,.35)" : "rgba(239,68,68,.35)",
      }}
    >
      <div className="text-sm uppercase tracking-wide opacity-70">
        {good ? "Hardened store" : "Vulnerable store"}
      </div>
      {s ? (
        <>
          <div className="text-3xl font-bold mt-1">
            {good ? `${s.blocked}/${s.total} blocked` : `${s.succeeded}/${s.total} exploited`}
          </div>
          <div className="mt-1 text-lg" style={{ color: good ? "#22c55e" : "#ef4444" }}>
            {good ? "$0.00 lost" : `${money(s.amount_at_risk)} total exposure (sandbox)`}
          </div>
        </>
      ) : (
        <div className="text-sm opacity-60 mt-2">no run yet</div>
      )}
    </div>
  );
}

function Detail({ f }: { f: Finding | null }) {
  if (!f) return <div className="opacity-50 p-6">Select a finding to see the attack transcript, the PayPal API calls, and the fix.</div>;
  return (
    <div className="p-5 space-y-4 overflow-auto" style={{ maxHeight: "70vh" }}>
      <div>
        <div className="text-xs uppercase opacity-60">
          {f.attack} · {f.severity} · <span style={{ color: tierColor(f.tier) }}>{TIER_LABELS[f.tier] ?? f.tier}</span>
        </div>
        <h2 className="text-xl font-semibold">{f.title}</h2>
        <p className="opacity-80 mt-1">{f.summary}</p>
      </div>
      <div className="rounded-lg p-3" style={{ background: "rgba(59,130,246,.1)", border: "1px solid rgba(59,130,246,.3)" }}>
        <div className="text-xs uppercase opacity-70 mb-1">The fix</div>
        <div>{f.fix || "—"}</div>
        {f.invariant && (
          <div className="mt-2 text-xs">
            <span className="opacity-60">Invariant enforced: </span>
            <code style={{ background: "rgba(255,255,255,.08)", padding: "1px 5px", borderRadius: 4 }}>{f.invariant}</code>
          </div>
        )}
      </div>
      {f.loss_kind && f.loss_kind !== "none" && (
        <div className="text-xs opacity-70">
          Loss type: <b>{LOSS_LABELS[f.loss_kind] ?? f.loss_kind}</b> · {money(f.amount_at_risk)}{" "}
          <span className="opacity-60">({BASIS_LABELS[f.amount_basis] ?? f.amount_basis})</span>
        </div>
      )}
      {f.transaction_ids && Object.values(f.transaction_ids).some(Boolean) && (
        <div className="text-xs opacity-60">
          <span className="opacity-70">Transaction ids (check against the sandbox ledger): </span>
          {Object.entries(f.transaction_ids)
            .filter(([, v]) => v)
            .map(([k, v]) => `${k}=${v}`)
            .join(" · ")}
        </div>
      )}
      <div>
        <div className="text-xs uppercase opacity-60 mb-1">Attack transcript</div>
        <ol className="space-y-1">
          {f.transcript.map((t, i) => (
            <li key={i} className="text-sm rounded px-2 py-1" style={{ background: "rgba(255,255,255,.04)" }}>
              {t.step ? <b>{t.step}: </b> : t.role ? <b>{t.role}: </b> : null}
              {t.detail || t.content || (t.name ? `${t.name}(${JSON.stringify(t.input || {})}) → ${t.result ?? ""}` : JSON.stringify(t))}
            </li>
          ))}
        </ol>
      </div>
      <div>
        <div className="text-xs uppercase opacity-60 mb-1">PayPal / target API calls</div>
        <pre className="text-xs rounded p-2 overflow-auto" style={{ background: "rgba(255,255,255,.04)" }}>
          {JSON.stringify(f.api_calls, null, 2)}
        </pre>
      </div>
    </div>
  );
}

export default function App() {
  const [summary, setSummary] = useState<Summary | null>(null);
  const [runs, setRuns] = useState<Run[]>([]);
  const [runId, setRunId] = useState<string>("");
  const [run, setRun] = useState<Run | null>(null);
  const [selected, setSelected] = useState<Finding | null>(null);
  const [busy, setBusy] = useState(false);

  const refresh = async () => {
    const [s, r] = await Promise.all([api.summary(), api.runs()]);
    setSummary(s);
    setRuns(r);
    const target = runId || s.vulnerable?.id || r[0]?.id || "";
    if (target) {
      setRunId(target);
      setRun(await api.run(target));
    }
  };

  useEffect(() => { refresh().catch(console.error); }, []);
  useEffect(() => { if (runId) api.run(runId).then(setRun).catch(console.error); }, [runId]);

  const doRun = async (target: "vulnerable" | "hardened") => {
    setBusy(true);
    try {
      const r = await api.createRun(target);
      await refresh();
      setRunId(r.id);
    } finally {
      setBusy(false);
    }
  };

  const cols = useMemo<ColDef<Finding>[]>(() => [
    { field: "attack", headerName: "Attack", flex: 1 },
    {
      field: "status", headerName: "Result", width: 130,
      cellStyle: (p) => ({
        color: p.value === "SUCCEEDED" ? "#ef4444" : p.value === "BLOCKED" ? "#22c55e" : "#eab308",
        fontWeight: 600,
      }),
    },
    {
      field: "tier", headerName: "Tier", width: 130,
      valueFormatter: (p) => TIER_LABELS[p.value] ?? p.value,
      cellStyle: (p) => ({ color: tierColor(p.value), fontWeight: 600 }),
    },
    { field: "severity", headerName: "Severity", width: 100 },
    {
      field: "amount_at_risk", headerName: "$ at risk", width: 110,
      valueFormatter: (p) => money(p.value || 0),
      cellStyle: { textAlign: "right" },
    },
    { field: "summary", headerName: "What happened", flex: 2 },
  ], []);

  return (
    <div className="max-w-6xl mx-auto p-6">
      <header className="mb-5">
        <h1 className="text-2xl font-bold">Breakpoint</h1>
        <p className="opacity-70">
          A sandbox security test bench for AI-enabled checkout. It runs scripted and AI-driven
          attack scenarios against <b>Dusk Coffee</b> — a purpose-built, intentionally-vulnerable
          demo app — in the PayPal sandbox, shows the order/payment state each one caused, and the
          rule that fixes it.
        </p>
        <p className="opacity-40 text-xs mt-1">
          Scope: tests the bundled Dusk Coffee app only, never arbitrary stores. 2 scenarios are
          scripted checks; 4 (haggle, prompt-injection, data-exfiltration, rogue-payout) drive a live LLM against the shop assistant.
        </p>
        <p className="opacity-50 text-xs mt-1">
          Tier: <span style={{ color: tierColor("architectural") }}>architectural</span> = exploited
          regardless of the model (a system flaw); <span style={{ color: tierColor("ai_judgment") }}>AI-judgment</span>{" "}
          = depends on the model declining — fragile, which the hardened build removes.
        </p>
      </header>

      <div className="flex gap-4 mb-3">
        <Tile run={summary?.vulnerable ?? null} kind="vuln" />
        <Tile run={summary?.hardened ?? null} kind="hard" />
      </div>
      {summary?.vulnerable && <ExposureBreakdown by={summary.vulnerable.stats.exposure_by_kind} />}

      <div className="flex items-center gap-3 mb-3">
        <select
          className="rounded px-3 py-2"
          style={{ background: "#11161d", border: "1px solid #2a3340", color: "#e6edf3" }}
          value={runId}
          onChange={(e) => setRunId(e.target.value)}
        >
          {runs.map((r) => (
            <option key={r.id} value={r.id}>
              {r.label} — {r.stats.succeeded}/{r.stats.total} exploited · {money(r.stats.amount_at_risk)}
            </option>
          ))}
        </select>
        <button disabled={busy} onClick={() => doRun("vulnerable")}
          className="rounded px-3 py-2" style={{ background: "#7f1d1d", opacity: busy ? 0.6 : 1 }}>
          {busy ? "running…" : "Run vulnerable"}
        </button>
        <button disabled={busy} onClick={() => doRun("hardened")}
          className="rounded px-3 py-2" style={{ background: "#14532d", opacity: busy ? 0.6 : 1 }}>
          {busy ? "running…" : "Run hardened"}
        </button>
        <span className="text-xs opacity-50">LLM attacks take ~1 min</span>
      </div>

      <div className="grid" style={{ gridTemplateColumns: "1.3fr 1fr", gap: "1rem" }}>
        <div className="ag-theme-quartz-dark" style={{ height: "70vh" }}>
          <AgGridReact<Finding>
            rowData={run?.findings ?? []}
            columnDefs={cols}
            onRowClicked={(e) => setSelected(e.data ?? null)}
            rowStyle={{ cursor: "pointer" }}
          />
        </div>
        <div className="rounded-xl" style={{ background: "#0f141b", border: "1px solid #202833" }}>
          <Detail f={selected} />
        </div>
      </div>
    </div>
  );
}
