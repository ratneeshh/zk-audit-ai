import { useEffect, useState } from "react";
import {
  ShieldCheck, ShieldAlert, Loader2, Play, CheckCircle2, XCircle, Link2, Cpu,
} from "lucide-react";
import { api, type AuditDetail, type AuditRow, type Verification } from "./api";

const SAMPLE = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        balances[msg.sender] -= amount;
    }
}
`;

const SEVERITY: Record<string, string> = {
  critical: "bg-red-500/20 text-red-300 border-red-500/40",
  high: "bg-orange-500/20 text-orange-300 border-orange-500/40",
  medium: "bg-yellow-500/20 text-yellow-300 border-yellow-500/40",
  low: "bg-sky-500/20 text-sky-300 border-sky-500/40",
};

const short = (h: string) => `${h.slice(0, 10)}…${h.slice(-6)}`;

function Check({ ok, label }: { ok: boolean; label: string }) {
  return (
    <div className="flex items-center gap-2 text-sm">
      {ok ? (
        <CheckCircle2 className="h-4 w-4 text-emerald-400" />
      ) : (
        <XCircle className="h-4 w-4 text-red-400" />
      )}
      <span className={ok ? "text-slate-300" : "text-red-300"}>{label}</span>
    </div>
  );
}

export default function App() {
  const [source, setSource] = useState(SAMPLE);
  const [history, setHistory] = useState<AuditRow[]>([]);
  const [detail, setDetail] = useState<AuditDetail | null>(null);
  const [verification, setVerification] = useState<Verification | null>(null);
  const [busy, setBusy] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = async () => setHistory(await api.list());

  const open = async (id: string) => {
    setVerification(null);
    setDetail(await api.get(id));
  };

  useEffect(() => {
    refresh().catch((e) => setError(e.message));
  }, []);

  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      const r = await api.run(source);
      await refresh();
      await open(r.auditId);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const verify = async () => {
    if (!detail) return;
    setVerifying(true);
    setError(null);
    try {
      setVerification(await api.verify(detail.audit.auditId));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setVerifying(false);
    }
  };

  return (
    <div className="mx-auto max-w-7xl p-4 sm:p-6">
      <header className="mb-6 flex items-center gap-3">
        <ShieldCheck className="h-8 w-8 text-emerald-400" />
        <div>
          <h1 className="text-xl font-semibold">ZK-Audit-AI</h1>
          <p className="text-sm text-slate-400">
            Local AST masking, LLM audit, ZK node proofs, signed hash-chained receipts
          </p>
        </div>
      </header>

      {error && (
        <div className="mb-4 rounded-lg border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-300">
          {error}
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-[260px_1fr]">
        <aside className="rounded-xl border border-slate-800 bg-slate-900 p-3">
          <h2 className="mb-2 text-sm font-medium text-slate-400">Audit history</h2>
          <ul className="space-y-1">
            {history.length === 0 && (
              <li className="text-sm text-slate-500">No audits yet</li>
            )}
            {history.map((a) => (
              <li key={a.auditId}>
                <button
                  onClick={() => open(a.auditId)}
                  className={`w-full rounded-lg px-3 py-2 text-left text-sm hover:bg-slate-800 ${
                    detail?.audit.auditId === a.auditId ? "bg-slate-800" : ""
                  }`}
                >
                  <div className="font-medium">Audit #{a.seq}</div>
                  <div className="text-xs text-slate-500">
                    {new Date(a.createdAt).toLocaleString()}
                    {a.usedFallback && " · rules"}
                  </div>
                </button>
              </li>
            ))}
          </ul>
        </aside>

        <main className="space-y-6">
          <section className="rounded-xl border border-slate-800 bg-slate-900 p-4">
            <div className="mb-2 flex items-center justify-between">
              <h2 className="text-sm font-medium text-slate-400">
                Solidity source (never leaves this machine unmasked)
              </h2>
              <button
                onClick={run}
                disabled={busy || !source.trim()}
                className="flex items-center gap-2 rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium hover:bg-emerald-500 disabled:opacity-50"
              >
                {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
                {busy ? "Auditing…" : "Run audit"}
              </button>
            </div>
            <textarea
              value={source}
              onChange={(e) => setSource(e.target.value)}
              spellCheck={false}
              className="h-64 w-full rounded-lg border border-slate-800 bg-slate-950 p-3 font-mono text-xs text-slate-200 outline-none focus:border-emerald-600"
            />
          </section>

          {detail && (
            <>
              <section className="rounded-xl border border-slate-800 bg-slate-900 p-4">
                <h2 className="mb-3 flex items-center gap-2 text-sm font-medium text-slate-400">
                  <ShieldAlert className="h-4 w-4" /> Findings ({detail.findings.length})
                </h2>
                {detail.findings.length === 0 && (
                  <p className="text-sm text-slate-500">No findings reported.</p>
                )}
                <div className="space-y-3">
                  {detail.findings.map((f) => (
                    <article key={f.findingId} className="rounded-lg border border-slate-800 bg-slate-950 p-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className={`rounded border px-2 py-0.5 text-xs uppercase ${SEVERITY[f.severity] ?? ""}`}>
                          {f.severity}
                        </span>
                        <h3 className="font-medium">{f.vulnerabilityType}</h3>
                      </div>
                      <div className="mt-1 flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-500">
                        <span>confidence {f.confidenceScore}</span>
                        <span>node #{f.nodeId}</span>
                        {f.line && <span>line {f.line}</span>}
                        <span>source: {f.source}</span>
                        <span className={f.zkProofVerified ? "text-emerald-400" : "text-red-400"}>
                          <Cpu className="mr-1 inline h-3 w-3" />
                          {f.zkProofVerified ? "ZK node proof verified" : "no valid proof"}
                        </span>
                      </div>
                      {f.aiExplanation && (
                        <p className="mt-2 text-sm text-slate-300">{f.aiExplanation}</p>
                      )}
                      {f.maskedCodeSnippet && (
                        <pre className="mt-2 overflow-x-auto rounded bg-slate-900 p-2 text-xs text-slate-400">
                          {f.maskedCodeSnippet}
                        </pre>
                      )}
                    </article>
                  ))}
                </div>
              </section>

              <section className="rounded-xl border border-slate-800 bg-slate-900 p-4">
                <div className="mb-3 flex items-center justify-between">
                  <h2 className="flex items-center gap-2 text-sm font-medium text-slate-400">
                    <Link2 className="h-4 w-4" /> Receipt #{detail.audit.seq}
                  </h2>
                  <button
                    onClick={verify}
                    disabled={verifying}
                    className="flex items-center gap-2 rounded-lg border border-slate-700 px-3 py-1.5 text-sm hover:bg-slate-800 disabled:opacity-50"
                  >
                    {verifying && <Loader2 className="h-4 w-4 animate-spin" />}
                    Verify receipt
                  </button>
                </div>
                <dl className="grid gap-x-6 gap-y-1 text-xs sm:grid-cols-[140px_1fr]">
                  {(
                    [
                      ["AST root", detail.audit.astRootHash],
                      ["Source hash", detail.audit.repositoryHash],
                      ["Receipt hash", detail.audit.receiptHash],
                      ["Previous receipt", detail.audit.prevReceiptHash],
                      ["Signature", detail.audit.signature],
                    ] as const
                  ).map(([k, v]) => (
                    <div key={k} className="contents">
                      <dt className="text-slate-500">{k}</dt>
                      <dd className="font-mono text-slate-300" title={v}>{short(v)}</dd>
                    </div>
                  ))}
                </dl>

                {verification && (
                  <div
                    className={`mt-4 rounded-lg border p-3 ${
                      verification.valid
                        ? "border-emerald-500/40 bg-emerald-500/10"
                        : "border-red-500/40 bg-red-500/10"
                    }`}
                  >
                    <p className="mb-2 font-medium">
                      {verification.valid ? "Receipt is intact" : "Verification failed: tampering detected"}
                    </p>
                    <div className="grid gap-1 sm:grid-cols-2">
                      <Check ok={verification.checks.hashOk} label="Receipt hash matches stored data" />
                      <Check ok={verification.checks.signatureOk} label="Signature valid" />
                      <Check ok={verification.checks.chainOk} label="Linked to previous receipt" />
                      <Check
                        ok={verification.checks.proofsOk}
                        label={`ZK proofs valid (${verification.checks.proofCount})`}
                      />
                    </div>
                  </div>
                )}
              </section>
            </>
          )}
        </main>
      </div>
    </div>
  );
}
