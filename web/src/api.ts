export interface AuditRow {
  auditId: string;
  seq: number;
  status: string;
  usedFallback: boolean;
  createdAt: string;
}

export interface Finding {
  findingId: string;
  vulnerabilityType: string;
  severity: string;
  confidenceScore: string | null;
  nodeId: number;
  line: number | null;
  maskedCodeSnippet: string | null;
  aiExplanation: string | null;
  source: string;
  zkProofVerified: boolean;
}

export interface AuditDetail {
  audit: AuditRow & {
    astRootHash: string;
    repositoryHash: string;
    receiptHash: string;
    prevReceiptHash: string;
    signature: string;
    receiptTs: string;
  };
  findings: Finding[];
}

export interface Verification {
  auditId: string;
  valid: boolean;
  checks: {
    hashOk: boolean;
    signatureOk: boolean;
    chainOk: boolean;
    proofsOk: boolean;
    proofCount: number;
  };
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch("/api" + path, init);
  const body: any = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body.error ?? body.message ?? `HTTP ${r.status}`);
  return body as T;
}

export const api = {
  list: () => req<AuditRow[]>("/audits"),
  get: (id: string) => req<AuditDetail>(`/audits/${id}`),
  verify: (id: string) => req<Verification>(`/audits/${id}/verify`),
  run: (source: string) =>
    req<{ auditId: string }>("/audits", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ source }),
    }),
};
