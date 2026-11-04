/** Compliance evidence pack (follow-on): audit integrity + access evidence. */
export interface AuditRow { org_id: string; actor: string; action: string; entry_hash: string; prev_hash: string | null; created_at: string }

export function verifyAuditChain(rows: AuditRow[]): boolean {
  const sorted = [...rows].sort((a, b) => a.created_at.localeCompare(b.created_at));
  return sorted.every((r, i) => i === 0 || r.prev_hash === sorted[i - 1].entry_hash);
}

export interface ComplianceReport {
  orgId: string; generatedAt: string;
  auditEntries: number; chainValid: boolean;
  actionsByType: Record<string, number>;
  actors: string[];
  controls: { tenantIsolation: string; auditIntegrity: string; secretHandling: string };
}

export function complianceReport(orgId: string, rows: AuditRow[]): ComplianceReport {
  const actionsByType: Record<string, number> = {};
  for (const r of rows) actionsByType[r.action] = (actionsByType[r.action] ?? 0) + 1;
  return {
    orgId, generatedAt: new Date().toISOString(),
    auditEntries: rows.length,
    chainValid: verifyAuditChain(rows),
    actionsByType,
    actors: [...new Set(rows.map((r) => r.actor))].sort(),
    controls: {
      tenantIsolation: "Postgres RLS keyed on Clerk JWT org claim (auth.jwt()->'o'->>'id') on environments/deployments/runs/datasets/templates",
      auditIntegrity: "Hash-chained append-only audit_log (entry_hash + prev_hash trigger); chain verification in this report",
      secretHandling: "Per-run credentials in Supabase Vault; Clerk secret key server-side only; dataset export redaction policy versioned",
    },
  };
}
