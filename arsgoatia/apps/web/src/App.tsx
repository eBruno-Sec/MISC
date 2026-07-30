import React, { useEffect, useState, useCallback } from "react";

// ---------------------------------------------------------------------------
// Color system — Squid Game-inspired severity escalation
// ---------------------------------------------------------------------------
const C = {
  pink: "#F0A0BC",
  pinkLight: "#F8D0DF",
  mint: "#4ECDC4",
  mintLight: "#A8E6CF",
  cream: "#FFF8E7",
  guard: "#C0392B",
  blood: "#8B1A1A",
  dark: "#1A1A2E",
  darkSurface: "#16213E",
  text: "#E8E8E8",
  textMuted: "#9BA4B5",
  border: "#2C3E50",
  surface: "#1E2A3A",
  surfaceHover: "#243447",
};

const RISK_COLORS: Record<string, string> = {
  R0: C.mint,
  R1: "#52C7A0",
  R2: C.pink,
  R3: "#E74C3C",
  R4: C.guard,
  R5: C.blood,
};

const STATE_COLORS: Record<string, string> = {
  DRAFT: C.textMuted,
  AUTHORIZATION_PENDING: "#F39C12",
  SCOPE_COMPILED: "#F39C12",
  READY: C.mint,
  RUNNING: C.mint,
  PAUSED: "#F39C12",
  REPORTING: C.pink,
  CLEANUP_PENDING: "#F39C12",
  STOPPING: C.guard,
  COMPLETED: C.mint,
  FAILED: C.guard,
};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
type View =
  | "dashboard"
  | "engagements"
  | "actions"
  | "approvals"
  | "evidence"
  | "findings"
  | "reports"
  | "system";

interface HealthStatus {
  status: string;
  service: string;
}

interface EngagementSummary {
  id: string;
  name: string;
  state: string;
  created_at: string;
  updated_at: string;
  tags: Record<string, string>;
}

interface FindingSummary {
  id: string;
  engagement_id: string;
  weakness: string;
  affected_object: string;
  severity: number;
  confidence: number;
  state: string;
  created_at: string;
}

// ---------------------------------------------------------------------------
// API helpers
// ---------------------------------------------------------------------------
const TENANT_ID = "00000000-0000-0000-0000-000000000001";

async function apiFetch<T>(path: string): Promise<T | null> {
  try {
    const r = await fetch(`/api/v1${path}`, {
      headers: { "X-Tenant-Id": TENANT_ID },
    });
    if (!r.ok) return null;
    return await r.json();
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------
function useHealth() {
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(() => {
    setLoading(true);
    fetch("/api/v1/health")
      .then((r) => (r.ok ? r.json() : null))
      .then(setHealth)
      .catch(() => setHealth(null))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    refresh();
    const iv = setInterval(refresh, 15000);
    return () => clearInterval(iv);
  }, [refresh]);

  return { health, loading, refresh };
}

function useEngagements() {
  const [data, setData] = useState<{
    items: EngagementSummary[];
    total: number;
  } | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(() => {
    setLoading(true);
    apiFetch<{ items: EngagementSummary[]; total: number }>("/engagements")
      .then(setData)
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  return { data, loading, refresh };
}

function useFindings() {
  const [data, setData] = useState<{
    items: FindingSummary[];
    total: number;
  } | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    apiFetch<{ items: FindingSummary[]; total: number }>("/findings").then(
      (d) => {
        setData(d);
        setLoading(false);
      },
    );
  }, []);

  return { data, loading };
}

// ---------------------------------------------------------------------------
// Components
// ---------------------------------------------------------------------------

function RiskBadge({ tier }: { tier: string }) {
  const color = RISK_COLORS[tier] || C.textMuted;
  return (
    <span
      style={{
        display: "inline-block",
        padding: "2px 8px",
        borderRadius: "4px",
        fontSize: "0.7rem",
        fontWeight: 700,
        letterSpacing: "0.05em",
        color: "#fff",
        background: color,
      }}
    >
      {tier}
    </span>
  );
}

function StateBadge({ state }: { state: string }) {
  const color = STATE_COLORS[state] || C.textMuted;
  return (
    <span
      style={{
        display: "inline-block",
        padding: "2px 10px",
        borderRadius: "4px",
        fontSize: "0.7rem",
        fontWeight: 600,
        color: "#fff",
        background: color,
      }}
    >
      {state}
    </span>
  );
}

function StatusDot({ ok }: { ok: boolean }) {
  return (
    <span
      style={{
        display: "inline-block",
        width: 8,
        height: 8,
        borderRadius: "50%",
        background: ok ? C.mint : C.guard,
        marginRight: 8,
      }}
    />
  );
}

function Card({
  title,
  value,
  subtitle,
  color,
}: {
  title: string;
  value: string | number;
  subtitle?: string;
  color?: string;
}) {
  return (
    <div
      style={{
        background: C.surface,
        border: `1px solid ${C.border}`,
        borderRadius: 8,
        padding: "1.25rem",
        borderTop: `3px solid ${color || C.mint}`,
      }}
    >
      <div style={{ color: C.textMuted, fontSize: "0.75rem", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.08em" }}>
        {title}
      </div>
      <div style={{ fontSize: "1.75rem", fontWeight: 700, color: color || C.text, marginTop: 4 }}>
        {value}
      </div>
      {subtitle && (
        <div style={{ fontSize: "0.75rem", color: C.textMuted, marginTop: 4 }}>
          {subtitle}
        </div>
      )}
    </div>
  );
}

function EmptyState({ message }: { message: string }) {
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        padding: "3rem",
        color: C.textMuted,
        border: `1px dashed ${C.border}`,
        borderRadius: 8,
        background: C.surface,
      }}
    >
      <div style={{ fontSize: "2rem", marginBottom: "0.5rem", opacity: 0.4 }}>
        &#9744;
      </div>
      <div style={{ fontSize: "0.85rem" }}>{message}</div>
    </div>
  );
}

function NavItem({
  label,
  active,
  onClick,
  badge,
}: {
  label: string;
  active: boolean;
  onClick: () => void;
  badge?: number;
}) {
  return (
    <button
      onClick={onClick}
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        width: "100%",
        padding: "10px 16px",
        border: "none",
        borderRadius: 6,
        background: active ? C.surfaceHover : "transparent",
        color: active ? C.pink : C.textMuted,
        cursor: "pointer",
        fontSize: "0.8rem",
        fontWeight: active ? 600 : 400,
        textAlign: "left",
        transition: "all 0.15s",
        borderLeft: active ? `3px solid ${C.pink}` : "3px solid transparent",
      }}
    >
      <span>{label}</span>
      {badge !== undefined && badge > 0 && (
        <span
          style={{
            background: C.guard,
            color: "#fff",
            borderRadius: 10,
            padding: "1px 7px",
            fontSize: "0.65rem",
            fontWeight: 700,
          }}
        >
          {badge}
        </span>
      )}
    </button>
  );
}

// ---------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------

function DashboardView({
  health,
  engagements,
  findings,
}: {
  health: HealthStatus | null;
  engagements: { items: EngagementSummary[]; total: number } | null;
  findings: { items: FindingSummary[]; total: number } | null;
}) {
  const running = engagements?.items.filter((e) => e.state === "RUNNING").length || 0;
  const confirmed = findings?.items.filter((f) => f.state === "CONFIRMED").length || 0;

  return (
    <div>
      <h2 style={{ margin: "0 0 1.25rem", fontSize: "1.1rem", fontWeight: 600 }}>
        Operations Overview
      </h2>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
          gap: "1rem",
          marginBottom: "1.5rem",
        }}
      >
        <Card
          title="Engagements"
          value={engagements?.total ?? 0}
          subtitle={running > 0 ? `${running} running` : "None active"}
          color={running > 0 ? C.mint : C.textMuted}
        />
        <Card
          title="Confirmed Findings"
          value={confirmed}
          subtitle={confirmed > 0 ? "Action required" : "Clean"}
          color={confirmed > 0 ? C.guard : C.mint}
        />
        <Card
          title="Pending Approvals"
          value={0}
          subtitle="Queue empty"
          color={C.textMuted}
        />
        <Card
          title="Evidence Items"
          value={0}
          subtitle="Content-addressed"
          color={C.textMuted}
        />
      </div>

      <h3 style={{ fontSize: "0.85rem", fontWeight: 600, color: C.textMuted, marginBottom: "0.75rem", textTransform: "uppercase", letterSpacing: "0.08em" }}>
        System Health
      </h3>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
          gap: "0.75rem",
        }}
      >
        {[
          { name: "API", ok: health?.status === "ok" },
          { name: "PostgreSQL", ok: health?.status === "ok" },
          { name: "Temporal", ok: false },
          { name: "MinIO", ok: false },
          { name: "Worker", ok: false },
        ].map((svc) => (
          <div
            key={svc.name}
            style={{
              display: "flex",
              alignItems: "center",
              background: C.surface,
              border: `1px solid ${C.border}`,
              borderRadius: 6,
              padding: "10px 14px",
              fontSize: "0.8rem",
            }}
          >
            <StatusDot ok={svc.ok} />
            <span style={{ color: svc.ok ? C.text : C.textMuted }}>
              {svc.name}
            </span>
            <span
              style={{
                marginLeft: "auto",
                fontSize: "0.7rem",
                color: svc.ok ? C.mint : C.textMuted,
              }}
            >
              {svc.ok ? "healthy" : "unknown"}
            </span>
          </div>
        ))}
      </div>

      <div style={{ marginTop: "1.5rem" }}>
        <h3 style={{ fontSize: "0.85rem", fontWeight: 600, color: C.textMuted, marginBottom: "0.75rem", textTransform: "uppercase", letterSpacing: "0.08em" }}>
          Risk Tier Reference
        </h3>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          {(["R0", "R1", "R2", "R3", "R4", "R5"] as const).map((tier) => (
            <RiskBadge key={tier} tier={tier} />
          ))}
        </div>
        <div style={{ fontSize: "0.7rem", color: C.textMuted, marginTop: 8 }}>
          R0-R1 auto-allow &middot; R2 policy-dependent &middot; R3 one-person approval &middot; R4 two-person deny-by-default &middot; R5 always denied
        </div>
      </div>
    </div>
  );
}

function EngagementsView({
  data,
  loading,
  refresh,
}: {
  data: { items: EngagementSummary[]; total: number } | null;
  loading: boolean;
  refresh: () => void;
}) {
  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }}>
        <h2 style={{ margin: 0, fontSize: "1.1rem", fontWeight: 600 }}>
          Engagements
        </h2>
        <button
          onClick={refresh}
          style={{
            background: C.pink,
            color: C.dark,
            border: "none",
            borderRadius: 6,
            padding: "6px 16px",
            fontSize: "0.75rem",
            fontWeight: 600,
            cursor: "pointer",
          }}
        >
          Refresh
        </button>
      </div>

      {loading ? (
        <div style={{ color: C.textMuted, fontSize: "0.85rem" }}>Loading...</div>
      ) : !data || data.items.length === 0 ? (
        <EmptyState message="No engagements yet. Create one via the API to get started." />
      ) : (
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.8rem" }}>
            <thead>
              <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                {["Name", "State", "Created", "Updated"].map((h) => (
                  <th
                    key={h}
                    style={{
                      textAlign: "left",
                      padding: "8px 12px",
                      color: C.textMuted,
                      fontWeight: 600,
                      fontSize: "0.7rem",
                      textTransform: "uppercase",
                      letterSpacing: "0.08em",
                    }}
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {data.items.map((e) => (
                <tr
                  key={e.id}
                  style={{ borderBottom: `1px solid ${C.border}` }}
                >
                  <td style={{ padding: "10px 12px", color: C.text }}>
                    {e.name || e.id.slice(0, 8)}
                  </td>
                  <td style={{ padding: "10px 12px" }}>
                    <StateBadge state={e.state} />
                  </td>
                  <td style={{ padding: "10px 12px", color: C.textMuted }}>
                    {new Date(e.created_at).toLocaleDateString()}
                  </td>
                  <td style={{ padding: "10px 12px", color: C.textMuted }}>
                    {new Date(e.updated_at).toLocaleDateString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function ApprovalsView() {
  return (
    <div>
      <h2 style={{ margin: "0 0 1rem", fontSize: "1.1rem", fontWeight: 600 }}>
        Approval Queue
      </h2>
      <EmptyState message="No pending approvals. Actions at R3+ risk tiers will appear here for review." />

      <div style={{ marginTop: "1.5rem", fontSize: "0.8rem", color: C.textMuted }}>
        <div style={{ fontWeight: 600, marginBottom: 8 }}>Approval Flow</div>
        <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
          {[
            { label: "R0-R1", desc: "Auto-allow", color: RISK_COLORS.R0 },
            { label: "R2", desc: "Policy gate", color: RISK_COLORS.R2 },
            { label: "R3", desc: "One-person approval", color: RISK_COLORS.R3 },
            { label: "R4", desc: "Two-person, deny-by-default", color: RISK_COLORS.R4 },
            { label: "R5", desc: "Always denied", color: RISK_COLORS.R5 },
          ].map((r) => (
            <div
              key={r.label}
              style={{
                background: C.surface,
                border: `1px solid ${C.border}`,
                borderLeft: `3px solid ${r.color}`,
                borderRadius: 6,
                padding: "8px 14px",
                minWidth: 140,
              }}
            >
              <div style={{ fontWeight: 700, color: r.color }}>{r.label}</div>
              <div style={{ fontSize: "0.7rem" }}>{r.desc}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function FindingsView({
  data,
  loading,
}: {
  data: { items: FindingSummary[]; total: number } | null;
  loading: boolean;
}) {
  return (
    <div>
      <h2 style={{ margin: "0 0 1rem", fontSize: "1.1rem", fontWeight: 600 }}>
        Findings
      </h2>

      {loading ? (
        <div style={{ color: C.textMuted, fontSize: "0.85rem" }}>Loading...</div>
      ) : !data || data.items.length === 0 ? (
        <EmptyState message="No findings recorded yet. Findings are created deterministically during validation phases." />
      ) : (
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.8rem" }}>
            <thead>
              <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                {["Weakness", "Target", "Severity", "Confidence", "State", "Date"].map((h) => (
                  <th
                    key={h}
                    style={{
                      textAlign: "left",
                      padding: "8px 12px",
                      color: C.textMuted,
                      fontWeight: 600,
                      fontSize: "0.7rem",
                      textTransform: "uppercase",
                      letterSpacing: "0.08em",
                    }}
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {data.items.map((f) => {
                const sevColor =
                  f.severity >= 9 ? C.blood :
                  f.severity >= 7 ? C.guard :
                  f.severity >= 4 ? "#F39C12" :
                  C.mint;
                return (
                  <tr
                    key={f.id}
                    style={{ borderBottom: `1px solid ${C.border}` }}
                  >
                    <td style={{ padding: "10px 12px", color: C.text, fontWeight: 600 }}>
                      {f.weakness}
                    </td>
                    <td style={{ padding: "10px 12px", color: C.textMuted, maxWidth: 240, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {f.affected_object}
                    </td>
                    <td style={{ padding: "10px 12px", color: sevColor, fontWeight: 700 }}>
                      {f.severity.toFixed(1)}
                    </td>
                    <td style={{ padding: "10px 12px", color: C.textMuted }}>
                      {(f.confidence * 100).toFixed(0)}%
                    </td>
                    <td style={{ padding: "10px 12px" }}>
                      <StateBadge state={f.state} />
                    </td>
                    <td style={{ padding: "10px 12px", color: C.textMuted }}>
                      {new Date(f.created_at).toLocaleDateString()}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function ActionsView() {
  return (
    <div>
      <h2 style={{ margin: "0 0 1rem", fontSize: "1.1rem", fontWeight: 600 }}>
        Actions
      </h2>
      <EmptyState message="No active actions. Actions are proposed by the planner and executed by Temporal workflows." />
    </div>
  );
}

function EvidenceView() {
  return (
    <div>
      <h2 style={{ margin: "0 0 1rem", fontSize: "1.1rem", fontWeight: 600 }}>
        Evidence Store
      </h2>
      <EmptyState message="No evidence artifacts stored. Evidence is content-addressed (SHA-256) and immutable." />
    </div>
  );
}

function ReportsView() {
  return (
    <div>
      <h2 style={{ margin: "0 0 1rem", fontSize: "1.1rem", fontWeight: 600 }}>
        Reports
      </h2>
      <EmptyState message="No reports generated. Reports are created from frozen engagement data in JSON, HTML, and SARIF formats." />
    </div>
  );
}

function SystemView({ health }: { health: HealthStatus | null }) {
  return (
    <div>
      <h2 style={{ margin: "0 0 1.25rem", fontSize: "1.1rem", fontWeight: 600 }}>
        System Status
      </h2>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem" }}>
        <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, padding: "1rem" }}>
          <h3 style={{ margin: "0 0 0.75rem", fontSize: "0.85rem", fontWeight: 600, color: C.textMuted, textTransform: "uppercase", letterSpacing: "0.08em" }}>
            API Server
          </h3>
          <div style={{ fontSize: "0.8rem" }}>
            <div style={{ display: "flex", alignItems: "center", marginBottom: 6 }}>
              <StatusDot ok={health?.status === "ok"} />
              <span>{health ? `${health.service} (${health.status})` : "Unreachable"}</span>
            </div>
            <div style={{ color: C.textMuted }}>
              Port 8000 &middot; FastAPI &middot; RLS-enabled
            </div>
          </div>
        </div>

        <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, padding: "1rem" }}>
          <h3 style={{ margin: "0 0 0.75rem", fontSize: "0.85rem", fontWeight: 600, color: C.textMuted, textTransform: "uppercase", letterSpacing: "0.08em" }}>
            Temporal
          </h3>
          <div style={{ fontSize: "0.8rem" }}>
            <div style={{ display: "flex", alignItems: "center", marginBottom: 6 }}>
              <StatusDot ok={false} />
              <span>Status unknown</span>
            </div>
            <div style={{ color: C.textMuted }}>
              Port 7233 &middot; UI at :8088
            </div>
          </div>
        </div>

        <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, padding: "1rem" }}>
          <h3 style={{ margin: "0 0 0.75rem", fontSize: "0.85rem", fontWeight: 600, color: C.textMuted, textTransform: "uppercase", letterSpacing: "0.08em" }}>
            PostgreSQL
          </h3>
          <div style={{ fontSize: "0.8rem" }}>
            <div style={{ display: "flex", alignItems: "center", marginBottom: 6 }}>
              <StatusDot ok={health?.status === "ok"} />
              <span>{health?.status === "ok" ? "Connected" : "Unreachable"}</span>
            </div>
            <div style={{ color: C.textMuted }}>
              Port 5432 &middot; 10 schemas &middot; RLS active
            </div>
          </div>
        </div>

        <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, padding: "1rem" }}>
          <h3 style={{ margin: "0 0 0.75rem", fontSize: "0.85rem", fontWeight: 600, color: C.textMuted, textTransform: "uppercase", letterSpacing: "0.08em" }}>
            MinIO (Evidence)
          </h3>
          <div style={{ fontSize: "0.8rem" }}>
            <div style={{ display: "flex", alignItems: "center", marginBottom: 6 }}>
              <StatusDot ok={false} />
              <span>Status unknown</span>
            </div>
            <div style={{ color: C.textMuted }}>
              Port 9000 &middot; Versioned bucket &middot; SHA-256 keyed
            </div>
          </div>
        </div>
      </div>

      <div style={{ marginTop: "1.5rem", background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, padding: "1rem" }}>
        <h3 style={{ margin: "0 0 0.75rem", fontSize: "0.85rem", fontWeight: 600, color: C.textMuted, textTransform: "uppercase", letterSpacing: "0.08em" }}>
          Platform Configuration
        </h3>
        <div style={{ fontSize: "0.75rem", color: C.textMuted, display: "grid", gridTemplateColumns: "1fr 1fr", gap: "4px 24px" }}>
          <span>Policy engine:</span><span style={{ color: C.text }}>6-layer deterministic</span>
          <span>Scope firewall:</span><span style={{ color: C.text }}>SSRF-protected, fail-closed</span>
          <span>Envelope signing:</span><span style={{ color: C.text }}>HMAC-SHA256</span>
          <span>Evidence addressing:</span><span style={{ color: C.text }}>SHA-256 content-addressed</span>
          <span>Planner layers:</span><span style={{ color: C.text }}>8-layer scoring engine</span>
          <span>AI gateway:</span><span style={{ color: C.text }}>Advisory only, never in control path</span>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------
function App() {
  const [view, setView] = useState<View>("dashboard");
  const { health } = useHealth();
  const engagements = useEngagements();
  const findings = useFindings();

  const navItems: { key: View; label: string; badge?: number }[] = [
    { key: "dashboard", label: "Dashboard" },
    { key: "engagements", label: "Engagements", badge: engagements.data?.total },
    { key: "actions", label: "Actions" },
    { key: "approvals", label: "Approvals" },
    { key: "evidence", label: "Evidence" },
    { key: "findings", label: "Findings", badge: findings.data?.total },
    { key: "reports", label: "Reports" },
    { key: "system", label: "System" },
  ];

  return (
    <div
      style={{
        display: "flex",
        height: "100vh",
        background: C.dark,
        color: C.text,
        fontFamily:
          "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif",
        fontSize: "14px",
      }}
    >
      {/* Sidebar */}
      <nav
        style={{
          width: 220,
          minWidth: 220,
          background: C.darkSurface,
          borderRight: `1px solid ${C.border}`,
          display: "flex",
          flexDirection: "column",
          padding: "0",
          overflowY: "auto",
        }}
      >
        {/* Logo */}
        <div
          style={{
            padding: "20px 16px 12px",
            borderBottom: `1px solid ${C.border}`,
          }}
        >
          <div style={{ fontSize: "1rem", fontWeight: 700, color: C.pink, letterSpacing: "0.02em" }}>
            ArsGoatia
          </div>
          <div style={{ fontSize: "0.6rem", color: C.textMuted, marginTop: 2, textTransform: "uppercase", letterSpacing: "0.1em" }}>
            Security Validation Platform
          </div>
        </div>

        {/* Navigation */}
        <div style={{ padding: "8px", flex: 1, display: "flex", flexDirection: "column", gap: 2 }}>
          {navItems.map((item) => (
            <NavItem
              key={item.key}
              label={item.label}
              active={view === item.key}
              onClick={() => setView(item.key)}
              badge={item.badge}
            />
          ))}
        </div>

        {/* Connection status */}
        <div
          style={{
            padding: "12px 16px",
            borderTop: `1px solid ${C.border}`,
            fontSize: "0.7rem",
          }}
        >
          <div style={{ display: "flex", alignItems: "center" }}>
            <StatusDot ok={health?.status === "ok"} />
            <span style={{ color: health?.status === "ok" ? C.mint : C.textMuted }}>
              {health?.status === "ok" ? "API Connected" : "API Disconnected"}
            </span>
          </div>
        </div>
      </nav>

      {/* Main content */}
      <main
        style={{
          flex: 1,
          overflow: "auto",
          padding: "1.5rem 2rem",
        }}
      >
        {view === "dashboard" && (
          <DashboardView
            health={health}
            engagements={engagements.data}
            findings={findings.data}
          />
        )}
        {view === "engagements" && (
          <EngagementsView
            data={engagements.data}
            loading={engagements.loading}
            refresh={engagements.refresh}
          />
        )}
        {view === "actions" && <ActionsView />}
        {view === "approvals" && <ApprovalsView />}
        {view === "evidence" && <EvidenceView />}
        {view === "findings" && (
          <FindingsView data={findings.data} loading={findings.loading} />
        )}
        {view === "reports" && <ReportsView />}
        {view === "system" && <SystemView health={health} />}
      </main>
    </div>
  );
}

export default App;
