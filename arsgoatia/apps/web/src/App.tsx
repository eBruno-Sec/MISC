import React, { useEffect, useState, useCallback, useMemo } from "react";

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
  dark: "#0F1220",
  darkSurface: "#141830",
  text: "#E8E8E8",
  textMuted: "#9BA4B5",
  border: "#2C3E50",
  surface: "#1B1F35",
  surfaceHover: "#243447",
};

const RISK_COLORS: Record<string, string> = {
  R0: C.mint,
  R1: "#52C7A0",
  R2: C.pink,
  R3: "#E67E22",
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
  CANDIDATE: "#F39C12",
  CONFIRMED: C.guard,
  REJECTED: C.textMuted,
  INCONCLUSIVE: C.textMuted,
  PROPOSED: C.pink,
  APPROVAL_REQUIRED: "#E67E22",
  APPROVED: C.mint,
};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
type View =
  | "dashboard"
  | "engagements"
  | "engagementDetail"
  | "actions"
  | "approvals"
  | "capabilities"
  | "evidence"
  | "findings"
  | "reports"
  | "system"
  | "guide";

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
  temporal_workflow_id?: string | null;
}

interface EngagementDetailData extends EngagementSummary {
  description: string;
  target_url: string;
  scope?: any;
  rules?: any;
  workflow_state?: any;
}

interface FindingSummary {
  id: string;
  engagement_id: string;
  weakness: string;
  affected_object: string;
  severity: number;
  confidence: number;
  state: string;
  evidence_count: number;
  created_at: string;
}

interface EvidenceItem {
  id: string;
  engagement_id: string;
  action_id: string;
  kind: string;
  digest: string;
  size_bytes: number;
  media_type: string;
  storage_uri: string;
  sensitivity: string;
  created_at: string;
}

interface ReportItem {
  id: string;
  engagement_id: string;
  report_type: string;
  format: string;
  digest: string;
  storage_uri: string;
  created_at: string;
}

// ---------------------------------------------------------------------------
// API helpers
// ---------------------------------------------------------------------------
const TENANT_ID_KEY = "arsgoatia.tenantId";

function getTenantId(): string {
  const stored = localStorage.getItem(TENANT_ID_KEY);
  if (stored) return stored;
  const generated =
    "00000000-0000-0000-0000-" + Date.now().toString(16).padStart(12, "0");
  localStorage.setItem(TENANT_ID_KEY, generated);
  return generated;
}

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T | null> {
  try {
    const r = await fetch(`/api/v1${path}`, {
      ...init,
      headers: {
        "X-Tenant-Id": getTenantId(),
        "Content-Type": "application/json",
        ...(init?.headers || {}),
      },
    });
    if (!r.ok) {
      console.warn(`API ${path} → ${r.status}`);
      return null;
    }
    if (r.status === 204) return null;
    return (await r.json()) as T;
  } catch (e) {
    console.warn(`API ${path} error`, e);
    return null;
  }
}

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------
function useHealth() {
  const [health, setHealth] = useState<HealthStatus | null>(null);
  useEffect(() => {
    const load = () =>
      fetch("/api/v1/health")
        .then((r) => (r.ok ? r.json() : null))
        .then(setHealth)
        .catch(() => setHealth(null));
    load();
    const iv = setInterval(load, 15000);
    return () => clearInterval(iv);
  }, []);
  return health;
}

function usePolling<T>(path: string, ms = 5000) {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const refresh = useCallback(() => {
    setLoading(true);
    apiFetch<T>(path)
      .then(setData)
      .finally(() => setLoading(false));
  }, [path]);
  useEffect(() => {
    refresh();
    const iv = setInterval(refresh, ms);
    return () => clearInterval(iv);
  }, [refresh, ms]);
  return { data, loading, refresh };
}

// ---------------------------------------------------------------------------
// Shared components
// ---------------------------------------------------------------------------
function StateBadge({ state }: { state: string }) {
  const color = STATE_COLORS[state?.toUpperCase()] || C.textMuted;
  return (
    <span
      style={{
        display: "inline-block",
        padding: "2px 10px",
        borderRadius: 4,
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

function RiskBadge({ tier }: { tier: string }) {
  const color = RISK_COLORS[tier] || C.textMuted;
  return (
    <span
      style={{
        display: "inline-block",
        padding: "2px 8px",
        borderRadius: 4,
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
  onClick,
}: {
  title: string;
  value: string | number;
  subtitle?: string;
  color?: string;
  onClick?: () => void;
}) {
  return (
    <div
      onClick={onClick}
      style={{
        background: C.surface,
        border: `1px solid ${C.border}`,
        borderRadius: 8,
        padding: "1.25rem",
        borderTop: `3px solid ${color || C.mint}`,
        cursor: onClick ? "pointer" : "default",
        transition: "transform 0.1s",
      }}
    >
      <div
        style={{
          color: C.textMuted,
          fontSize: "0.72rem",
          fontWeight: 600,
          textTransform: "uppercase",
          letterSpacing: "0.08em",
        }}
      >
        {title}
      </div>
      <div
        style={{
          fontSize: "1.75rem",
          fontWeight: 700,
          color: color || C.text,
          marginTop: 4,
        }}
      >
        {value}
      </div>
      {subtitle && (
        <div style={{ fontSize: "0.72rem", color: C.textMuted, marginTop: 4 }}>
          {subtitle}
        </div>
      )}
    </div>
  );
}

function EmptyState({ message, cta }: { message: string; cta?: React.ReactNode }) {
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
      <div style={{ fontSize: "0.85rem", marginBottom: cta ? "1rem" : 0 }}>{message}</div>
      {cta}
    </div>
  );
}

function Btn({
  children,
  onClick,
  variant = "primary",
  disabled,
  small,
}: {
  children: React.ReactNode;
  onClick?: () => void;
  variant?: "primary" | "ghost" | "danger" | "mint";
  disabled?: boolean;
  small?: boolean;
}) {
  const styles: Record<string, React.CSSProperties> = {
    primary: { background: C.pink, color: C.dark },
    ghost: {
      background: "transparent",
      color: C.text,
      border: `1px solid ${C.border}`,
    },
    danger: { background: C.guard, color: "#fff" },
    mint: { background: C.mint, color: C.dark },
  };
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      style={{
        border: "none",
        borderRadius: 6,
        padding: small ? "4px 10px" : "8px 18px",
        fontSize: small ? "0.72rem" : "0.8rem",
        fontWeight: 600,
        cursor: disabled ? "not-allowed" : "pointer",
        opacity: disabled ? 0.5 : 1,
        ...styles[variant],
      }}
    >
      {children}
    </button>
  );
}

// ---------------------------------------------------------------------------
// Modal
// ---------------------------------------------------------------------------
function Modal({
  title,
  onClose,
  children,
}: {
  title: string;
  onClose: () => void;
  children: React.ReactNode;
}) {
  return (
    <div
      onClick={onClose}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,0.6)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 100,
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          background: C.darkSurface,
          border: `1px solid ${C.border}`,
          borderRadius: 10,
          padding: "1.5rem",
          minWidth: 480,
          maxWidth: 640,
          maxHeight: "85vh",
          overflow: "auto",
        }}
      >
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            marginBottom: "1rem",
            paddingBottom: "0.75rem",
            borderBottom: `1px solid ${C.border}`,
          }}
        >
          <h3 style={{ margin: 0, fontSize: "1rem", color: C.pink }}>{title}</h3>
          <button
            onClick={onClose}
            style={{
              background: "transparent",
              border: "none",
              color: C.textMuted,
              fontSize: "1.2rem",
              cursor: "pointer",
            }}
          >
            ×
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// New Engagement form
// ---------------------------------------------------------------------------
function NewEngagementForm({
  onCreated,
  onClose,
}: {
  onCreated: () => void;
  onClose: () => void;
}) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [targetUrl, setTargetUrl] = useState("http://juice-shop:3000");
  const [scopeType, setScopeType] = useState<"exact_host" | "dns_suffix" | "url_prefix">(
    "exact_host",
  );
  const [scopeValue, setScopeValue] = useState("juice-shop");
  const [identityCount, setIdentityCount] = useState(2);
  const [submitting, setSubmitting] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const submit = async () => {
    if (!name.trim() || !targetUrl.trim() || !scopeValue.trim()) {
      setErr("Name, target URL, and scope value are required");
      return;
    }
    setSubmitting(true);
    setErr(null);
    const body = {
      name,
      description,
      target_url: targetUrl,
      scope: { include: [{ type: scopeType, value: scopeValue }] },
      rules: { identity_count: identityCount, allowed_risk_tiers: ["R0", "R1", "R2"] },
    };
    const result = await apiFetch("/engagements", {
      method: "POST",
      body: JSON.stringify(body),
    });
    setSubmitting(false);
    if (result) {
      onCreated();
      onClose();
    } else {
      setErr("Create failed — check console + API logs");
    }
  };

  const inputStyle: React.CSSProperties = {
    width: "100%",
    padding: "8px 10px",
    background: C.dark,
    color: C.text,
    border: `1px solid ${C.border}`,
    borderRadius: 4,
    fontSize: "0.85rem",
    fontFamily: "inherit",
  };
  const labelStyle: React.CSSProperties = {
    display: "block",
    fontSize: "0.72rem",
    fontWeight: 600,
    color: C.textMuted,
    textTransform: "uppercase",
    letterSpacing: "0.05em",
    marginBottom: 4,
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "0.85rem" }}>
      <div>
        <label style={labelStyle}>Name *</label>
        <input
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Juice Shop authorized scan"
          style={inputStyle}
        />
      </div>
      <div>
        <label style={labelStyle}>Target URL *</label>
        <input
          type="text"
          value={targetUrl}
          onChange={(e) => setTargetUrl(e.target.value)}
          style={inputStyle}
        />
      </div>
      <div>
        <label style={labelStyle}>Description</label>
        <textarea
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          rows={2}
          style={{ ...inputStyle, resize: "vertical" }}
        />
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr", gap: "0.75rem" }}>
        <div>
          <label style={labelStyle}>Scope type</label>
          <select
            value={scopeType}
            onChange={(e) => setScopeType(e.target.value as any)}
            style={inputStyle}
          >
            <option value="exact_host">exact_host</option>
            <option value="dns_suffix">dns_suffix</option>
            <option value="url_prefix">url_prefix</option>
          </select>
        </div>
        <div>
          <label style={labelStyle}>Scope value *</label>
          <input
            type="text"
            value={scopeValue}
            onChange={(e) => setScopeValue(e.target.value)}
            style={inputStyle}
          />
        </div>
      </div>
      <div>
        <label style={labelStyle}>Identity count (1-8)</label>
        <input
          type="number"
          min={1}
          max={8}
          value={identityCount}
          onChange={(e) => setIdentityCount(parseInt(e.target.value) || 2)}
          style={{ ...inputStyle, width: 80 }}
        />
      </div>
      {err && (
        <div
          style={{
            padding: 10,
            background: `${C.guard}30`,
            border: `1px solid ${C.guard}`,
            borderRadius: 4,
            color: C.guard,
            fontSize: "0.8rem",
          }}
        >
          {err}
        </div>
      )}
      <div
        style={{
          display: "flex",
          justifyContent: "flex-end",
          gap: "0.5rem",
          marginTop: "0.5rem",
        }}
      >
        <Btn variant="ghost" onClick={onClose}>
          Cancel
        </Btn>
        <Btn variant="primary" onClick={submit} disabled={submitting}>
          {submitting ? "Creating..." : "Create Engagement"}
        </Btn>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------
function DashboardView({
  health,
  engagementsTotal,
  running,
  findings,
  evidenceTotal,
  onNew,
  onGoTo,
}: any) {
  const confirmed =
    findings?.items?.filter((f: FindingSummary) => f.state === "CONFIRMED").length || 0;

  return (
    <div>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: "1.25rem",
        }}
      >
        <h2 style={{ margin: 0, fontSize: "1.15rem", fontWeight: 600 }}>
          Operations Overview
        </h2>
        <Btn variant="primary" onClick={onNew}>
          + New Engagement
        </Btn>
      </div>

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
          value={engagementsTotal ?? 0}
          subtitle={running > 0 ? `${running} running` : "None active"}
          color={running > 0 ? C.mint : C.textMuted}
          onClick={() => onGoTo("engagements")}
        />
        <Card
          title="Confirmed Findings"
          value={confirmed}
          subtitle={confirmed > 0 ? "Action required" : "Clean"}
          color={confirmed > 0 ? C.guard : C.mint}
          onClick={() => onGoTo("findings")}
        />
        <Card
          title="Evidence Items"
          value={evidenceTotal ?? 0}
          subtitle="SHA-256 addressed"
          color={C.textMuted}
          onClick={() => onGoTo("evidence")}
        />
        <Card
          title="Health"
          value={health?.status === "ok" ? "OK" : "DOWN"}
          subtitle={health?.status === "ok" ? "API reachable" : "Check /health"}
          color={health?.status === "ok" ? C.mint : C.guard}
          onClick={() => onGoTo("system")}
        />
      </div>

      <h3
        style={{
          fontSize: "0.82rem",
          fontWeight: 600,
          color: C.textMuted,
          marginBottom: "0.75rem",
          textTransform: "uppercase",
          letterSpacing: "0.08em",
        }}
      >
        Quick Start
      </h3>
      <div
        style={{
          background: C.surface,
          border: `1px solid ${C.border}`,
          borderRadius: 8,
          padding: "1rem 1.25rem",
          fontSize: "0.85rem",
          lineHeight: 1.6,
        }}
      >
        <ol style={{ margin: 0, paddingLeft: "1.25rem", color: C.textMuted }}>
          <li>
            Click <strong style={{ color: C.pink }}>+ New Engagement</strong>, name it, set the
            target URL, pick a scope rule.
          </li>
          <li>
            Go to <strong style={{ color: C.text }}>Engagements</strong>, click the row to open
            detail, then hit <strong style={{ color: C.pink }}>Start</strong>.
          </li>
          <li>
            Watch the workflow progress live. Evidence + findings appear as the run advances.
          </li>
          <li>
            Approvals for R2+ actions land in the{" "}
            <strong style={{ color: C.pink }}>Approvals</strong> tab.
          </li>
        </ol>
        <div style={{ marginTop: "0.75rem", fontSize: "0.75rem" }}>
          Need more?{" "}
          <a
            href="#"
            onClick={(e) => {
              e.preventDefault();
              onGoTo("guide");
            }}
            style={{ color: C.pink }}
          >
            Read the full guide →
          </a>
        </div>
      </div>
    </div>
  );
}

function EngagementsView({
  data,
  loading,
  refresh,
  onNew,
  onOpen,
}: any) {
  return (
    <div>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: "1rem",
        }}
      >
        <h2 style={{ margin: 0, fontSize: "1.1rem" }}>Engagements</h2>
        <div style={{ display: "flex", gap: "0.5rem" }}>
          <Btn variant="ghost" onClick={refresh} small>
            Refresh
          </Btn>
          <Btn variant="primary" onClick={onNew}>
            + New Engagement
          </Btn>
        </div>
      </div>

      {loading ? (
        <div style={{ color: C.textMuted, fontSize: "0.85rem" }}>Loading...</div>
      ) : !data || data.items.length === 0 ? (
        <EmptyState
          message="No engagements yet. Create one to get started."
          cta={<Btn variant="primary" onClick={onNew}>+ Create your first engagement</Btn>}
        />
      ) : (
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.85rem" }}>
            <thead>
              <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                {["Name", "State", "Workflow", "Created", ""].map((h) => (
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
              {data.items.map((e: EngagementSummary) => (
                <tr
                  key={e.id}
                  onClick={() => onOpen(e.id)}
                  style={{ borderBottom: `1px solid ${C.border}`, cursor: "pointer" }}
                >
                  <td style={{ padding: "10px 12px", color: C.text, fontWeight: 500 }}>
                    {e.name}
                  </td>
                  <td style={{ padding: "10px 12px" }}>
                    <StateBadge state={e.state} />
                  </td>
                  <td style={{ padding: "10px 12px", color: C.textMuted, fontFamily: "monospace", fontSize: "0.7rem" }}>
                    {e.temporal_workflow_id || "-"}
                  </td>
                  <td style={{ padding: "10px 12px", color: C.textMuted }}>
                    {new Date(e.created_at).toLocaleString()}
                  </td>
                  <td style={{ padding: "10px 12px" }}>
                    <Btn variant="ghost" onClick={() => onOpen(e.id)} small>
                      Open →
                    </Btn>
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

function EngagementDetailView({
  engagementId,
  onBack,
  onRefreshList,
}: {
  engagementId: string;
  onBack: () => void;
  onRefreshList: () => void;
}) {
  const { data, refresh, loading } = usePolling<EngagementDetailData>(
    `/engagements/${engagementId}`,
    3000,
  );
  const { data: auditData } = usePolling<{ items: any[]; total: number }>(
    `/audit/events?engagement_id=${engagementId}&limit=25`,
    3000,
  );

  const startEngagement = async () => {
    const r = await apiFetch(`/engagements/${engagementId}:start`, { method: "POST" });
    if (r) {
      refresh();
      onRefreshList();
    }
  };
  const pauseEngagement = async () => {
    await apiFetch(`/engagements/${engagementId}:pause`, { method: "POST" });
    refresh();
  };
  const resumeEngagement = async () => {
    await apiFetch(`/engagements/${engagementId}:resume`, { method: "POST" });
    refresh();
  };
  const emergencyStop = async () => {
    if (!confirm("Emergency stop — halt all actions immediately. Confirm?")) return;
    await apiFetch(`/engagements/${engagementId}:emergency-stop`, { method: "POST" });
    refresh();
    onRefreshList();
  };

  if (loading && !data) {
    return <div style={{ color: C.textMuted, fontSize: "0.9rem" }}>Loading...</div>;
  }
  if (!data) {
    return <EmptyState message="Engagement not found." />;
  }

  const canStart = ["DRAFT", "READY", "SCOPE_COMPILED"].includes(data.state);
  const canPause = data.state === "RUNNING";
  const canResume = data.state === "PAUSED";
  const canStop = ["RUNNING", "PAUSED", "REPORTING", "CLEANUP_PENDING"].includes(data.state);

  const ws = data.workflow_state as any;

  return (
    <div>
      <div style={{ marginBottom: "1rem" }}>
        <Btn variant="ghost" onClick={onBack} small>
          ← Back to engagements
        </Btn>
      </div>

      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "flex-start",
          marginBottom: "1.25rem",
        }}
      >
        <div>
          <h2 style={{ margin: 0, fontSize: "1.15rem" }}>{data.name}</h2>
          <div style={{ fontSize: "0.78rem", color: C.textMuted, marginTop: 4 }}>
            {data.target_url}
          </div>
        </div>
        <div style={{ display: "flex", gap: "0.5rem" }}>
          {canStart && (
            <Btn variant="primary" onClick={startEngagement}>
              ▶ Start
            </Btn>
          )}
          {canPause && (
            <Btn variant="ghost" onClick={pauseEngagement}>
              ‖ Pause
            </Btn>
          )}
          {canResume && <Btn variant="mint" onClick={resumeEngagement}>▶ Resume</Btn>}
          {canStop && (
            <Btn variant="danger" onClick={emergencyStop}>
              ⬛ Emergency Stop
            </Btn>
          )}
        </div>
      </div>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
          gap: "1rem",
          marginBottom: "1.5rem",
        }}
      >
        <Card
          title="State"
          value={data.state}
          color={STATE_COLORS[data.state] || C.textMuted}
        />
        <Card
          title="Progress"
          value={ws ? `${ws.progress_pct ?? 0}%` : "-"}
          subtitle={ws?.phase || "not started"}
          color={C.pink}
        />
        <Card
          title="Findings"
          value={ws?.findings_count ?? 0}
          color={ws?.findings_count > 0 ? C.guard : C.textMuted}
        />
        <Card
          title="Evidence"
          value={ws?.evidence_count ?? 0}
          color={C.textMuted}
        />
      </div>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: "1rem",
        }}
      >
        <div
          style={{
            background: C.surface,
            border: `1px solid ${C.border}`,
            borderRadius: 8,
            padding: "1rem 1.25rem",
            fontSize: "0.78rem",
          }}
        >
          <div
            style={{
              fontSize: "0.72rem",
              fontWeight: 600,
              color: C.textMuted,
              textTransform: "uppercase",
              letterSpacing: "0.08em",
              marginBottom: "0.75rem",
            }}
          >
            Details
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "130px 1fr", gap: "6px 12px" }}>
            <span style={{ color: C.textMuted }}>Engagement ID:</span>
            <span style={{ fontFamily: "monospace", fontSize: "0.7rem" }}>{data.id}</span>
            <span style={{ color: C.textMuted }}>Workflow ID:</span>
            <span style={{ fontFamily: "monospace", fontSize: "0.7rem" }}>
              {data.temporal_workflow_id || "—"}
            </span>
            <span style={{ color: C.textMuted }}>Description:</span>
            <span>{data.description || "—"}</span>
            <span style={{ color: C.textMuted }}>Scope:</span>
            <span style={{ fontFamily: "monospace", fontSize: "0.7rem" }}>
              {JSON.stringify(data.scope?.include || [])}
            </span>
            <span style={{ color: C.textMuted }}>Created:</span>
            <span>{new Date(data.created_at).toLocaleString()}</span>
            <span style={{ color: C.textMuted }}>Updated:</span>
            <span>{new Date(data.updated_at).toLocaleString()}</span>
          </div>
        </div>

        <div
          style={{
            background: C.surface,
            border: `1px solid ${C.border}`,
            borderRadius: 8,
            padding: "1rem 1.25rem",
            fontSize: "0.78rem",
            maxHeight: 320,
            overflowY: "auto",
          }}
        >
          <div
            style={{
              fontSize: "0.72rem",
              fontWeight: 600,
              color: C.textMuted,
              textTransform: "uppercase",
              letterSpacing: "0.08em",
              marginBottom: "0.75rem",
            }}
          >
            Activity Timeline
          </div>
          {!auditData || auditData.items.length === 0 ? (
            <div style={{ color: C.textMuted, fontStyle: "italic" }}>
              No events yet.
            </div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: "0.4rem" }}>
              {auditData.items.map((ev: any) => (
                <div
                  key={ev.id}
                  style={{
                    display: "grid",
                    gridTemplateColumns: "70px 1fr",
                    gap: "0.5rem",
                    borderLeft: `2px solid ${
                      ev.event_type.includes("emergency") || ev.event_type.includes("rejected")
                        ? C.guard
                        : ev.event_type.includes("approved") ||
                          ev.event_type.includes("started")
                        ? C.mint
                        : C.pink
                    }`,
                    paddingLeft: "0.5rem",
                  }}
                >
                  <span
                    style={{
                      color: C.textMuted,
                      fontSize: "0.68rem",
                      fontFamily: "monospace",
                    }}
                  >
                    {new Date(ev.created_at).toLocaleTimeString()}
                  </span>
                  <span>
                    <span style={{ color: C.pink, fontWeight: 500 }}>{ev.event_type}</span>
                    {ev.actor_id && (
                      <span style={{ color: C.textMuted, marginLeft: 6 }}>
                        by {ev.actor_id}
                      </span>
                    )}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function FindingsView({ data }: { data: any }) {
  return (
    <div>
      <h2 style={{ margin: "0 0 1rem", fontSize: "1.1rem" }}>Findings</h2>
      {!data || data.items.length === 0 ? (
        <EmptyState message="No findings yet. Findings appear after a validation phase confirms a weakness with all required evidence." />
      ) : (
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.85rem" }}>
            <thead>
              <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                {["Weakness", "Target", "Severity", "State", "Date"].map((h) => (
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
              {data.items.map((f: FindingSummary) => {
                const sevColor =
                  f.severity >= 9
                    ? C.blood
                    : f.severity >= 7
                    ? C.guard
                    : f.severity >= 4
                    ? "#E67E22"
                    : C.mint;
                return (
                  <tr key={f.id} style={{ borderBottom: `1px solid ${C.border}` }}>
                    <td style={{ padding: "10px 12px", fontWeight: 600 }}>{f.weakness}</td>
                    <td
                      style={{
                        padding: "10px 12px",
                        color: C.textMuted,
                        maxWidth: 300,
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {f.affected_object}
                    </td>
                    <td style={{ padding: "10px 12px", color: sevColor, fontWeight: 700 }}>
                      {f.severity.toFixed(1)}
                    </td>
                    <td style={{ padding: "10px 12px" }}>
                      <StateBadge state={f.state} />
                    </td>
                    <td style={{ padding: "10px 12px", color: C.textMuted }}>
                      {new Date(f.created_at).toLocaleString()}
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

function EvidenceView({ data }: { data: any }) {
  return (
    <div>
      <h2 style={{ margin: "0 0 1rem", fontSize: "1.1rem" }}>Evidence</h2>
      {!data || data.items.length === 0 ? (
        <EmptyState message="No evidence stored yet. Every target-facing exchange is hashed + kept in MinIO." />
      ) : (
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.8rem" }}>
            <thead>
              <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                {["Kind", "Digest", "Size", "Media", "When"].map((h) => (
                  <th
                    key={h}
                    style={{
                      textAlign: "left",
                      padding: "8px 12px",
                      color: C.textMuted,
                      fontWeight: 600,
                      fontSize: "0.7rem",
                      textTransform: "uppercase",
                    }}
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {data.items.slice(0, 100).map((e: EvidenceItem) => (
                <tr key={e.id} style={{ borderBottom: `1px solid ${C.border}` }}>
                  <td style={{ padding: "8px 12px", color: C.pink, fontWeight: 500 }}>
                    {e.kind}
                  </td>
                  <td
                    style={{
                      padding: "8px 12px",
                      fontFamily: "monospace",
                      color: C.textMuted,
                      fontSize: "0.7rem",
                    }}
                  >
                    {e.digest?.slice(0, 24)}...
                  </td>
                  <td style={{ padding: "8px 12px", color: C.textMuted }}>{e.size_bytes}</td>
                  <td style={{ padding: "8px 12px", color: C.textMuted, fontSize: "0.72rem" }}>
                    {e.media_type}
                  </td>
                  <td style={{ padding: "8px 12px", color: C.textMuted }}>
                    {new Date(e.created_at).toLocaleTimeString()}
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

function ReportsView({ data }: { data: any }) {
  const download = async (id: string, fmt: string) => {
    const r = await fetch(`/api/v1/reports/${id}/download`, {
      headers: { "X-Tenant-Id": getTenantId() },
    });
    if (!r.ok) {
      alert(`Download failed: ${r.status}`);
      return;
    }
    const blob = await r.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `arsgoatia-report-${id.slice(0, 8)}.${fmt}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div>
      <h2 style={{ margin: "0 0 1rem", fontSize: "1.1rem" }}>Reports</h2>
      {!data || data.items.length === 0 ? (
        <EmptyState message="No reports yet. Reports are auto-generated during the REPORTING phase." />
      ) : (
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.85rem" }}>
            <thead>
              <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                {["Type", "Format", "Digest", "Created", ""].map((h) => (
                  <th
                    key={h}
                    style={{
                      textAlign: "left",
                      padding: "8px 12px",
                      color: C.textMuted,
                      fontWeight: 600,
                      fontSize: "0.7rem",
                      textTransform: "uppercase",
                    }}
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {data.items.map((r: ReportItem) => (
                <tr key={r.id} style={{ borderBottom: `1px solid ${C.border}` }}>
                  <td style={{ padding: "10px 12px" }}>{r.report_type}</td>
                  <td style={{ padding: "10px 12px", color: C.pink, textTransform: "uppercase" }}>
                    {r.format}
                  </td>
                  <td
                    style={{
                      padding: "10px 12px",
                      fontFamily: "monospace",
                      color: C.textMuted,
                      fontSize: "0.7rem",
                    }}
                  >
                    {r.digest?.slice(0, 32)}...
                  </td>
                  <td style={{ padding: "10px 12px", color: C.textMuted }}>
                    {new Date(r.created_at).toLocaleString()}
                  </td>
                  <td style={{ padding: "10px 12px", textAlign: "right" }}>
                    <Btn variant="primary" onClick={() => download(r.id, r.format)} small>
                      ⬇ Download
                    </Btn>
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
  const { data, refresh } = usePolling<{ items: any[]; total: number }>(
    "/approvals/pending",
    3000,
  );

  const approve = async (id: string) => {
    if (!confirm(`Approve action ${id.slice(0, 8)}? This will unblock the workflow.`)) return;
    await apiFetch(`/actions/${id}:approve`, {
      method: "POST",
      body: JSON.stringify({ reason: "approved via web console" }),
    });
    refresh();
  };
  const reject = async (id: string) => {
    const reason = prompt("Rejection reason:");
    if (!reason) return;
    await apiFetch(`/actions/${id}:reject`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    });
    refresh();
  };

  return (
    <div>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: "1rem",
        }}
      >
        <h2 style={{ margin: 0, fontSize: "1.1rem" }}>Approval Queue</h2>
        <Btn variant="ghost" onClick={refresh} small>
          Refresh
        </Btn>
      </div>

      {!data || data.items.length === 0 ? (
        <EmptyState message="Queue empty. R2+ action proposals land here for operator sign-off." />
      ) : (
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.85rem" }}>
            <thead>
              <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                {["Risk", "Technique", "Target", "Proposed", ""].map((h) => (
                  <th
                    key={h}
                    style={{
                      textAlign: "left",
                      padding: "8px 12px",
                      color: C.textMuted,
                      fontWeight: 600,
                      fontSize: "0.7rem",
                      textTransform: "uppercase",
                    }}
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {data.items.map((a: any) => (
                <tr key={a.id} style={{ borderBottom: `1px solid ${C.border}` }}>
                  <td style={{ padding: "10px 12px" }}>
                    <RiskBadge tier={a.risk_tier} />
                  </td>
                  <td style={{ padding: "10px 12px", fontWeight: 500 }}>{a.technique_id}</td>
                  <td
                    style={{
                      padding: "10px 12px",
                      color: C.textMuted,
                      maxWidth: 300,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {a.target}
                  </td>
                  <td style={{ padding: "10px 12px", color: C.textMuted }}>
                    {new Date(a.created_at).toLocaleString()}
                  </td>
                  <td style={{ padding: "10px 12px", textAlign: "right" }}>
                    <Btn variant="mint" onClick={() => approve(a.id)} small>
                      ✓ Approve
                    </Btn>{" "}
                    <Btn variant="danger" onClick={() => reject(a.id)} small>
                      ✗ Reject
                    </Btn>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div style={{ marginTop: "1.5rem", fontSize: "0.8rem", color: C.textMuted }}>
        <div style={{ fontWeight: 600, marginBottom: 8 }}>Risk-tier reference</div>
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

function ActionsView() {
  return (
    <div>
      <h2 style={{ margin: "0 0 1rem", fontSize: "1.1rem" }}>Actions</h2>
      <EmptyState message="Actions are proposed by the deterministic planner during a live engagement. Open an engagement to see its proposals." />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Capabilities
// ---------------------------------------------------------------------------
function CapabilitiesView() {
  const { data, loading } = usePolling<{ total: number; items: any[] }>(
    "/capabilities",
    30000,
  );

  const sevColor = (s: string) => {
    switch (s) {
      case "critical":
        return C.blood;
      case "high":
        return C.guard;
      case "medium":
        return "#E67E22";
      case "low":
        return "#F1C40F";
      case "info":
        return C.mint;
      default:
        return C.textMuted;
    }
  };

  return (
    <div>
      <div style={{ marginBottom: "1rem" }}>
        <h2 style={{ margin: 0, fontSize: "1.15rem" }}>Capabilities</h2>
        <div style={{ color: C.textMuted, fontSize: "0.78rem", marginTop: 4 }}>
          What arsgoatia can actually do — every technique pack the platform has
          compiled from source.{" "}
          {data && (
            <span style={{ color: C.pink, fontWeight: 500 }}>
              {data.total} packs registered.
            </span>
          )}
        </div>
      </div>

      {loading && !data ? (
        <div style={{ color: C.textMuted, fontSize: "0.85rem" }}>Loading capability registry...</div>
      ) : !data || data.items.length === 0 ? (
        <EmptyState message="No capability packs discovered. Check packs/**/*.capability.yaml on disk." />
      ) : (
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fill, minmax(360px, 1fr))",
            gap: "1rem",
          }}
        >
          {data.items.map((pack: any) => (
            <div
              key={pack.metadata.id}
              style={{
                background: C.surface,
                border: `1px solid ${C.border}`,
                borderLeft: `3px solid ${sevColor(pack.classification.severity)}`,
                borderRadius: 8,
                padding: "1rem 1.15rem",
                fontSize: "0.8rem",
              }}
            >
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "flex-start",
                  gap: 8,
                }}
              >
                <div>
                  <div style={{ fontWeight: 600, color: C.text, fontSize: "0.9rem" }}>
                    {pack.metadata.name}
                  </div>
                  <div style={{ color: C.textMuted, fontSize: "0.7rem", fontFamily: "monospace" }}>
                    {pack.metadata.id} @ {pack.metadata.version}
                  </div>
                </div>
                <div style={{ display: "flex", gap: 4, flexShrink: 0 }}>
                  <RiskBadge tier={pack.classification.risk_tier} />
                  <span
                    style={{
                      display: "inline-block",
                      padding: "2px 8px",
                      borderRadius: 4,
                      fontSize: "0.62rem",
                      fontWeight: 700,
                      color: "#fff",
                      background: sevColor(pack.classification.severity),
                      textTransform: "uppercase",
                      letterSpacing: "0.05em",
                    }}
                  >
                    {pack.classification.severity}
                  </span>
                </div>
              </div>

              <div style={{ marginTop: 10, display: "grid", gridTemplateColumns: "auto 1fr", gap: "3px 10px", fontSize: "0.72rem" }}>
                {pack.classification.weakness_id && (
                  <>
                    <span style={{ color: C.textMuted }}>Weakness</span>
                    <span style={{ color: C.text, fontFamily: "monospace" }}>
                      {pack.classification.weakness_id}
                    </span>
                  </>
                )}
                {pack.classification.owasp && (
                  <>
                    <span style={{ color: C.textMuted }}>OWASP</span>
                    <span style={{ color: C.text }}>{pack.classification.owasp}</span>
                  </>
                )}
                <span style={{ color: C.textMuted }}>Confirmation</span>
                <span style={{ color: C.text }}>{pack.confirmation.strategy}</span>
                {pack.confirmation.determinism && (
                  <>
                    <span style={{ color: C.textMuted }}>Determinism</span>
                    <span style={{ color: C.mint }}>{pack.confirmation.determinism}</span>
                  </>
                )}
              </div>

              {pack.remediation?.short && (
                <div
                  style={{
                    marginTop: 10,
                    padding: "6px 10px",
                    borderLeft: `2px solid ${C.mint}`,
                    background: C.dark,
                    color: C.text,
                    fontSize: "0.72rem",
                    lineHeight: 1.4,
                  }}
                >
                  <div
                    style={{
                      color: C.mint,
                      fontSize: "0.62rem",
                      fontWeight: 600,
                      textTransform: "uppercase",
                      letterSpacing: "0.05em",
                      marginBottom: 3,
                    }}
                  >
                    Remediation
                  </div>
                  {pack.remediation.short}
                </div>
              )}

              {pack.confirmation.false_positive_conditions?.length > 0 && (
                <details style={{ marginTop: 8, fontSize: "0.72rem", color: C.textMuted }}>
                  <summary style={{ cursor: "pointer", color: C.pink }}>
                    False-positive conditions ({pack.confirmation.false_positive_conditions.length})
                  </summary>
                  <ul style={{ margin: "6px 0 0", paddingLeft: "1.2rem" }}>
                    {pack.confirmation.false_positive_conditions.map((c: string, i: number) => (
                      <li key={i}>{c}</li>
                    ))}
                  </ul>
                </details>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function SystemView({ health }: any) {
  return (
    <div>
      <h2 style={{ margin: "0 0 1.25rem", fontSize: "1.1rem" }}>System Status</h2>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem" }}>
        {[
          { name: "API", ok: health?.status === "ok", detail: "FastAPI · Port 8000 · RLS" },
          { name: "PostgreSQL", ok: health?.status === "ok", detail: "10 schemas · RLS · Immutable triggers" },
          { name: "Temporal", ok: true, detail: "Port 7233 · UI :8088" },
          { name: "MinIO", ok: true, detail: "Port 9000 · Console :9101 · Versioned" },
          { name: "Worker", ok: true, detail: "Queues: arsgoatia-control, arsgoatia-web" },
          { name: "Web", ok: true, detail: "Nginx · Port 80 → :3100" },
        ].map((s) => (
          <div
            key={s.name}
            style={{
              background: C.surface,
              border: `1px solid ${C.border}`,
              borderRadius: 8,
              padding: "1rem",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", marginBottom: 6 }}>
              <StatusDot ok={s.ok} />
              <span style={{ fontWeight: 600 }}>{s.name}</span>
            </div>
            <div style={{ color: C.textMuted, fontSize: "0.75rem" }}>{s.detail}</div>
          </div>
        ))}
      </div>
      <div
        style={{
          marginTop: "1.5rem",
          background: C.surface,
          border: `1px solid ${C.border}`,
          borderRadius: 8,
          padding: "1rem",
          fontSize: "0.8rem",
        }}
      >
        <div style={{ fontWeight: 600, marginBottom: 8, color: C.pink }}>Your Tenant ID</div>
        <code style={{ color: C.text }}>{getTenantId()}</code>
        <div style={{ color: C.textMuted, fontSize: "0.72rem", marginTop: 6 }}>
          Auto-generated + kept in localStorage. All API requests are scoped to this tenant.
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Guide
// ---------------------------------------------------------------------------
function GuideView() {
  const H = ({ children }: any) => (
    <h3
      style={{
        margin: "1.5rem 0 0.5rem",
        fontSize: "0.9rem",
        color: C.pink,
        textTransform: "uppercase",
        letterSpacing: "0.05em",
      }}
    >
      {children}
    </h3>
  );
  const P = ({ children }: any) => (
    <p style={{ margin: "0 0 0.6rem", color: C.text, lineHeight: 1.55, fontSize: "0.85rem" }}>
      {children}
    </p>
  );
  const Code = ({ children }: any) => (
    <pre
      style={{
        background: C.dark,
        padding: "10px 14px",
        borderRadius: 6,
        border: `1px solid ${C.border}`,
        fontSize: "0.75rem",
        overflowX: "auto",
      }}
    >
      <code>{children}</code>
    </pre>
  );
  const Tip = ({ children, color = C.pink }: any) => (
    <div
      style={{
        borderLeft: `3px solid ${color}`,
        background: C.surface,
        padding: "8px 12px",
        margin: "0.5rem 0",
        fontSize: "0.8rem",
        color: C.text,
        lineHeight: 1.5,
      }}
    >
      {children}
    </div>
  );

  return (
    <div style={{ maxWidth: 780 }}>
      <h2 style={{ margin: "0 0 1rem", fontSize: "1.2rem" }}>ArsGoatia Guide</h2>
      <P>
        This platform runs deterministic autonomous pentests. Automation collects, structured
        reasoning decides, evidence proves. LLMs are advisory only — never in the control path.
      </P>

      <H>Quick start</H>
      <P>
        <strong>1.</strong> Dashboard → <em>+ New Engagement</em>. Give it a name, a target URL,
        a scope rule (start with <code>exact_host</code> if unsure), pick 2 identities.
      </P>
      <P>
        <strong>2.</strong> Engagements tab → click the row → <em>Start</em>. The workflow runs
        through 9 phases; the detail page auto-polls every 3s.
      </P>
      <P>
        <strong>3.</strong> Evidence + Findings tabs populate as the run advances. Reports (JSON,
        HTML, SARIF) drop into Reports at the end.
      </P>

      <H>Understanding risk tiers</H>
      <P>Every action is classified. The deterministic policy engine gates on tier:</P>
      <ul style={{ margin: 0, paddingLeft: "1.25rem", color: C.text, fontSize: "0.82rem" }}>
        <li>
          <RiskBadge tier="R0" /> Offline / no target contact → auto-allow
        </li>
        <li>
          <RiskBadge tier="R1" /> Passive observation only → auto-allow
        </li>
        <li>
          <RiskBadge tier="R2" /> Bounded active (read probes) → policy-dependent
        </li>
        <li>
          <RiskBadge tier="R3" /> State-changing → requires one-person approval
        </li>
        <li>
          <RiskBadge tier="R4" /> High-impact → two-person, deny-by-default
        </li>
        <li>
          <RiskBadge tier="R5" /> Destructive → always denied
        </li>
      </ul>

      <H>Scope rules</H>
      <Tip>
        <strong>Fail-closed:</strong> an engagement with no scope include rules will refuse every
        target. Add at least one <code>exact_host</code>, <code>dns_suffix</code>, or{" "}
        <code>url_prefix</code>.
      </Tip>
      <P>
        For Juice Shop on the compose network: <code>exact_host</code> = <code>juice-shop</code>.
        For public web pentests: <code>dns_suffix</code> = <code>.customer.com</code>.
      </P>

      <H>Engagement lifecycle</H>
      <P>
        States progress: <code>DRAFT → AUTHORIZATION_PENDING → SCOPE_COMPILED → READY → RUNNING
        → REPORTING → CLEANUP_PENDING → COMPLETED</code>. Signals available: pause, resume,
        emergency stop, provide-approval.
      </P>

      <H>Emergency stop</H>
      <Tip color={C.guard}>
        The red button on the engagement detail page. It cancels every child workflow and
        triggers the cleanup phase. Use it if a scan is going somewhere it shouldn't.
      </Tip>

      <H>Where is my evidence?</H>
      <P>
        Everything is content-addressed by SHA-256 and stored twice: metadata rows in Postgres
        (<code>evidence.evidence</code> table) and the raw bytes in MinIO
        (<code>arsgoatia-evidence</code> bucket, versioning enabled). Browse the bucket at{" "}
        <a href="http://localhost:9101" target="_blank" rel="noreferrer" style={{ color: C.pink }}>
          http://localhost:9101
        </a>{" "}
        (user <code>arsgoatia</code> / pass <code>arsgoatia-dev-secret</code>).
      </P>

      <H>Direct API access</H>
      <P>Set the tenant header on every request:</P>
      <Code>
        {`curl -H "X-Tenant-Id: ${getTenantId()}" \\
     http://localhost:8080/api/v1/engagements`}
      </Code>
      <P>OpenAPI docs live at http://localhost:8080/docs (Swagger UI).</P>

      <H>Watching workflows</H>
      <P>
        Temporal UI is at{" "}
        <a href="http://localhost:8088" target="_blank" rel="noreferrer" style={{ color: C.pink }}>
          http://localhost:8088
        </a>
        . Every EngagementWorkflow is named <code>eng-{"{engagement_id}"}</code>. Click a
        workflow to see its history, activity retries, and stack trace.
      </P>

      <H>Troubleshooting</H>
      <Tip>
        <strong>Workflow stuck at 20%?</strong> Check{" "}
        <code>docker logs arsgoatia-worker-1</code> — usually a recon activity is blocked on a
        target that refuses connections.
      </Tip>
      <Tip>
        <strong>API returns 401?</strong> Missing <code>X-Tenant-Id</code> header. The web UI
        adds it automatically; direct curl callers must add it themselves.
      </Tip>
      <Tip>
        <strong>Evidence table empty but MinIO full?</strong> The store_evidence activity writes
        to both. Check worker logs for <code>evidence-row persist failed</code>.
      </Tip>
      <Tip color={C.guard}>
        <strong>Emergency stop didn't return control?</strong> The signal is best-effort; if the
        workflow doesn't exist yet in Temporal it swallows the error. State on the DB row still
        flips to STOPPING.
      </Tip>

      <H>Tips + tricks</H>
      <Tip color={C.mint}>
        <strong>Reuse identities:</strong> the identity activity now tries Juice Shop's
        <code>/api/Users</code> + <code>/rest/user/login</code> first, then falls back to
        generic <code>/register</code> + <code>/login</code>. Add your own targets by editing{" "}
        <code>services/worker/activities/identity.py</code>.
      </Tip>
      <Tip color={C.mint}>
        <strong>Add a technique pack:</strong> drop a new module under{" "}
        <code>packs/techniques/</code> and register its activity in{" "}
        <code>services/worker/worker.py</code>.
      </Tip>
      <Tip color={C.mint}>
        <strong>Zero false positives:</strong> a finding only emits if baseline, positive
        control, and negative control all pass AND the differential shows the auth bypass.
        Broken baselines land as INCONCLUSIVE, not CONFIRMED.
      </Tip>
      <Tip color={C.mint}>
        <strong>Multi-tenant:</strong> your tenant ID is auto-generated. Clear localStorage to
        get a fresh one; RLS ensures you can never see another tenant's rows.
      </Tip>

      <H>Reference</H>
      <ul style={{ fontSize: "0.82rem", color: C.text, paddingLeft: "1.25rem" }}>
        <li>Web console: http://localhost:3100</li>
        <li>API + Swagger: http://localhost:8080/docs</li>
        <li>Temporal UI: http://localhost:8088</li>
        <li>MinIO console: http://localhost:9101</li>
        <li>Juice Shop (test target): http://localhost:42000</li>
      </ul>
    </div>
  );
}

// ---------------------------------------------------------------------------
// NavItem + App shell
// ---------------------------------------------------------------------------
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
        fontSize: "0.82rem",
        fontWeight: active ? 600 : 400,
        textAlign: "left",
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

function App() {
  const [view, setView] = useState<View>("dashboard");
  const [selectedEngagement, setSelectedEngagement] = useState<string | null>(null);
  const [showNewForm, setShowNewForm] = useState(false);

  const health = useHealth();
  const engagements = usePolling<{ items: EngagementSummary[]; total: number }>(
    "/engagements",
    5000,
  );
  const findings = usePolling<{ items: FindingSummary[]; total: number }>("/findings", 5000);
  const evidenceP = usePolling<{ items: EvidenceItem[]; total: number }>("/evidence", 5000);
  const reports = usePolling<{ items: ReportItem[]; total: number }>("/reports", 5000);

  const running = useMemo(
    () => engagements.data?.items.filter((e) => e.state === "RUNNING").length || 0,
    [engagements.data],
  );

  const nav: { key: View; label: string; badge?: number }[] = [
    { key: "dashboard", label: "Dashboard" },
    { key: "engagements", label: "Engagements", badge: engagements.data?.total },
    { key: "actions", label: "Actions" },
    { key: "approvals", label: "Approvals" },
    { key: "capabilities", label: "Capabilities" },
    { key: "evidence", label: "Evidence", badge: evidenceP.data?.total },
    { key: "findings", label: "Findings", badge: findings.data?.total },
    { key: "reports", label: "Reports", badge: reports.data?.total },
    { key: "system", label: "System" },
    { key: "guide", label: "📖 Guide" },
  ];

  const openEngagement = (id: string) => {
    setSelectedEngagement(id);
    setView("engagementDetail");
  };

  return (
    <div
      style={{
        display: "flex",
        height: "100vh",
        background: C.dark,
        color: C.text,
        fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif",
        fontSize: "14px",
      }}
    >
      {showNewForm && (
        <Modal title="New Engagement" onClose={() => setShowNewForm(false)}>
          <NewEngagementForm
            onCreated={() => engagements.refresh()}
            onClose={() => setShowNewForm(false)}
          />
        </Modal>
      )}

      <nav
        style={{
          width: 220,
          minWidth: 220,
          background: C.darkSurface,
          borderRight: `1px solid ${C.border}`,
          display: "flex",
          flexDirection: "column",
          overflowY: "auto",
        }}
      >
        <div style={{ padding: "20px 16px 12px", borderBottom: `1px solid ${C.border}` }}>
          <div style={{ fontSize: "1rem", fontWeight: 700, color: C.pink }}>ArsGoatia</div>
          <div
            style={{
              fontSize: "0.6rem",
              color: C.textMuted,
              marginTop: 2,
              textTransform: "uppercase",
              letterSpacing: "0.1em",
            }}
          >
            Security Validation Platform
          </div>
        </div>
        <div style={{ padding: 8, flex: 1, display: "flex", flexDirection: "column", gap: 2 }}>
          {nav.map((item) => (
            <NavItem
              key={item.key}
              label={item.label}
              active={view === item.key}
              onClick={() => {
                setView(item.key);
                if (item.key !== "engagementDetail") setSelectedEngagement(null);
              }}
              badge={item.badge}
            />
          ))}
        </div>
        <div
          style={{ padding: "12px 16px", borderTop: `1px solid ${C.border}`, fontSize: "0.7rem" }}
        >
          <div style={{ display: "flex", alignItems: "center" }}>
            <StatusDot ok={health?.status === "ok"} />
            <span style={{ color: health?.status === "ok" ? C.mint : C.textMuted }}>
              {health?.status === "ok" ? "API Connected" : "API Disconnected"}
            </span>
          </div>
        </div>
      </nav>

      <main style={{ flex: 1, overflow: "auto", padding: "1.5rem 2rem" }}>
        {view === "dashboard" && (
          <DashboardView
            health={health}
            engagementsTotal={engagements.data?.total}
            running={running}
            findings={findings.data}
            evidenceTotal={evidenceP.data?.total}
            onNew={() => setShowNewForm(true)}
            onGoTo={setView}
          />
        )}
        {view === "engagements" && (
          <EngagementsView
            data={engagements.data}
            loading={engagements.loading}
            refresh={engagements.refresh}
            onNew={() => setShowNewForm(true)}
            onOpen={openEngagement}
          />
        )}
        {view === "engagementDetail" && selectedEngagement && (
          <EngagementDetailView
            engagementId={selectedEngagement}
            onBack={() => setView("engagements")}
            onRefreshList={engagements.refresh}
          />
        )}
        {view === "actions" && <ActionsView />}
        {view === "approvals" && <ApprovalsView />}
        {view === "capabilities" && <CapabilitiesView />}
        {view === "evidence" && <EvidenceView data={evidenceP.data} />}
        {view === "findings" && <FindingsView data={findings.data} />}
        {view === "reports" && <ReportsView data={reports.data} />}
        {view === "system" && <SystemView health={health} />}
        {view === "guide" && <GuideView />}
      </main>
    </div>
  );
}

export default App;
