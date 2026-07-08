import type { LiveHost, Finding, Severity } from '../types'

// Lightweight 2D network topology (hand-rolled SVG — no external graph lib, so it
// stays inside the CSP with no new dependency). Target at the centre, live hosts
// on a ring, severity tallies up top. Fills in as HERMES confirms hosts.

const SEV_COLOR: Record<string, string> = {
  critical: 'var(--crit)', high: 'var(--high)', medium: 'var(--med)',
  low: 'var(--low)', info: 'var(--info)',
}
const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

function truncate(s: string, n: number): string {
  return s.length > n ? s.slice(0, n - 1) + '…' : s
}

export default function TopologyPanel(
  { target, liveHosts, findings }: { target: string; liveHosts: LiveHost[]; findings: Finding[] }
) {
  const counts: Record<string, number> = {}
  findings.forEach(f => { counts[f.severity] = (counts[f.severity] || 0) + 1 })

  const W = 640, H = 460, cx = W / 2, cy = H / 2
  const hosts = liveHosts.slice(0, 16)
  const R = Math.min(W, H) / 2 - 70

  const nodes = hosts.map((h, i) => {
    const theta = (2 * Math.PI * i) / Math.max(hosts.length, 1) - Math.PI / 2
    return { host: h, x: cx + R * Math.cos(theta), y: cy + R * Math.sin(theta) }
  })

  return (
    <div style={{ padding: '0.75rem 1rem 1.5rem', overflow: 'auto' }}>
      <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap', marginBottom: '0.6rem' }}>
        {SEV_ORDER.map(s => (
          <span key={s} style={{ fontSize: '0.66rem', padding: '0.2rem 0.5rem', border: `1px solid ${SEV_COLOR[s]}`, color: SEV_COLOR[s] }}>
            {counts[s] || 0} {s.toUpperCase()}
          </span>
        ))}
      </div>

      {hosts.length === 0 ? (
        <div style={{ fontSize: '0.78rem', color: 'var(--text-dim)', padding: '1rem 0', lineHeight: 1.7 }}>
          No live hosts to map yet. The topology fills in once HERMES confirms live hosts for this mission.
        </div>
      ) : (
        <svg viewBox={`0 0 ${W} ${H}`} style={{ width: '100%', height: 'auto', border: '1px solid var(--border)', background: 'var(--bg)' }}>
          {nodes.map((n, i) => (
            <line key={`l${i}`} x1={cx} y1={cy} x2={n.x} y2={n.y} stroke="var(--border2)" strokeWidth={1} />
          ))}
          <circle cx={cx} cy={cy} r={34} fill="var(--surface2)" stroke="var(--accent)" strokeWidth={2} />
          <text x={cx} y={cy} textAnchor="middle" dominantBaseline="middle" fontSize={11} fill="var(--text-bright)" fontFamily="var(--mono)">
            {truncate(target, 16)}
          </text>
          {nodes.map((n, i) => {
            const up = n.host.status_code !== null
            const col = up ? 'var(--accent3)' : 'var(--text-dim)'
            return (
              <g key={`n${i}`}>
                <circle cx={n.x} cy={n.y} r={9} fill="var(--surface)" stroke={col} strokeWidth={2} />
                <text x={n.x} y={n.y + 22} textAnchor="middle" fontSize={9} fill="var(--text-dim)" fontFamily="var(--mono)">
                  {truncate(n.host.host, 18)}
                </text>
              </g>
            )
          })}
        </svg>
      )}

      <div style={{ fontSize: '0.66rem', color: 'var(--text-dim)', marginTop: '0.5rem' }}>
        {hosts.length} live host{hosts.length === 1 ? '' : 's'} mapped
        {liveHosts.length > hosts.length ? ` (of ${liveHosts.length})` : ''}. Green = responded, grey = unverified.
      </div>
    </div>
  )
}
