import { useState, useEffect, useCallback } from 'react'
import { api } from '../api'
import type { Finding, Severity, SurfaceEndpoint, RedirectEdge } from '../types'

// Website topology as a site-map tree: the discovered directories and endpoints,
// connected parent -> child. Rounded-rectangle nodes, smooth curved edges. Nodes
// with parameters (testable input) are marked. Built from the attack surface.

const SEV_COLOR: Record<string, string> = {
  critical: 'var(--crit)', high: 'var(--high)', medium: 'var(--med)',
  low: 'var(--low)', info: 'var(--info)',
}
const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

interface TNode {
  name: string
  path: string
  children: TNode[]
  parameterized: boolean
  x: number   // depth (column)
  y: number   // leaf-order row
}

function truncate(s: string, n: number): string {
  return s.length > n ? s.slice(0, n - 1) + '…' : s
}

function layout(node: TNode, depth: number, counter: { n: number }): void {
  node.x = depth
  if (node.children.length === 0) {
    node.y = counter.n++
  } else {
    node.children.forEach(c => layout(c, depth + 1, counter))
    const ys = node.children.map(c => c.y)
    node.y = (Math.min(...ys) + Math.max(...ys)) / 2
  }
}

function collect(node: TNode, nodes: TNode[], edges: Array<[TNode, TNode]>): void {
  nodes.push(node)
  for (const c of node.children) {
    edges.push([node, c])
    collect(c, nodes, edges)
  }
}

export default function TopologyPanel(
  { missionId, target, findings }: { missionId: string; target: string; findings: Finding[] }
) {
  const [endpoints, setEndpoints] = useState<SurfaceEndpoint[]>([])
  const [redirects, setRedirects] = useState<RedirectEdge[]>([])
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    try {
      const s = await api.getSurface(missionId)
      setEndpoints(s.endpoints || [])
      setRedirects(s.redirects || [])
    } catch {
      /* surface may not exist until a mission has crawled */
    } finally {
      setLoading(false)
    }
  }, [missionId])
  useEffect(() => { load() }, [load])

  const counts: Record<string, number> = {}
  findings.forEach(f => { counts[f.severity] = (counts[f.severity] || 0) + 1 })

  // Build the tree (root = target host, then one node per path segment).
  const CAP = 70
  const root: TNode = { name: truncate(target, 20), path: '/', children: [], parameterized: false, x: 0, y: 0 }
  for (const ep of endpoints.slice(0, CAP)) {
    const segs = ep.path.split('/').filter(Boolean)
    let node = root
    let acc = ''
    for (const seg of segs) {
      acc += '/' + seg
      let child = node.children.find(c => c.name === seg)
      if (!child) {
        child = { name: seg, path: acc, children: [], parameterized: false, x: 0, y: 0 }
        node.children.push(child)
      }
      node = child
    }
    if (ep.parameterized) node.parameterized = true
  }

  const counter = { n: 0 }
  layout(root, 0, counter)
  const nodes: TNode[] = []
  const edges: Array<[TNode, TNode]> = []
  collect(root, nodes, edges)

  // Redirect edges: dashed cross-links between two nodes that both exist in the tree.
  const byPath = new Map<string, TNode>()
  for (const n of nodes) byPath.set(n.path, n)
  const redEdges: Array<[TNode, TNode]> = []
  for (const r of redirects) {
    const a = byPath.get(r.from)
    const b = byPath.get(r.to)
    if (a && b && a !== b) redEdges.push([a, b])
  }

  const leaves = Math.max(counter.n, 1)
  const maxDepth = nodes.reduce((m, n) => Math.max(m, n.x), 0)
  const COL = 158, ROWH = 34, NODEW = 132, NODEH = 24, PADX = 14, PADY = 18
  const px = (n: TNode) => PADX + n.x * COL
  const py = (n: TNode) => PADY + n.y * ROWH
  const W = PADX * 2 + (maxDepth + 1) * COL
  const H = PADY * 2 + leaves * ROWH

  return (
    <div style={{ padding: '0.75rem 1rem 1.5rem', overflow: 'auto' }}>
      <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap', marginBottom: '0.6rem' }}>
        {SEV_ORDER.map(s => (
          <span key={s} style={{ fontSize: '0.66rem', padding: '0.2rem 0.5rem', border: `1px solid ${SEV_COLOR[s]}`, color: SEV_COLOR[s], borderRadius: 4 }}>
            {counts[s] || 0} {s.toUpperCase()}
          </span>
        ))}
      </div>

      {loading ? (
        <div style={{ fontSize: '0.78rem', color: 'var(--text-dim)', padding: '1rem 0' }}>Loading site map…</div>
      ) : endpoints.length === 0 ? (
        <div style={{ fontSize: '0.78rem', color: 'var(--text-dim)', padding: '1rem 0', lineHeight: 1.7 }}>
          No site map yet. It builds from the attack surface once a mission has crawled the target.
        </div>
      ) : (
        <div style={{ overflow: 'auto', border: '1px solid var(--border)', background: 'var(--bg)' }}>
          <svg viewBox={`0 0 ${W} ${H}`} width={W} height={H} style={{ display: 'block', maxWidth: 'none' }}>
            <defs>
              <marker id="oly-arrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="6" markerHeight="6" orient="auto">
                <path d="M0,0 L8,4 L0,8 z" fill="var(--accent2)" />
              </marker>
            </defs>
            {edges.map(([a, b], i) => {
              const x1 = px(a) + NODEW, y1 = py(a) + NODEH / 2
              const x2 = px(b), y2 = py(b) + NODEH / 2
              const mx = (x1 + x2) / 2
              return (
                <path key={`e${i}`} d={`M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`}
                  fill="none" stroke="var(--border2)" strokeWidth={1.2} />
              )
            })}
            {nodes.map((n, i) => {
              const isRoot = n === root
              const stroke = isRoot ? 'var(--accent)' : n.parameterized ? 'var(--gold)' : 'var(--border2)'
              return (
                <g key={`n${i}`}>
                  <rect x={px(n)} y={py(n)} width={NODEW} height={NODEH} rx={7} ry={7}
                    fill={isRoot ? 'var(--surface2)' : 'var(--surface)'} stroke={stroke}
                    strokeWidth={isRoot ? 2 : 1.2} />
                  <text x={px(n) + 9} y={py(n) + NODEH / 2} dominantBaseline="middle" fontSize={10.5}
                    fill={isRoot ? 'var(--text-bright)' : 'var(--text)'} fontFamily="var(--mono)">
                    {truncate((isRoot ? '' : '/') + n.name, 17)}{n.parameterized ? ' ◆' : ''}
                  </text>
                </g>
              )
            })}
            {redEdges.map(([a, b], i) => {
              const x1 = px(a) + NODEW / 2, y1 = py(a) + NODEH / 2
              const x2 = px(b) + NODEW / 2, y2 = py(b) + NODEH / 2
              const mx = (x1 + x2) / 2
              return (
                <path key={`r${i}`} d={`M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`}
                  fill="none" stroke="var(--accent2)" strokeWidth={1.3} strokeDasharray="4 3"
                  markerEnd="url(#oly-arrow)" opacity={0.85} />
              )
            })}
          </svg>
        </div>
      )}

      <div style={{ fontSize: '0.66rem', color: 'var(--text-dim)', marginTop: '0.5rem', lineHeight: 1.6 }}>
        Site map of {endpoints.length} discovered endpoint{endpoints.length === 1 ? '' : 's'}
        {endpoints.length > CAP ? ` (first ${CAP} shown)` : ''}.{' '}
        <span style={{ color: 'var(--gold)' }}>◆</span> = has parameters.{' '}
        {redEdges.length > 0 && <><span style={{ color: 'var(--accent2)' }}>– – ▶</span> = redirect ({redEdges.length}).</>}
      </div>
    </div>
  )
}
