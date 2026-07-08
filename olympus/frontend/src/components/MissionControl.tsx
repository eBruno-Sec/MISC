import { useEffect, useState, useCallback } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { api } from '../api'
import { useWebSocket } from '../hooks/useWebSocket'
import type { Mission, LogEntry, Finding, ApprovalRequest, MissionStatus, MissionNote, WSEvent, LiveHost } from '../types'
import GodStatus from './GodStatus'
import TerminalFeed from './TerminalFeed'
import FindingsPanel from './FindingsPanel'
import ApprovalGate from './ApprovalGate'
import TargetsPanel from './TargetsPanel'
import NotesPanel from './NotesPanel'
import RerunModal from './RerunModal'
import WordlistsPanel from './WordlistsPanel'
import SurfacePanel from './SurfacePanel'

const STATUS_COLOR: Record<string, string> = {
  pending: 'var(--text-dim)', planning: 'var(--accent)', recon: 'var(--accent)',
  scanning: 'var(--gold)', exploiting: 'var(--accent2)', post_exploit: 'var(--accent2)',
  reporting: 'var(--accent3)', complete: 'var(--accent3)',
  awaiting_approval: 'var(--gold)', failed: 'var(--crit)',
}

type Tab = 'terminal' | 'targets' | 'notes' | 'wordlists' | 'surface'

interface GodDef { key: string; name: string; symbol: string; role: string }

export default function MissionControl() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()

  const [mission, setMission] = useState<Mission | null>(null)
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [findings, setFindings] = useState<Finding[]>([])
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([])
  const [notes, setNotes] = useState<MissionNote[]>([])
  const [status, setStatus] = useState<MissionStatus>('pending')
  const [currentPhase, setCurrentPhase] = useState<string | null>(null)
  const [completedPhases, setCompletedPhases] = useState<Set<string>>(new Set())
  const [liveHosts, setLiveHosts] = useState<LiveHost[]>([])
  const [loading, setLoading] = useState(true)
  const [tab, setTab] = useState<Tab>('terminal')
  const [rerunGod, setRerunGod] = useState<GodDef | null>(null)

  const load = useCallback(async () => {
    if (!id) return
    try {
      const m = await api.getMission(id)
      setMission(m)
      setLogs(m.logs)
      setFindings(m.findings)
      setApprovals(m.pending_approvals)
      setNotes(m.notes || [])
      setStatus(m.status as MissionStatus)
      const terminal = m.status === 'complete' || m.status === 'failed'
      setCurrentPhase(terminal ? null : m.current_phase)

      const hosts: LiveHost[] = m.context?.hermes?.live_hosts || []
      setLiveHosts(hosts)

      const phaseOrder = ['zeus', 'athena', 'hermes', 'ares', 'hephaestus', 'hades', 'apollo']
      const phases = new Set<string>()
      if (m.status === 'complete') {
        phaseOrder.forEach(p => { if (m.context?.[p]) phases.add(p) })
      } else if (m.current_phase) {
        phaseOrder.slice(0, phaseOrder.indexOf(m.current_phase)).forEach(p => phases.add(p))
      }
      setCompletedPhases(phases)
    } catch {}
    finally { setLoading(false) }
  }, [id])

  useEffect(() => { load() }, [load])

  const onWsEvent = useCallback((event: WSEvent) => {
    switch (event.type) {
      case 'log':
        setLogs(prev => [...prev, { id: Math.random().toString(36).slice(2), agent: event.agent, symbol: event.symbol, level: event.level, message: event.message, timestamp: event.timestamp }])
        break
      case 'finding':
        load()
        break
      case 'finding_updated':
        setFindings(prev => prev.map(f => f.id === event.finding_id ? { ...f, tag: event.tag, severity: event.severity } : f))
        break
      case 'finding_deleted':
        setFindings(prev => prev.filter(f => f.id !== event.finding_id))
        break
      case 'status_change':
        setStatus(event.status)
        if (event.status === 'complete' || event.status === 'failed') {
          // Terminal state: clear the active phase so no god card stays stuck on RUNNING
          setCurrentPhase(null)
          load()
          break
        }
        if (event.phase) {
          setCurrentPhase(event.phase)
          const phaseOrder = ['zeus', 'athena', 'hermes', 'ares', 'hephaestus', 'hades', 'apollo']
          setCompletedPhases(prev => {
            const n = new Set(prev)
            phaseOrder.slice(0, phaseOrder.indexOf(event.phase!)).forEach(p => n.add(p))
            return n
          })
        }
        break
      case 'approval_required':
        setApprovals(prev => [...prev, { id: event.approval_id, agent: event.agent, action: event.action, description: event.description, created_at: event.timestamp }])
        break
      case 'approval_resolved':
        setApprovals(prev => prev.filter(a => a.id !== event.approval_id))
        break
      case 'targets_added':
        load()
        setTab('targets')
        break
      case 'note_added':
        setNotes(prev => [...prev, event.note])
        break
      case 'agent_rerun':
        setCurrentPhase(event.agent)
        break
      case 'mission_complete':
      case 'mission_failed':
        setCurrentPhase(null)
        setCompletedPhases(new Set(['zeus', 'athena', 'hermes', 'ares', 'hephaestus', 'hades', 'apollo']))
        load()
        break
    }
  }, [load])

  useWebSocket(id || null, onWsEvent)

  const handleRerun = async (agent: GodDef, targets?: string[], options?: object) => {
    if (!id) return
    try {
      await api.rerunAgent(id, agent.key, targets, options)
    } catch (e: any) {
      alert(e.message)
    }
  }

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '50vh', color: 'var(--text-dim)', fontSize: '0.8rem' }}>
      Loading mission...
    </div>
  )
  if (!mission) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '50vh', color: 'var(--accent2)', fontSize: '0.8rem' }}>
      Mission not found.{' '}
      <button onClick={() => navigate('/')} style={{ color: 'var(--accent)', marginLeft: '1rem', cursor: 'pointer' }}>Back</button>
    </div>
  )

  const isLive = !['complete', 'failed'].includes(status)
  const color = STATUS_COLOR[status] || 'var(--text-dim)'

  const TabBtn = ({ id, label, count }: { id: Tab; label: string; count?: number }) => (
    <button
      onClick={() => setTab(id)}
      style={{
        fontSize: '0.68rem', letterSpacing: '0.15em', padding: '0.5rem 1rem',
        border: 'none', cursor: 'pointer',
        borderBottom: tab === id ? '2px solid var(--accent)' : '2px solid transparent',
        background: tab === id ? 'var(--accent-dim)' : 'var(--surface)',
        color: tab === id ? 'var(--accent)' : 'var(--text-dim)',
        transition: 'all 0.1s',
      }}
    >
      {label}{count !== undefined ? ` (${count})` : ''}
    </button>
  )

  const critCount = findings.filter(f => f.severity === 'critical' && f.tag !== 'false_positive').length
  const highCount = findings.filter(f => f.severity === 'high' && f.tag !== 'false_positive').length

  return (
    <>
      <div style={{ display: 'flex', flexDirection: 'column', height: 'calc(100vh - 52px)' }}>

        {/* Mission header */}
        <div style={{ padding: '0.75rem 1.5rem', background: 'var(--surface)', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '1rem', flexWrap: 'wrap', flexShrink: 0 }}>
          <div>
            <div style={{ fontSize: '0.62rem', letterSpacing: '0.2em', color: 'var(--text-dim)', marginBottom: '0.2rem' }}>
              {mission.id.slice(0, 8).toUpperCase()} · {mission.mode.toUpperCase()} · {new Date(mission.created_at).toLocaleDateString()}
            </div>
            <div style={{ fontFamily: 'var(--display)', fontSize: '1.2rem', fontWeight: 900, color: 'var(--text-bright)' }}>{mission.target}</div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
            {/* Severity summary */}
            {(critCount > 0 || highCount > 0) && (
              <div style={{ display: 'flex', gap: '0.5rem' }}>
                {critCount > 0 && <span style={{ fontSize: '0.7rem', padding: '0.2rem 0.5rem', background: 'rgba(255,0,64,0.12)', border: '1px solid rgba(255,0,64,0.3)', color: 'var(--crit)' }}>{critCount} CRIT</span>}
                {highCount > 0 && <span style={{ fontSize: '0.7rem', padding: '0.2rem 0.5rem', background: 'rgba(255,61,107,0.12)', border: '1px solid rgba(255,61,107,0.3)', color: 'var(--high)' }}>{highCount} HIGH</span>}
              </div>
            )}

            {/* Status */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color }}>
              {isLive && <span style={{ width: '7px', height: '7px', borderRadius: '50%', background: color, animation: 'pulse-border 1.5s ease infinite', display: 'inline-block' }} />}
              <span style={{ fontSize: '0.72rem', fontWeight: 700, letterSpacing: '0.1em' }}>{status.toUpperCase().replace('_', ' ')}</span>
            </div>

            {/* Export */}
            <div style={{ display: 'flex', gap: '1px' }}>
              <a href={api.exportUrl(mission.id, 'csv')} download style={{ fontSize: '0.68rem', letterSpacing: '0.1em', padding: '0.35rem 0.65rem', border: '1px solid var(--border2)', color: 'var(--text-dim)', textDecoration: 'none' }} title="Export CSV">CSV</a>
              <a href={api.exportUrl(mission.id, 'json')} download style={{ fontSize: '0.68rem', letterSpacing: '0.1em', padding: '0.35rem 0.65rem', border: '1px solid var(--border2)', color: 'var(--text-dim)', textDecoration: 'none' }} title="Export JSON">JSON</a>
            </div>

            {/* Report */}
            {status === 'complete' && (
              <a href={api.getReportUrl(mission.id)} target="_blank" rel="noopener noreferrer" style={{ fontSize: '0.72rem', letterSpacing: '0.12em', padding: '0.35rem 0.9rem', background: 'var(--accent3)', color: 'var(--bg)', fontFamily: 'var(--display)', fontWeight: 700, textDecoration: 'none' }}>
                ☀ REPORT
              </a>
            )}
          </div>
        </div>

        {/* God status bar */}
        <div style={{ flexShrink: 0 }}>
          <GodStatus
            currentPhase={currentPhase}
            status={status}
            completedPhases={completedPhases}
            onRerun={setRerunGod}
          />
        </div>

        {/* Main layout: left panel (tabs) + right panel (findings) */}
        <div style={{ flex: 1, display: 'grid', gridTemplateColumns: '60% 40%', overflow: 'hidden' }}>

          {/* Left panel */}
          <div style={{ borderRight: '1px solid var(--border)', overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
            {/* Tab bar */}
            <div style={{ display: 'flex', background: 'var(--surface)', borderBottom: '1px solid var(--border)', flexShrink: 0 }}>
              <TabBtn id="terminal" label="TERMINAL" />
              <TabBtn id="targets" label="TARGETS" count={liveHosts.length} />
              <TabBtn id="notes" label="NOTES" count={notes.length || undefined} />
              <TabBtn id="wordlists" label="WORDLISTS" />
              <TabBtn id="surface" label="SURFACE" />
            </div>

            <div style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
              {tab === 'terminal' && <TerminalFeed logs={logs} />}
              {tab === 'targets' && (
                <TargetsPanel
                  missionId={mission.id}
                  liveHosts={liveHosts}
                  onAgentRerun={(agent, targets) => {
                    const god = { key: agent, name: agent.toUpperCase(), symbol: '', role: '' }
                    handleRerun(god, targets)
                  }}
                />
              )}
              {tab === 'notes' && (
                <NotesPanel
                  missionId={mission.id}
                  notes={notes}
                  onDelete={noteId => setNotes(prev => prev.filter(n => n.id !== noteId))}
                />
              )}
              {tab === 'wordlists' && (
                <div style={{ overflow: 'auto' }}>
                  <WordlistsPanel missionId={mission.id} />
                </div>
              )}
              {tab === 'surface' && (
                <div style={{ overflow: 'auto' }}>
                  <SurfacePanel missionId={mission.id} />
                </div>
              )}
            </div>
          </div>

          {/* Right panel: findings */}
          <div style={{ overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
            <FindingsPanel
              missionId={mission.id}
              findings={findings}
              onUpdate={(fid, data) => setFindings(prev => prev.map(f => f.id === fid ? { ...f, ...data } : f))}
              onDelete={fid => setFindings(prev => prev.filter(f => f.id !== fid))}
              onAdd={f => setFindings(prev => [f, ...prev])}
            />
          </div>
        </div>
      </div>

      {/* Approval gate overlay */}
      {approvals.length > 0 && (
        <ApprovalGate
          missionId={mission.id}
          approvals={approvals}
          onResolved={() => setApprovals(prev => prev.slice(1))}
        />
      )}

      {/* Re-run modal */}
      {rerunGod && (
        <RerunModal
          missionId={mission.id}
          agentName={rerunGod.key}
          agentSymbol={rerunGod.symbol}
          agentRole={rerunGod.role}
          onConfirm={(targets, options) => handleRerun(rerunGod, targets, options)}
          onClose={() => setRerunGod(null)}
        />
      )}
    </>
  )
}
