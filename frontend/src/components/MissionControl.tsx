import { useEffect, useState, useCallback, useRef } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { api } from '../api'
import { useWebSocket } from '../hooks/useWebSocket'
import type { Mission, LogEntry, Finding, ApprovalRequest, MissionStatus, MissionNote, WSEvent, LiveHost, MissionHealth } from '../types'
import { AGENT_ORDER, agentMeta, type AgentDef } from '../brand'
import GodStatus from './GodStatus'
import TerminalFeed from './TerminalFeed'
import FindingsPanel from './FindingsPanel'
import ApprovalGate from './ApprovalGate'
import TargetsPanel from './TargetsPanel'
import NotesPanel from './NotesPanel'
import RerunModal from './RerunModal'
import WorkbenchPanel from './WorkbenchPanel'

const STATUS_COLOR: Record<string, string> = {
  pending: 'var(--text-dim)',
  planning: 'var(--accent)',
  recon: 'var(--accent)',
  scanning: 'var(--gold)',
  exploiting: 'var(--accent2)',
  post_exploit: 'var(--accent2)',
  reporting: 'var(--accent3)',
  complete: 'var(--accent3)',
  awaiting_approval: 'var(--gold)',
  failed: 'var(--crit)',
}

type Tab = 'terminal' | 'targets' | 'workbench' | 'notes'

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
  const [missionHealth, setMissionHealth] = useState<MissionHealth | null>(null)
  const [loading, setLoading] = useState(true)
  const [tab, setTab] = useState<Tab>('terminal')
  const [rerunAgent, setRerunAgent] = useState<AgentDef | null>(null)
  const backupFileRef = useRef<HTMLInputElement>(null)
  const [importingBackup, setImportingBackup] = useState(false)

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
      const activeTargets: LiveHost[] = (m.context?.ares?.active_targets || []).map((t: any) => ({
        host: t.host,
        url: t.url,
        status_code: t.status_code ?? null,
        server: t.source === 'primary_fallback' ? 'Primary target fallback scanned by Tyr' : 'Scanned by Tyr',
        manually_added: t.source === 'manual',
      }))
      setLiveHosts(hosts.length ? hosts : activeTargets)
      setMissionHealth(m.context?.mission_health || null)

      const phases = new Set<string>()
      if (m.status === 'complete') {
        AGENT_ORDER.forEach(p => { if (m.context?.[p]) phases.add(p) })
      } else if (m.current_phase) {
        AGENT_ORDER.slice(0, AGENT_ORDER.indexOf(m.current_phase)).forEach(p => phases.add(p))
      }
      setCompletedPhases(phases)
    } catch {}
    finally { setLoading(false) }
  }, [id])

  useEffect(() => { load() }, [load])

  useEffect(() => {
    if (!id || ['complete', 'failed'].includes(status)) return
    const timer = window.setInterval(load, 3000)
    return () => window.clearInterval(timer)
  }, [id, status, load])

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
          setCurrentPhase(null)
          load()
          break
        }
        if (event.phase) {
          setCurrentPhase(event.phase)
          setCompletedPhases(prev => {
            const next = new Set(prev)
            AGENT_ORDER.slice(0, AGENT_ORDER.indexOf(event.phase!)).forEach(p => next.add(p))
            return next
          })
        }
        break
      case 'approval_required':
        setStatus('awaiting_approval')
        setCurrentPhase(event.agent)
        setApprovals(prev => (
          prev.some(a => a.id === event.approval_id)
            ? prev
            : [...prev, { id: event.approval_id, agent: event.agent, action: event.action, description: event.description, created_at: event.timestamp }]
        ))
        break
      case 'approval_resolved':
        setApprovals(prev => prev.filter(a => a.id !== event.approval_id))
        load()
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
        setCompletedPhases(new Set(AGENT_ORDER))
        load()
        break
      case 'mission_heartbeat':
        setMissionHealth(event.health)
        break
    }
  }, [load])

  useWebSocket(id || null, onWsEvent)

  const handleRerun = async (agent: AgentDef, targets?: string[], options?: object) => {
    if (!id) return
    try {
      await api.rerunAgent(id, agent.key, targets, options)
    } catch (e: any) {
      alert(e.message)
    }
  }

  const handleBackupImport = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    event.target.value = ''
    if (!file) return
    if (file.size > 2 * 1024 * 1024) {
      alert('Backup file is too large. Maximum size is 2 MB.')
      return
    }
    setImportingBackup(true)
    try {
      const payload = JSON.parse(await file.text())
      const summary = await api.summarizeBackup(payload)
      const confirmed = confirm(
        `Import workspace backup?\n\nTarget: ${summary.target}\nMode: ${summary.mode}\nFindings: ${summary.findings}\nNotes: ${summary.notes}\nHTTP exchanges: ${summary.http_exchanges}\n\nImport creates a new assessment and does not overwrite this one.`
      )
      if (!confirmed) return
      const imported = await api.importBackup(payload)
      navigate(`/mission/${imported.id}`)
    } catch (err: any) {
      alert(err?.message || 'Backup import failed')
    } finally {
      setImportingBackup(false)
    }
  }

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '50vh', color: 'var(--text-dim)', fontSize: '0.9rem' }}>
      Loading assessment...
    </div>
  )

  if (!mission) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '50vh', color: 'var(--accent2)', fontSize: '0.9rem' }}>
      Assessment not found.
      <button onClick={() => navigate('/')} style={{ color: 'var(--accent)', marginLeft: '1rem', cursor: 'pointer' }}>Back</button>
    </div>
  )

  const isLive = !['complete', 'failed'].includes(status)
  const color = STATUS_COLOR[status] || 'var(--text-dim)'
  const heartbeatAge = missionHealth?.last_heartbeat_at
    ? Math.max(0, Math.floor((Date.now() - new Date(missionHealth.last_heartbeat_at).getTime()) / 1000))
    : null
  const heartbeatLabel = !isLive
    ? 'Finished'
    : heartbeatAge === null
      ? 'Starting'
      : heartbeatAge <= 90
        ? 'Live'
        : heartbeatAge <= 180
          ? 'Delayed'
          : 'Check logs'
  const heartbeatColor = heartbeatLabel === 'Live'
    ? 'var(--accent3)'
    : heartbeatLabel === 'Delayed'
      ? 'var(--gold)'
      : heartbeatLabel === 'Check logs'
        ? 'var(--accent2)'
        : 'var(--text-dim)'

  const formatDuration = (seconds?: number | null) => {
    if (seconds === undefined || seconds === null) return '0s'
    const safe = Math.max(0, Math.floor(seconds))
    const mins = Math.floor(safe / 60)
    const secs = safe % 60
    const hrs = Math.floor(mins / 60)
    if (hrs > 0) return `${hrs}h ${mins % 60}m`
    if (mins > 0) return `${mins}m ${secs}s`
    return `${secs}s`
  }

  const TabBtn = ({ id, label, count }: { id: Tab; label: string; count?: number }) => (
    <button
      onClick={() => setTab(id)}
      style={{
        fontSize: '0.82rem',
        padding: '0.65rem 0.9rem',
        border: '1px solid',
        borderColor: tab === id ? 'var(--accent)' : 'transparent',
        background: tab === id ? 'var(--accent-dim)' : 'transparent',
        color: tab === id ? 'var(--accent)' : 'var(--text-dim)',
        fontWeight: 750,
      }}
    >
      {label}{count !== undefined ? ` (${count})` : ''}
    </button>
  )

  const critCount = findings.filter(f => f.severity === 'critical' && f.tag !== 'false_positive').length
  const highCount = findings.filter(f => f.severity === 'high' && f.tag !== 'false_positive').length
  const apolloResult = mission.context?.apollo || {}
  const reportError = typeof apolloResult.report_error === 'string' && apolloResult.report_error ? apolloResult.report_error : ''
  const reportAvailable = Boolean(apolloResult.report_path) && !reportError
  const reportMissing = status === 'complete' && !reportAvailable

  return (
    <>
      <div style={{ display: 'flex', flexDirection: 'column', height: 'calc(100vh - 64px)' }}>
        <div style={{
          padding: '0.9rem 1.25rem',
          background: 'var(--surface)',
          borderBottom: '1px solid var(--border)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: '1rem',
          flexWrap: 'wrap',
          flexShrink: 0,
        }}>
          <div style={{ minWidth: 0 }}>
            <div className="eyebrow" style={{ marginBottom: '0.25rem' }}>
              {mission.id.slice(0, 8).toUpperCase()} - {mission.mode.toUpperCase()} - {new Date(mission.created_at).toLocaleDateString()}
            </div>
            <div style={{ fontSize: '1.22rem', fontWeight: 850, color: 'var(--text-bright)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {mission.target}
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', flexWrap: 'wrap' }}>
            {(critCount > 0 || highCount > 0) && (
              <div style={{ display: 'flex', gap: '0.45rem' }}>
                {critCount > 0 && <span style={{ fontSize: '0.78rem', padding: '0.28rem 0.55rem', background: 'rgba(180,35,53,0.10)', border: '1px solid rgba(180,35,53,0.26)', borderRadius: '999px', color: 'var(--crit)', fontWeight: 750 }}>{critCount} critical</span>}
                {highCount > 0 && <span style={{ fontSize: '0.78rem', padding: '0.28rem 0.55rem', background: 'rgba(198,83,72,0.10)', border: '1px solid rgba(198,83,72,0.26)', borderRadius: '999px', color: 'var(--high)', fontWeight: 750 }}>{highCount} high</span>}
              </div>
            )}

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', color }}>
              {isLive && <span style={{ width: '7px', height: '7px', borderRadius: '50%', background: color, animation: 'pulse-border 1.5s ease infinite', display: 'inline-block' }} />}
              <span style={{ fontSize: '0.82rem', fontWeight: 800 }}>{status.replace('_', ' ')}</span>
            </div>

            <div style={{ display: 'flex', gap: '0.45rem', flexWrap: 'wrap' }}>
              <a href={api.exportUrl(mission.id, 'csv')} download style={{ fontSize: '0.78rem', padding: '0.42rem 0.68rem', border: '1px solid var(--border2)', borderRadius: '999px', color: 'var(--text-dim)', background: 'var(--surface)', textDecoration: 'none' }} title="Export CSV">CSV</a>
              <a href={api.exportUrl(mission.id, 'json')} download style={{ fontSize: '0.78rem', padding: '0.42rem 0.68rem', border: '1px solid var(--border2)', borderRadius: '999px', color: 'var(--text-dim)', background: 'var(--surface)', textDecoration: 'none' }} title="Export JSON">JSON</a>
              <a href={api.backupUrl(mission.id)} download style={{ fontSize: '0.78rem', padding: '0.42rem 0.68rem', border: '1px solid var(--border2)', borderRadius: '999px', color: 'var(--accent)', background: 'var(--surface)', textDecoration: 'none', fontWeight: 750 }}>
                Download Workspace Backup (.json)
              </a>
              <input ref={backupFileRef} type="file" accept="application/json,.json" onChange={handleBackupImport} style={{ display: 'none' }} />
              <button
                onClick={() => backupFileRef.current?.click()}
                disabled={importingBackup}
                style={{ fontSize: '0.78rem', padding: '0.42rem 0.68rem', border: '1px solid var(--border2)', borderRadius: '999px', color: 'var(--accent)', background: 'var(--surface)', fontWeight: 750 }}
              >
                {importingBackup ? 'Importing...' : 'Import Workspace Backup (.json)'}
              </button>
            </div>

            {status === 'complete' && reportAvailable && (
              <a href={api.getReportUrl(mission.id)} target="_blank" rel="noopener noreferrer" className="primary-action" style={{ padding: '0.45rem 0.85rem', fontSize: '0.82rem' }}>
                Report
              </a>
            )}
            {reportMissing && (
              <button
                onClick={() => handleRerun(agentMeta('apollo'))}
                style={{ padding: '0.45rem 0.85rem', fontSize: '0.82rem', border: '1px solid rgba(184,129,54,0.35)', background: 'var(--gold-dim)', color: 'var(--gold)', fontWeight: 800 }}
                title={reportError || 'Report is not available. Rerun Saga to retry report generation.'}
              >
                Retry Report
              </button>
            )}
          </div>
        </div>

        {isLive && (
          <div style={{
            padding: '0.55rem 1.25rem',
            background: 'var(--surface2)',
            borderBottom: '1px solid var(--border)',
            display: 'flex',
            alignItems: 'center',
            gap: '0.75rem',
            flexWrap: 'wrap',
            fontSize: '0.8rem',
            color: 'var(--text-dim)',
            flexShrink: 0,
          }}>
            <span className="eyebrow" style={{ color: 'var(--text-dim)' }}>Function Check</span>
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem', color: heartbeatColor, fontWeight: 800 }}>
              <span style={{ width: '7px', height: '7px', borderRadius: '50%', background: heartbeatColor, display: 'inline-block' }} />
              {heartbeatLabel}
            </span>
            <span>
              Last check: {heartbeatAge === null ? 'waiting for first 60s heartbeat' : `${formatDuration(heartbeatAge)} ago`}
            </span>
            <span style={{ color: 'var(--text)', minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '720px' }}>
              {missionHealth?.message || 'Yggdrasil is starting the mission monitor.'}
            </span>
          </div>
        )}

        {reportMissing && (
          <div style={{
            padding: '0.65rem 1.25rem',
            background: 'var(--gold-dim)',
            borderBottom: '1px solid rgba(184,129,54,0.25)',
            color: 'var(--text)',
            fontSize: '0.82rem',
            lineHeight: 1.55,
            flexShrink: 0,
          }}>
            <strong style={{ color: 'var(--gold)' }}>Report unavailable.</strong>{' '}
            {reportError || 'Saga did not produce an HTML report.'} Use Retry Report to regenerate it from the preserved findings and evidence.
          </div>
        )}

        <div style={{ flexShrink: 0 }}>
          <GodStatus
            currentPhase={currentPhase}
            status={status}
            completedPhases={completedPhases}
            onRerun={setRerunAgent}
          />
        </div>

        <div className="mission-workspace-grid">
          <section className="soft-panel" style={{ overflow: 'hidden', display: 'flex', flexDirection: 'column', minHeight: 0 }}>
            <div style={{ display: 'flex', padding: '0.55rem', gap: '0.35rem', background: 'var(--surface)', borderBottom: '1px solid var(--border)', flexShrink: 0 }}>
              <TabBtn id="terminal" label="Activity" />
              <TabBtn id="targets" label="Targets" count={liveHosts.length} />
              <TabBtn id="workbench" label="Workbench" />
              <TabBtn id="notes" label="Notes" count={notes.length || undefined} />
            </div>

            <div style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
              {tab === 'terminal' && <TerminalFeed logs={logs} />}
              {tab === 'targets' && (
                <TargetsPanel
                  missionId={mission.id}
                  liveHosts={liveHosts}
                  onAgentRerun={(agent, targets) => handleRerun(agentMeta(agent), targets)}
                />
              )}
              {tab === 'workbench' && (
                <WorkbenchPanel missionId={mission.id} target={mission.target} />
              )}
              {tab === 'notes' && (
                <NotesPanel
                  missionId={mission.id}
                  notes={notes}
                  onDelete={noteId => setNotes(prev => prev.filter(n => n.id !== noteId))}
                />
              )}
            </div>
          </section>

          <section className="soft-panel" style={{ overflow: 'hidden', display: 'flex', flexDirection: 'column', minHeight: 0 }}>
            <FindingsPanel
              missionId={mission.id}
              findings={findings}
              onUpdate={(fid, data) => setFindings(prev => prev.map(f => f.id === fid ? { ...f, ...data } : f))}
              onDelete={fid => setFindings(prev => prev.filter(f => f.id !== fid))}
              onAdd={f => setFindings(prev => [f, ...prev])}
            />
          </section>
        </div>
      </div>

      {approvals.length > 0 && (
        <ApprovalGate
          missionId={mission.id}
          approvals={approvals}
          onResolved={() => setApprovals(prev => prev.slice(1))}
        />
      )}

      {rerunAgent && (
        <RerunModal
          missionId={mission.id}
          agentName={rerunAgent.key}
          agentSymbol={rerunAgent.symbol}
          agentRole={rerunAgent.role}
          onConfirm={(targets, options) => handleRerun(rerunAgent, targets, options)}
          onClose={() => setRerunAgent(null)}
        />
      )}
    </>
  )
}
