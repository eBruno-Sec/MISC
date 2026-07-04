import { useEffect, useState, useCallback } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { api } from '../api'
import { useWebSocket } from '../hooks/useWebSocket'
import type { Mission, LogEntry, Finding, ApprovalRequest, MissionStatus, WSEvent } from '../types'
import GodStatus from './GodStatus'
import TerminalFeed from './TerminalFeed'
import FindingsPanel from './FindingsPanel'
import ApprovalGate from './ApprovalGate'

const STATUS_COLOR: Record<string, string> = {
  pending: 'var(--text-dim)', planning: 'var(--accent)', recon: 'var(--accent)',
  scanning: 'var(--gold)', exploiting: 'var(--accent2)', post_exploit: 'var(--accent2)',
  reporting: 'var(--accent3)', complete: 'var(--accent3)',
  awaiting_approval: 'var(--gold)', failed: 'var(--crit)',
}

export default function MissionControl() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()

  const [mission, setMission] = useState<Mission | null>(null)
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [findings, setFindings] = useState<Finding[]>([])
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([])
  const [status, setStatus] = useState<MissionStatus>('pending')
  const [currentPhase, setCurrentPhase] = useState<string | null>(null)
  const [completedPhases, setCompletedPhases] = useState<Set<string>>(new Set())
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    if (!id) return
    try {
      const m = await api.getMission(id)
      setMission(m)
      setLogs(m.logs)
      setFindings(m.findings)
      setApprovals(m.pending_approvals)
      setStatus(m.status as MissionStatus)
      setCurrentPhase(m.current_phase)

      // Infer completed phases from logs
      const phases = new Set<string>()
      const phaseOrder = ['zeus', 'athena', 'hermes', 'ares', 'hephaestus', 'hades', 'apollo']
      for (const log of m.logs) {
        if (m.current_phase && phaseOrder.indexOf(log.agent) < phaseOrder.indexOf(m.current_phase)) {
          phases.add(log.agent)
        }
        if (m.status === 'complete') phases.add(log.agent)
      }
      setCompletedPhases(phases)
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }, [id])

  useEffect(() => { load() }, [load])

  const onWsEvent = useCallback((event: WSEvent) => {
    switch (event.type) {
      case 'log':
        setLogs(prev => [...prev, {
          id: Math.random().toString(36).slice(2),
          agent: event.agent,
          symbol: event.symbol,
          level: event.level,
          message: event.message,
          timestamp: event.timestamp,
        }])
        break

      case 'finding':
        load()
        break

      case 'status_change':
        setStatus(event.status)
        if (event.phase) {
          setCurrentPhase(event.phase)
          if (event.status !== 'awaiting_approval') {
            setCompletedPhases(prev => {
              const phaseOrder = ['zeus', 'athena', 'hermes', 'ares', 'hephaestus', 'hades', 'apollo']
              const idx = phaseOrder.indexOf(event.phase!)
              const next = new Set(prev)
              phaseOrder.slice(0, idx).forEach(p => next.add(p))
              return next
            })
          }
        }
        if (event.status === 'complete') {
          setCompletedPhases(new Set(['zeus', 'athena', 'hermes', 'ares', 'hephaestus', 'hades', 'apollo']))
        }
        break

      case 'approval_required':
        setApprovals(prev => [...prev, {
          id: event.approval_id,
          agent: event.agent,
          action: event.action,
          description: event.description,
          created_at: event.timestamp,
        }])
        break

      case 'approval_resolved':
        setApprovals(prev => prev.filter(a => a.id !== event.approval_id))
        break

      case 'mission_complete':
      case 'mission_failed':
        load()
        break
    }
  }, [load])

  useWebSocket(id || null, onWsEvent)

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '50vh', color: 'var(--text-dim)', fontSize: '0.8rem' }}>
      Loading mission...
    </div>
  )

  if (!mission) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '50vh', color: 'var(--accent2)', fontSize: '0.8rem' }}>
      Mission not found. <button onClick={() => navigate('/')} style={{ color: 'var(--accent)', marginLeft: '1rem', cursor: 'pointer' }}>Back</button>
    </div>
  )

  const isLive = !['complete', 'failed'].includes(status)
  const color = STATUS_COLOR[status] || 'var(--text-dim)'

  return (
    <>
      <div style={{ display: 'flex', flexDirection: 'column', height: 'calc(100vh - 52px)' }}>
        {/* Mission header */}
        <div style={{
          padding: '1rem 1.5rem',
          background: 'var(--surface)', borderBottom: '1px solid var(--border)',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '1rem',
          flexWrap: 'wrap',
        }}>
          <div>
            <div style={{ fontSize: '0.65rem', letterSpacing: '0.25em', color: 'var(--text-dim)', marginBottom: '0.2rem' }}>
              {mission.id.slice(0, 8).toUpperCase()} · {mission.mode.toUpperCase()} MODE
            </div>
            <div style={{ fontFamily: 'var(--display)', fontSize: '1.3rem', fontWeight: 900, color: 'var(--text-bright)' }}>
              {mission.target}
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem' }}>
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: '0.65rem', letterSpacing: '0.15em', color: 'var(--text-dim)', marginBottom: '0.2rem' }}>STATUS</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color }}>
                {isLive && (
                  <span style={{ width: '7px', height: '7px', borderRadius: '50%', background: color, animation: 'pulse-border 1.5s ease infinite', display: 'inline-block' }} />
                )}
                <span style={{ fontSize: '0.78rem', fontWeight: 700, letterSpacing: '0.1em' }}>
                  {status.toUpperCase().replace('_', ' ')}
                </span>
              </div>
            </div>
            {status === 'complete' && (
              <a
                href={api.getReportUrl(mission.id)}
                target="_blank"
                rel="noopener noreferrer"
                style={{
                  fontSize: '0.72rem', letterSpacing: '0.15em',
                  padding: '0.4rem 1rem',
                  background: 'var(--accent3)',
                  color: 'var(--bg)',
                  fontFamily: 'var(--display)', fontWeight: 700,
                  textDecoration: 'none',
                }}
              >
                ☀ VIEW REPORT
              </a>
            )}
            <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>
              {findings.length} findings
            </div>
          </div>
        </div>

        {/* God status bar */}
        <GodStatus
          currentPhase={currentPhase}
          status={status}
          completedPhases={completedPhases}
        />

        {/* Main content: terminal + findings */}
        <div style={{ flex: 1, display: 'grid', gridTemplateColumns: '60% 40%', overflow: 'hidden' }}>
          <div style={{ borderRight: '1px solid var(--border)', overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
            <TerminalFeed logs={logs} />
          </div>
          <div style={{ overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
            <FindingsPanel findings={findings} />
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
    </>
  )
}
