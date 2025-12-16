import React, { useEffect, useState } from 'react'
import { idsLogs, idsExportLogs } from '../../services/idsApi'
import { subscribeToIDSEvents } from '../../services/idsEventStream'

interface LogEntry {
  id: string
  ts: string
  ip: string
  type: string
  label: string
  severity?: string
  kind?: string
}

const IDSLogs: React.FC = () => {
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [loadingMore, setLoadingMore] = useState(false)
  const [nextCursor, setNextCursor] = useState<string | null>(null)
  const loadLogs = async (options: { append?: boolean; cursor?: string | null } = {}) => {
    const { append = false, cursor = null } = options
    try {
      if (!append) setLoading(true)
      if (append) setLoadingMore(true)
      setError(null)
      const data = await idsLogs({ limit: 200, cursor: cursor || undefined })
      const items = Array.isArray(data) ? data : data.items || []
      if (append) {
        setLogs((prev) => {
          const existing = new Set(prev.map((log) => log.id))
          const merged = items.filter((log: LogEntry) => !existing.has(log.id))
          return [...prev, ...merged]
        })
      } else {
        setLogs(items)
      }
      const next =
        (typeof data === 'object' && !Array.isArray(data) && typeof data?.next_cursor === 'string')
          ? data.next_cursor
          : null
      setNextCursor(next)
    } catch (e: any) {
      setError(e?.error || e?.message || 'Failed to load logs')
    } finally {
      if (!append) setLoading(false)
      if (append) setLoadingMore(false)
    }
  }

  const handleExport = async (format: 'json' | 'csv') => {
    try {
      setError(null)
      await idsExportLogs({}, format)
    } catch (e: any) {
      setError(e?.error || e?.message || 'Failed to export logs')
    }
  }

  useEffect(() => {
    loadLogs()
  }, [])

  useEffect(() => {
    const unsubscribeAlert = subscribeToIDSEvents('alert', (newAlert) => {
      setLogs((prevLogs) => {
        const logEntry: LogEntry = {
          id: newAlert.id,
          ts: newAlert.ts,
          ip: newAlert.src_ip || newAlert.ip || '',
          type: 'alert',
          label: newAlert.label || newAlert.kind || '',
          severity: newAlert.severity,
          kind: newAlert.kind,
        }
        const exists = prevLogs.some(log => log.id === logEntry.id)
        if (exists) return prevLogs
        return [logEntry, ...prevLogs].slice(0, 1000)
      })
    })

    const unsubscribeBlock = subscribeToIDSEvents('block', (blockEvent) => {
      setLogs((prevLogs) => {
        const logEntry: LogEntry = {
          id: blockEvent.id,
          ts: blockEvent.ts,
          ip: blockEvent.ip || '',
          type: 'block',
          label: blockEvent.action || 'block',
          severity: undefined,
          kind: 'block',
        }
        const exists = prevLogs.some(log => log.id === logEntry.id)
        if (exists) return prevLogs
        return [logEntry, ...prevLogs].slice(0, 1000)
      })
    })

    return () => {
      unsubscribeAlert()
      unsubscribeBlock()
    }
  }, [])

  const formatDate = (ts: string) => {
    if (!ts) return ''
    return ts.split('T')[0]
  }

  const formatTime = (ts: string) => {
    if (!ts) return ''
    const timePart = ts.split('T')[1]
    return timePart ? timePart.slice(0, 5) : ''
  }

  const getSeverityBadgeClass = (severity?: string) => {
    if (!severity) return 'low'
    const lower = severity.toLowerCase()
    if (lower === 'critical' || lower === 'high') return 'high'
    if (lower === 'medium') return 'medium'
    return 'low'
  }

  return (
    <div className="ids-layout-shell">
      <div className="ids-view-header">
        <div>
          <h1>Log History</h1>
          <p>List of recent events</p>
        </div>
        <div className="ids-actions-row">
          <button className="ids-btn" onClick={() => handleExport('csv')}>
            Export CSV
          </button>
          <button className="ids-btn" onClick={() => handleExport('json')}>
            Export JSON
          </button>
        </div>
      </div>
      {error && (
        <div className="ids-alert-banner" style={{ marginBottom: '16px' }}>
          {error}
        </div>
      )}
      <section className="ids-surface ids-table-card ids-fade-in" style={{ animationDelay: '0s' }}>
        {loading && logs.length === 0 ? (
          <div className="ids-small">Loading...</div>
        ) : (
          <>
            <div style={{ overflowX: 'auto' }}>
              <table>
                <thead>
                  <tr>
                    <th>Date</th>
                    <th>Time</th>
                    <th>IP</th>
                    <th>Type</th>
                    <th>Severity</th>
                    <th>Description</th>
                  </tr>
                </thead>
                <tbody>
                  {logs.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="ids-small" style={{ textAlign: 'center', padding: '18px' }}>
                        No events yet.
                      </td>
                    </tr>
                  ) : (
                  logs.map((log: LogEntry) => (
                      <tr key={log.id}>
                        <td className="ids-small">{formatDate(log.ts)}</td>
                        <td className="ids-small">{formatTime(log.ts)}</td>
                        <td className="ids-mono" style={{ color: 'var(--ids-accent)' }}>{log.ip}</td>
                        <td style={{ textTransform: 'capitalize' }}>{log.type}</td>
                        <td>
                          {log.severity ? (
                            <span className={`ids-badge ${getSeverityBadgeClass(log.severity)}`}>
                              {log.severity}
                            </span>
                          ) : (
                            '—'
                          )}
                        </td>
                        <td>{log.label || log.kind || '—'}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
            {logs.length > 0 && nextCursor && (
              <div style={{ textAlign: 'center', marginTop: '16px' }}>
                <button
                  className="ids-btn"
                  onClick={() => loadLogs({ append: true, cursor: nextCursor })}
                  disabled={loadingMore}
                >
                  {loadingMore ? 'Loading…' : 'Load more'}
                </button>
              </div>
            )}
          </>
        )}
      </section>
    </div>
  )
}

export default IDSLogs
