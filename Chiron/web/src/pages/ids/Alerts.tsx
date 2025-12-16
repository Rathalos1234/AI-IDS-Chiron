import React, { useEffect, useState } from 'react'
import { idsLogs, idsExportLogs } from '../../services/idsApi'
import { subscribeToIDSEvents } from '../../services/idsEventStream'

interface AlertEvent {
  id: string
  ts: string
  ip: string
  type: string
  detail: string
  severity: string
  score?: number | null
}

const PAGE_SIZE = 200
const MAX_STREAM_BUFFER = 1000
const IDSAlerts: React.FC = () => {
  const [items, setItems] = useState<AlertEvent[]>([])
  const [loading, setLoading] = useState(false)
  const [loadingMore, setLoadingMore] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [fIp, setFIp] = useState('')
  const [fSeverity, setFSeverity] = useState('')
  const [fType, setFType] = useState('')
  const [fFrom, setFFrom] = useState('')
  const [fTo, setFTo] = useState('')
  const [nextCursor, setNextCursor] = useState<string | null>(null)
  const formatScore = (score?: number | null): string => {
    return typeof score === 'number' && !isNaN(score) ? score.toFixed(3) : '—'
  }

  const splitLabel = (value?: string) => {
    const label = value || ''
    const match = String(label).match(/^(.*)\s+score=([-+]?\d*\.?\d+(?:e[-+]?\d+)?)/i)
    if (match) {
      return {
        text: match[1].trim(),
        score: Number(match[2]),
      }
    }
    return { text: label, score: null }
  }

  const normalize = (event: any): AlertEvent | null => {
    if (!event) return null
    const ts = event.ts || event.timestamp || ''
    if (event.type === 'alert' || event.kind === 'ANOMALY' || event.kind === 'SIGNATURE') {
      const { text, score } = splitLabel(event.label || event.kind || '')
      return {
        id: event.id,
        ts,
        ip: event.src_ip || event.ip || '',
        type: 'alert',
        detail: text || (event.kind || ''),
        severity: event.severity || '',
        score,
      }
    }

    if (event.type === 'block' || event.action === 'block' || event.action === 'unblock') {
      const type = event.action === 'block' ? 'block' : 'unblock'
      return {
        id: event.id,
        ts,
        ip: event.ip || event.src_ip || '',
        type,
        detail: event.action || '',
        severity: event.severity || '',
        score: null,
      }
    }

    const { text, score } = splitLabel(event.label || event.detail || '')
    return {
      id: event.id,
      ts,
      ip: event.ip || event.src_ip || '',
      type: event.type || event.kind || 'event',
      detail: text,
      severity: event.severity || '',
      score,
    }
  }

  const loadData = async (options: { append?: boolean; cursor?: string | null; showSpinner?: boolean } = {}) => {
    const { append = false, cursor = null, showSpinner = false } = options
    try {
      if (showSpinner) setLoading(true)
      setError(null)
      const data = await idsLogs({
        limit: PAGE_SIZE,
        ip: fIp || undefined,
        severity: fSeverity || undefined,
        type: fType || undefined,
        from: fFrom || undefined,
        to: fTo || undefined,
        cursor: cursor || undefined,
      })
      const page = Array.isArray(data) ? data : data.items || []
      const normalized = page.map(normalize).filter((row: AlertEvent | null): row is AlertEvent => row !== null)
      if (append) {
        setItems((prevItems) => {
          const existing = new Set(prevItems.map(item => item.id))
          const merged = normalized.filter((item: AlertEvent) => !existing.has(item.id))
          return [...prevItems, ...merged]
        })
      } else {
        setItems(normalized)
      }
      const next = (typeof data === 'object' && !Array.isArray(data) && typeof data?.next_cursor === 'string')
        ? data.next_cursor
        : null
      setNextCursor(next)
    } catch (e: any) {
      setError(e?.error || e?.message || 'Failed to load alerts')
    } finally {
      if (showSpinner) setLoading(false)
      if (append) setLoadingMore(false)
    }
  }

  const exportCsv = async () => {
    try {
      await idsExportLogs({
        ip: fIp || undefined,
        severity: fSeverity || undefined,
        type: fType || undefined,
        from: fFrom || undefined,
        to: fTo || undefined,
      }, 'csv')
    } catch (e: any) {
      setError(e?.error || e?.message || 'Export failed')
    }
  }

  const exportJson = async () => {
    try {
      await idsExportLogs({
        ip: fIp || undefined,
        severity: fSeverity || undefined,
        type: fType || undefined,
        from: fFrom || undefined,
        to: fTo || undefined,
      }, 'json')
    } catch (e: any) {
      setError(e?.error || e?.message || 'Export failed')
    }
  }

  useEffect(() => {
    loadData({ showSpinner: true })
  }, [])

  useEffect(() => {
    const unsubscribe = subscribeToIDSEvents('alert', (newAlert) => {
      setItems((prevItems) => {
        const normalized = normalize(newAlert)
        if (!normalized) return prevItems

        const matchesIp = !fIp || normalized.ip === fIp
        const matchesSeverity = !fSeverity || normalized.severity?.toLowerCase() === fSeverity.toLowerCase()
        const matchesType = !fType || normalized.type === fType
        const matchesFrom = !fFrom || normalized.ts >= fFrom
        const matchesTo = !fTo || normalized.ts <= fTo
        if (!(matchesIp && matchesSeverity && matchesType && matchesFrom && matchesTo)) {
          return prevItems
        }

        const exists = prevItems.some(item => item.id === normalized.id)
        if (exists) return prevItems
        return [normalized, ...prevItems].slice(0, MAX_STREAM_BUFFER)
      })
    })
    return () => {
      unsubscribe()
    }
  }, [fIp, fSeverity, fType, fFrom, fTo])

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
    if (lower === 'high' || lower === 'critical') return 'high'
    if (lower === 'medium') return 'medium'
    return 'low'
  }

  return (
    <div className="ids-layout-shell">
      <div className="ids-view-header">
          <div>
            <h1>Alerts</h1>
            <p>Timeline of Alerts.</p>
          </div>
          <div className="ids-actions-row">
            <button className="ids-btn" onClick={exportCsv}>
              Export CSV
            </button>
            <button className="ids-btn" onClick={exportJson}>
              Export JSON
            </button>
          </div>
        </div>
        <section className="ids-surface ids-surface--soft ids-fade-in" style={{ marginBottom: '16px', animationDelay: '0s' }}>
          <div className="ids-actions-row" style={{ flexWrap: 'wrap', gap: '12px' }}>
            <input
              className="ids-input"
              value={fIp}
              onChange={(e) => setFIp(e.target.value)}
              placeholder="IP (e.g., 192.168.1.10)"
              style={{ minWidth: '180px' }}
            />
            <select className="ids-input" value={fSeverity} onChange={(e) => setFSeverity(e.target.value)}>
              <option value="">Severity (any)</option>
              <option>low</option>
              <option>medium</option>
              <option>high</option>
              <option>critical</option>
            </select>
            <select className="ids-input" value={fType} onChange={(e) => setFType(e.target.value)}>
              <option value="">Type (any)</option>
              <option value="alert">alert</option>
              <option value="block">block</option>
              <option value="unblock">unblock</option>
            </select>
            <input
              className="ids-input"
              value={fFrom}
              onChange={(e) => setFFrom(e.target.value)}
              placeholder="From ISO (2025-10-01T00:00:00Z)"
              style={{ minWidth: '220px' }}
            />
            <input
              className="ids-input"
              value={fTo}
              onChange={(e) => setFTo(e.target.value)}
              placeholder="To ISO (2025-10-01T00:00:00Z)"
              style={{ minWidth: '220px' }}
            />
            <button className="ids-btn ids-btn--primary" onClick={() => loadData({ showSpinner: true })} disabled={loading}>
              {loading ? 'Loading…' : 'Apply'}
            </button>
          </div>
        </section>
        {error && (
          <div className="ids-alert-banner" style={{ marginBottom: '16px' }}>
            {error}
          </div>
        )}
        <section className="ids-surface ids-table-card ids-fade-in" style={{ animationDelay: '0.1s' }}>
          <table>
            <thead>
              <tr>
                <th>Date</th>
                <th>Time</th>
                <th>IP Address</th>
                <th>Type</th>
                <th>Severity</th>
                <th>Details</th>
                <th>Score</th>
              </tr>
            </thead>
            <tbody>
              {items.length === 0 ? (
                <tr>
                  <td colSpan={7} className="ids-small" style={{ textAlign: 'center', padding: '18px' }}>
                    No events yet.
                  </td>
                </tr>
              ) : (
                items.map((e) => (
                  <tr key={e.id + e.type}>
                    <td>{formatDate(e.ts)}</td>
                    <td>{formatTime(e.ts)}</td>
                    <td className="ids-mono" style={{ color: 'var(--ids-accent)' }}>{e.ip}</td>
                    <td style={{ textTransform: 'capitalize' }}>{e.type}</td>
                    <td>
                      {e.severity ? (
                        <span className={`ids-badge ${getSeverityBadgeClass(e.severity)}`}>
                          {e.severity}
                        </span>
                      ) : (
                        '—'
                      )}
                    </td>
                    <td>{e.detail}</td>
                    <td className="ids-mono ids-small">{formatScore(e.score)}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
          {items.length > 0 && nextCursor && (
            <div style={{ marginTop: '16px', textAlign: 'center' }}>
              <button
                className="ids-btn"
                onClick={() => {
                  if (!nextCursor) return
                  setLoadingMore(true)
                  loadData({ append: true, cursor: nextCursor })
                }}
                disabled={loadingMore}
              >
                {loadingMore ? 'Loading…' : 'Load more'}
              </button>
            </div>
          )}
        </section>
    </div>
  )
}

export default IDSAlerts
