import React, { useEffect, useState } from 'react'
import { idsBlocks, idsBlockIp, idsUnblockIp, idsTrustedList, idsTrustIp, idsUntrustIp } from '../../services/idsApi'
import { subscribeToIDSEvents } from '../../services/idsEventStream'

interface Block {
  id: string
  ip: string
  ts: string
  action: string
  reason?: string
  expires_at?: string
}

interface TrustedIp {
  ip: string
  note?: string
  created_ts?: string
}

interface TableEntry {
  kind: 'blocked' | 'trusted'
  ip: string
  ts: string
  detail: string
}

const IDSBlocks: React.FC = () => {
  const ALERT_DISMISS_MS = 2000
  const [blocks, setBlocks] = useState<Block[]>([])
  const [trusted, setTrusted] = useState<TrustedIp[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [status, setStatus] = useState<string | null>(null)
  const [ip, setIp] = useState('')
  const [reason, setReason] = useState('')
  const [duration, setDuration] = useState('')
  const [note, setNote] = useState('')
  const friendlyError = (err: any, fallback: string) => {
    const code = typeof err?.error === 'string' ? err.error.toLowerCase() : ''
    switch (code) {
      case 'bad_ip':
        return 'Please enter a valid IPv4 or IPv6 address.'
      case 'trusted_ip':
        return 'That address is trusted (please remove it from the trusted list manually first).'
      case 'block_exists':
        return 'That address is already blocked.'
      case 'not_blocked':
        return 'That address is not currently blocked.'
      case 'not_trusted':
        return 'That address is not on the trusted list.'
      default:
        return err?.message || fallback
    }
  }
  const setStatusMessage = (msg: string) => {
    setError(null)
    setStatus(msg)
    setTimeout(() => setStatus(null), ALERT_DISMISS_MS)
  }

  const setErrorMessage = (msg: string) => {
    setStatus(null)
    setError(msg)
    setTimeout(() => setError(null), ALERT_DISMISS_MS)
  }

  const deriveActiveBlocks = (list: Block[]): Block[] => {
    if (!Array.isArray(list)) return []
    const seen = new Set<string>()
    const active: Block[] = []
    for (const row of list) {
      if (!row || !row.ip || seen.has(row.ip)) continue
      seen.add(row.ip)
      if ((row.action || '').toLowerCase() === 'block') {
        active.push(row)
      }
    }
    return active
  }

  const refresh = async () => {
    try {
      setLoading(true)
      setError(null)
      setStatus(null)
      const [blocksData, trustedData] = await Promise.all([
        idsBlocks(),
        idsTrustedList(),
      ])
      const rawBlocks = Array.isArray(blocksData) ? blocksData : blocksData.items || []
      setBlocks(Array.isArray(blocksData.active) ? blocksData.active : deriveActiveBlocks(rawBlocks))
      setTrusted(Array.isArray(trustedData) ? trustedData : trustedData.items || [])
    } catch (e: any) {
      setErrorMessage(friendlyError(e, 'Failed to load data'))
    } finally {
      setLoading(false)
    }
  }

  const handleBlock = async () => {
    if (!ip.trim()) return
    try {
      const dm = duration ? parseInt(duration, 10) : undefined
      const target = ip.trim()
      await idsBlockIp(target, reason.trim() || '', dm)
      setStatusMessage(`Blocked ${target}`)
      setIp('')
      setReason('')
      setDuration('')
      await refresh()
    } catch (e: any) {
      setErrorMessage(friendlyError(e, 'Failed to block IP'))
    }
  }

  const handleUnblock = async (addr: string) => {
    try {
      await idsUnblockIp(addr)
      setStatusMessage(`Unblocked ${addr}`)
      await refresh()
    } catch (e: any) {
      setErrorMessage(friendlyError(e, 'Failed to unblock IP'))
    }
  }

  const handleTrust = async () => {
    if (!ip.trim()) return
    try {
      const target = ip.trim()
      await idsTrustIp(target, note.trim() || '')
      setStatusMessage(`Marked ${target} as trusted`)
      setIp('')
      setNote('')
      await refresh()
    } catch (e: any) {
      setErrorMessage(friendlyError(e, 'Failed to trust IP'))
    }
  }

  const handleUntrust = async (addr: string) => {
    try {
      await idsUntrustIp(addr)
      setStatusMessage(`Removed ${addr} from trusted list`)
      await refresh()
    } catch (e: any) {
      setErrorMessage(friendlyError(e, 'Failed to untrust IP'))
    }
  }

  useEffect(() => {
    refresh()
  }, [])

  useEffect(() => {
    const unsubscribe = subscribeToIDSEvents('block', (blockEvent) => {
      refresh()
    })
    return () => {
      unsubscribe()
    }
  }, [])

  const tableEntries: TableEntry[] = [
    ...blocks.map((b) => ({
      kind: 'blocked' as const,
      ip: b.ip,
      ts: b.ts || '',
      detail: b.reason || '',
    })),
    ...trusted.map((t) => ({
      kind: 'trusted' as const,
      ip: t.ip,
      ts: t.created_ts || '',
      detail: t.note || '',
    })),
  ].sort((a, b) => {
    const order = { trusted: 0, blocked: 1 }
    if (order[a.kind] !== order[b.kind]) {
      return order[a.kind] - order[b.kind]
    }
    if (a.ts && b.ts) return b.ts.localeCompare(a.ts)
    if (a.ts) return -1
    if (b.ts) return 1
    return a.ip.localeCompare(b.ip)
  })

  const entryDate = (ts: string) => {
    if (!ts) return '—'
    if (ts.includes('T')) {
      return ts.split('T')[0]
    }
    return ts
  }

  const entryDetail = (text: string) => {
    return text && String(text).trim() ? text : '—'
  }

  return (
    <div className="ids-layout-shell">
      <div className="ids-view-header">
          <div>
            <h1>Ban List</h1>
            <p>Manage banned and trusted ip addresses.</p>
          </div>
          <div className="ids-actions-row">
            <button className="ids-btn" onClick={refresh} disabled={loading}>
              {loading ? 'Refreshing…' : 'Refresh'}
            </button>
          </div>
        </div>
        <div className="ids-stack" style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {error && (
            <div className="ids-alert-banner" style={{ '--alert-life': '2s' } as React.CSSProperties}>
              {error}
            </div>
          )}
          {status && (
            <div className="ids-alert-banner success" style={{ '--alert-life': '2s' } as React.CSSProperties}>
              {status}
            </div>
          )}
        </div>
        <section className="ids-surface ids-surface--soft ids-fade-in" style={{ marginBottom: '20px', animationDelay: '0s' }}>
          <div className="ids-actions-row" style={{ flexWrap: 'wrap', gap: '12px' }}>
            <input
              className="ids-input"
              value={ip}
              onChange={(e) => setIp(e.target.value)}
              placeholder="IP address"
              style={{ minWidth: '180px' }}
            />
            <input
              className="ids-input"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Reason (optional)"
              style={{ minWidth: '200px' }}
            />
            <input
              className="ids-input"
              value={duration}
              onChange={(e) => setDuration(e.target.value)}
              placeholder="Minutes (blank = permanent)"
              style={{ minWidth: '200px' }}
            />
            <button className="ids-btn ids-btn--danger" onClick={handleBlock} disabled={!ip.trim()}>
              Block
            </button>
          </div>
          <div className="ids-actions-row" style={{ flexWrap: 'wrap', gap: '12px', marginTop: '14px' }}>
            <input
              className="ids-input"
              value={ip}
              onChange={(e) => setIp(e.target.value)}
              placeholder="IP address (trust)"
              style={{ minWidth: '180px' }}
            />
            <input
              className="ids-input"
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder="Trust note (optional)"
              style={{ minWidth: '200px' }}
            />
            <div className="ids-actions-row" style={{ gap: '10px' }}>
              <button className="ids-btn ids-btn--primary" onClick={handleTrust} disabled={!ip.trim()}>
                Trust
              </button>
            </div>
          </div>
        </section>
        <section className="ids-surface ids-table-card ids-fade-in" style={{ animationDelay: '0.1s' }}>
          <table>
            <thead>
              <tr>
                <th>Date</th>
                <th>IP Address</th>
                <th>Details</th>
                <th>Status</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {tableEntries.length === 0 ? (
                <tr>
                  <td colSpan={5} className="ids-small" style={{ textAlign: 'center', padding: '18px' }}>
                    No entries yet.
                  </td>
                </tr>
              ) : (
                tableEntries.map((entry) => (
                  <tr key={`${entry.kind}-${entry.ip}`}>
                    <td>{entryDate(entry.ts)}</td>
                    <td className="ids-mono" style={{ color: 'var(--ids-accent)' }}>{entry.ip}</td>
                    <td>{entryDetail(entry.detail)}</td>
                    <td>
                      <span className={`ids-badge ${entry.kind === 'trusted' ? 'ids-badge--trusted' : 'ids-badge--blocked'}`}>
                        {entry.kind === 'trusted' ? 'TRUSTED' : 'BLOCKED'}
                      </span>
                    </td>
                    <td>
                      {entry.kind === 'blocked' ? (
                        <button className="ids-btn ids-btn--ghost" onClick={() => handleUnblock(entry.ip)}>
                          Unblock
                        </button>
                      ) : (
                        <button className="ids-btn ids-btn--ghost" onClick={() => handleUntrust(entry.ip)}>
                          Untrust
                        </button>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </section>
    </div>
  )
}

export default IDSBlocks
