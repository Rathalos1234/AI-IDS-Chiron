import React, { useCallback, useEffect, useRef, useState } from 'react'
import { idsDevices, idsStartDeviceScan, idsDeviceScanStatus, idsUpdateDeviceName } from '../../services/idsApi'
import { subscribeToIDSEvents } from '../../services/idsEventStream'

interface Device {
  ip: string
  first_seen?: string
  last_seen?: string
  name?: string
  open_ports?: string
  risk?: string
}

interface ScanInfo {
  status: string
  progress: number
  done: number
  targets: number
  last_scan_ts?: string
  finished?: string
  ts?: string
}

const IDSDevices: React.FC = () => {
  const [devices, setDevices] = useState<Device[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [scanning, setScanning] = useState(false)
  const [scanInfo, setScanInfo] = useState<ScanInfo | null>(null)
  const [scanCompleteHold, setScanCompleteHold] = useState(false)
  const [lastScanTs, setLastScanTs] = useState<string | null>(null)
  const [editingIp, setEditingIp] = useState<string | null>(null)
  const [pendingName, setPendingName] = useState('')
  const [savingDevice, setSavingDevice] = useState<string | null>(null)
  const commitRef = useRef(false)
  const getSeverityBadgeClass = (risk?: string) => {
    if (!risk) return 'low'
    const lower = risk.toLowerCase()
    if (lower === 'high' || lower === 'critical') return 'high'
    if (lower === 'medium') return 'medium'
    return 'low'
  }

  const computeLastScanTs = (scan: ScanInfo | null | undefined): string | null => {
    if (!scan) return null
    const ts =
      scan.last_scan_ts ??
      scan.finished ??
      (scan.progress === 100 ? scan.ts ?? null : null)
    return ts ?? null
  }

  const updateLastScanTimestamp = useCallback((scan: ScanInfo | null | undefined) => {
    if (!scan || scan.status === 'running') return
    const ts = computeLastScanTs(scan)
    if (ts) setLastScanTs(ts)
  }, [])
  const loadDevices = useCallback(async () => {
    try {
      setLoading(true)
      setError(null)
      const data = await idsDevices()
      setDevices(Array.isArray(data) ? data : data.items || [])
    } catch (e: any) {
      setError(e?.error || e?.message || 'Failed to load devices')
    } finally {
      setLoading(false)
    }
  }, [])

  const checkScanStatus = useCallback(async () => {
    try {
      const data = await idsDeviceScanStatus()
      if (data?.scan) {
        setScanInfo(data.scan)
        const isRunning = data.scan.status === 'running'
        setScanning((prevScanning) => {
          if (!isRunning && prevScanning && data.scan.progress === 100) {
            setScanCompleteHold(true)
            setTimeout(() => {
              setScanCompleteHold(false)
            }, 3500)
          }
          return isRunning
        })
        if (!isRunning) {
          updateLastScanTimestamp(data.scan)
        }
        return isRunning
      }
      return false
    } catch (e) {
      return false
    }
  }, [updateLastScanTimestamp])

  const startScan = async () => {
    try {
      setScanning(true)
      setScanCompleteHold(false)
      setError(null)
      await idsStartDeviceScan()
    } catch (e: any) {
      setError(e?.error || e?.message || 'Failed to start scan')
      setScanning(false)
    }
  }

  useEffect(() => {
    loadDevices()
    checkScanStatus()
  }, [loadDevices, checkScanStatus])

  useEffect(() => {
    const unsubscribe = subscribeToIDSEvents('scan', (data: any) => {
      if (data?.scan) {
        setScanInfo(data.scan)
        const isRunning = data.scan.status === 'running'

        setScanning((prevScanning) => {
          if (!isRunning && prevScanning && data.scan.progress === 100) {
            setScanCompleteHold(true)
            setTimeout(() => {
              setScanCompleteHold(false)
            }, 3500)
            loadDevices()
          }
          return isRunning
        })
        if (!isRunning && data.scan.progress === 100) {
           updateLastScanTimestamp(data.scan)
        }
      }
    })
    return () => {
      unsubscribe()
    }
  }, [loadDevices, updateLastScanTimestamp])

  useEffect(() => {
    if (!scanning) return
    const interval = setInterval(async () => {
      const stillRunning = await checkScanStatus()
      if (!stillRunning) {
        setScanning(false)
        loadDevices()
      }
    }, 2000)
    return () => clearInterval(interval)
  }, [scanning, checkScanStatus])

  const beginEditName = (device: Device) => {
    if (!device.ip) return
    commitRef.current = false
    setEditingIp(device.ip)
    setPendingName(device.name || '')
  }

  const cancelEdit = () => {
    setEditingIp(null)
    setPendingName('')
    commitRef.current = false
  }

  const commitNameChange = async () => {
    if (!editingIp || commitRef.current) return
    const device = devices.find((d) => d.ip === editingIp)
    if (!device) {
      cancelEdit()
      return
    }
    const trimmed = pendingName.trim()
    if ((device.name || '') === trimmed) {
      cancelEdit()
      return
    }
    commitRef.current = true
    try {
      setSavingDevice(editingIp)
      await idsUpdateDeviceName(editingIp, trimmed)
      setDevices((prev) =>
        prev.map((d) => (d.ip === editingIp ? { ...d, name: trimmed || undefined } : d))
      )
    } catch (e: any) {
      setError(e?.error || e?.message || 'Failed to update device name')
    } finally {
      setSavingDevice(null)
      cancelEdit()
    }
  }

  const scanProgress = scanInfo
    ? scanning || scanCompleteHold
      ? Math.min(100, Math.max(0, scanInfo.progress))
      : 0
    : 0

  let scanStatusText = 'Idle'
  let scanDotClass = 'is-idle'

  if (scanCompleteHold) {
    scanStatusText = 'Scan complete!'
    scanDotClass = 'is-done'
  } else if (scanning) {
    scanStatusText = 'Scanning network...'
    scanDotClass = 'is-running'
  }

  const lastScanTimestamp = lastScanTs || ((!scanning && scanInfo) ? computeLastScanTs(scanInfo) : null)
  const lastScanLabel = lastScanTimestamp ? new Date(lastScanTimestamp).toLocaleString() : null
  const showProgress = scanning || scanCompleteHold
  const isIdle = !scanning && !scanCompleteHold

  return (
    <div className="ids-layout-shell">
      <div className="ids-view-header">
        <div>
          <h1>Network Devices</h1>
          <p>Discover and monitor devices on your network</p>
        </div>
        <div className="ids-actions-row">
          <button
            onClick={startScan}
            disabled={scanning || scanCompleteHold}
            className="ids-btn ids-btn--primary"
          >
            {scanning || scanCompleteHold ? 'Scanning...' : 'Start Network Scan'}
          </button>
        </div>
      </div>
        {error && (
          <div className="ids-alert-banner" style={{ marginBottom: '16px' }}>
            {error}
          </div>
        )}
        <div className="ids-surface ids-scan-status-card ids-fade-in" style={{ animationDelay: '0s' }}>
          <div className="ids-scan-status-card__meta">
            <div className="ids-scan-status-card__status" style={{ gap: '14px' }}>
              <div className={`ids-scan-status-card__dot ${scanDotClass}`}></div>
              <div className="ids-scan-status-card__text">
                <div className="ids-scan-status-card__label">Network Scanner</div>
                <div className="ids-scan-status-card__status-text">{scanStatusText}</div>
              </div>
            </div>
            {scanInfo && (
              <div className="ids-scan-status-card__time">
                {typeof scanInfo.done === 'number' && typeof scanInfo.targets === 'number' && (
                  <div className="ids-small">
                    {scanInfo.done} / {scanInfo.targets} targets
                  </div>
                )}
                {lastScanLabel && (
                  <div className="ids-small" style={{ color: 'var(--ids-fg-muted)', marginTop: '4px' }}>
                    Last scan: {lastScanLabel}
                  </div>
                )}
              </div>
            )}
          </div>
          <div
            className="ids-scan-status-card__progress"
            aria-hidden={!showProgress}
            style={{
              maxHeight: '64px',
              opacity: showProgress ? 1 : 0.3,
              transform: showProgress ? 'translateY(0)' : 'translateY(-6px)',
              transition: 'opacity 0.3s ease, transform 0.3s ease',
              marginTop: '8px',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px', width: '100%' }}>
              <div className="ids-progress-bar" style={{ overflow: 'hidden', borderRadius: '999px' }}>
                <div
                  className={`ids-progress-bar__fill ${scanCompleteHold ? 'ids-progress-bar__fill--complete' : 'ids-progress-bar__fill--active'}`}
                  style={{ width: `${scanProgress}%` }}
                ></div>
              </div>
              <div className="ids-small">{Math.round(scanProgress)}%</div>
            </div>
          </div>
        </div>
        <div className="ids-surface ids-table-card ids-fade-in" style={{ animationDelay: '0.1s', marginTop: '24px' }}>
          <h2 style={{ margin: '0 0 16px', fontSize: '1.25rem', color: 'var(--ids-fg)' }}>
            Detected Devices ({devices.length})
          </h2>
          {loading ? (
            <div className="ids-small">Loading devices...</div>
          ) : devices.length === 0 ? (
            <div className="ids-small">No devices found.</div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table>
                <thead>
                  <tr>
                    <th>IP Address</th>
                    <th>Device Name</th>
                    <th>First Seen</th>
                    <th>Last Seen</th>
                    <th>Open Ports</th>
                    <th>Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {devices.map((device, idx) => {
                    const isEditing = editingIp === device.ip
                    return (
                      <tr key={device.ip || idx}>
                        <td className="ids-mono" style={{ color: 'var(--ids-accent)' }}>{device.ip}</td>
                        <td
                          onDoubleClick={() => beginEditName(device)}
                          style={{ cursor: 'text', minWidth: '180px' }}
                        >
                          {isEditing ? (
                            <input
                              autoFocus
                              className="ids-input"
                              value={pendingName}
                              onChange={(e) => setPendingName(e.target.value)}
                              onBlur={() => commitNameChange()}
                              onKeyDown={(e) => {
                                if (e.key === 'Enter') {
                                  e.preventDefault()
                                  commitNameChange()
                                } else if (e.key === 'Escape') {
                                  e.preventDefault()
                                  cancelEdit()
                                }
                              }}
                              disabled={savingDevice === device.ip}
                              placeholder="Enter a device name"
                              style={{ fontSize: '0.95rem', padding: '6px 10px' }}
                            />
                          ) : (
                            device.name || <span className="ids-small">Unknown (double-click to name)</span>
                          )}
                        </td>
                        <td className="ids-small">
                          {device.first_seen ? new Date(device.first_seen).toLocaleString() : '—'}
                        </td>
                        <td className="ids-small">
                          {device.last_seen ? new Date(device.last_seen).toLocaleString() : '—'}
                        </td>
                        <td className="ids-mono ids-small">{device.open_ports || '—'}</td>
                        <td>
                          {device.risk ? (
                            <span className={`ids-badge ${getSeverityBadgeClass(device.risk)}`}>
                              {device.risk}
                            </span>
                          ) : (
                            '—'
                          )}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
    </div>
  )
}

export default IDSDevices
