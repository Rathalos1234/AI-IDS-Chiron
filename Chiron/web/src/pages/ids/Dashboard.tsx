import React, { useCallback, useEffect, useRef, useState } from 'react'
import { idsStats, idsAlerts, idsDevices, idsBlocks, idsStartDeviceScan, idsDeviceScanStatus } from '../../services/idsApi'
import { subscribeToIDSEvents } from '../../services/idsEventStream'

interface Stats {
  counts: {
    alerts_200?: number
    blocks_200?: number
    alerts_total?: number
    blocks_total?: number
  }
  ts?: string
}

interface Alert {
  id: string
  ts: string
  src_ip: string
  label: string
  severity: string
  kind: string
  fresh?: boolean
}

interface Device {
  ip: string
  first_seen?: string
  last_seen?: string
  name?: string
  open_ports?: string
  risk?: string
  fresh?: boolean
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

const IDSDashboard: React.FC = () => {
  const [stats, setStats] = useState<Stats | null>(null)
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [devices, setDevices] = useState<Device[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [scanning, setScanning] = useState(false)
  const [scanInfo, setScanInfo] = useState<ScanInfo | null>(null)
  const [scanCompleteHold, setScanCompleteHold] = useState(false)
  const [lastScanTs, setLastScanTs] = useState<string | null>(null)
  const deviceFreshTimers = useRef<number[]>([])
  const unknownDevices = devices.filter(d => !d?.name).length
  const totalAlertCount = stats?.counts?.alerts_total
  const alertCount = totalAlertCount ?? stats?.counts?.alerts_200 ?? 0
  const blockCount = stats?.counts?.blocks_200 ?? stats?.counts?.blocks_total ?? 0
  const alertDisplay = totalAlertCount != null
    ? alertCount.toLocaleString()
    : alertCount >= 200
      ? '200+'
      : String(alertCount)
  const scanProgress = scanInfo
    ? scanning || scanCompleteHold
      ? Math.min(100, Math.max(0, scanInfo.progress))
      : 0
    : 0

  const computeLastScanTs = (scan: ScanInfo | null | undefined): string | null => {
    if (!scan) return null
    const ts =
      scan.last_scan_ts ??
      scan.finished ??
      (scan.progress === 100 ? scan.ts ?? null : null)
    return ts ?? null
  }

  const lastScanTimestamp = lastScanTs || ((!scanning && scanInfo) ? computeLastScanTs(scanInfo) : null)
  const lastScanLabel = lastScanTimestamp ? new Date(lastScanTimestamp).toLocaleString() : null
  const showProgress = scanning || scanCompleteHold
  const isIdle = !scanning && !scanCompleteHold

  let scanStatus = 'idle'
  let scanStatusText = 'Idle'
  let scanDotClass = 'is-idle'

  if (scanCompleteHold) {
    scanStatus = 'done'
    scanStatusText = 'Scan complete!'
    scanDotClass = 'is-done'
  } else if (scanning) {
    scanStatus = 'running'
    scanStatusText = 'Scanning network...'
    scanDotClass = 'is-running'
  }

  const updateLastScanTimestamp = useCallback((scan: ScanInfo | null | undefined) => {
    if (!scan || scan.status === 'running') return
    const ts = computeLastScanTs(scan)
    if (ts) setLastScanTs(ts)
  }, [])

  const applyDeviceList = useCallback((rawDevices: any) => {
    const normalized: Device[] = (Array.isArray(rawDevices) ? rawDevices : rawDevices?.items || []) as Device[]
    setDevices((prevDevices) => {
      const prevMap = new Map(prevDevices.map((device) => [device.ip, device]))
      const hasPrev = prevDevices.length > 0
      const newIps: string[] = []
      const nextDevices = normalized.map((device) => {
        const ip = device.ip
        const isNew = Boolean(hasPrev && ip && !prevMap.has(ip))
        if (isNew && ip) newIps.push(ip)
        return { ...device, fresh: isNew }
      })

      if (newIps.length) {
        const newIpSet = new Set(newIps)
        const timeoutId = window.setTimeout(() => {
          setDevices((current) =>
            current.map((device) =>
              device.ip && newIpSet.has(device.ip) ? { ...device, fresh: false } : device
            )
          )
          deviceFreshTimers.current = deviceFreshTimers.current.filter((id) => id !== timeoutId)
        }, 500)
        deviceFreshTimers.current.push(timeoutId)
      }

      return nextDevices
    })
  }, [])

  const loadData = useCallback(async (withSpinner = false) => {
    try {
      if (withSpinner) setLoading(true)
      setError(null)
      const [statsData, alertsData, devicesData, blocksData] = await Promise.all([
        idsStats(),
        idsAlerts(5),
        idsDevices(),
        idsBlocks(),
      ])

      const activeBlocksCount = Array.isArray(blocksData.active) ? blocksData.active.length : 0
      const correctedStats = {
        ...statsData,
        counts: {
          ...statsData.counts,
          blocks_200: activeBlocksCount,
        },
      }
      setStats(correctedStats)
      updateLastScanTimestamp(statsData?.scan as ScanInfo)
      const normalizedAlerts = (Array.isArray(alertsData) ? alertsData : alertsData.items || []).map(
        (a: Alert) => ({ ...a, fresh: false })
      )
      setAlerts(normalizedAlerts)
      applyDeviceList(devicesData)
    } catch (e: any) {
      setError(e?.error || e?.message || 'Failed to load data')
    } finally {
      if (withSpinner) setLoading(false)
    }
  }, [updateLastScanTimestamp, applyDeviceList])

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
      await idsStartDeviceScan()
    } catch (e: any) {
      setError(e?.error || e?.message || 'Failed to start scan')
      setScanning(false)
    }
  }

  useEffect(() => {
    loadData(true)
    checkScanStatus()
  }, [loadData, checkScanStatus])

  useEffect(() => {
    const interval = setInterval(() => {
      loadData()
    }, 10000)
    return () => clearInterval(interval)
  }, [loadData])

  useEffect(() => {
    const unsubscribeAlert = subscribeToIDSEvents('alert', (newAlert) => {
      setAlerts((prevAlerts) => {
        const exists = prevAlerts.some(a => a.id === newAlert.id)
        if (exists) return prevAlerts
        const entry: Alert = { ...newAlert, fresh: true }
        const updated = [entry, ...prevAlerts].slice(0, 5)
        setTimeout(() => {
          setAlerts((current) =>
            current.map((item) =>
              item.id === newAlert.id ? { ...item, fresh: false } : item
            )
          )
        }, 700)
        return updated
      })
      setStats((prevStats) => {
        if (!prevStats) return prevStats
        const currentCount = prevStats.counts?.alerts_200 ?? 0
        const totalCount = prevStats.counts?.alerts_total ?? currentCount
        return {
          ...prevStats,
          counts: {
            ...prevStats.counts,
            alerts_200: Math.min(currentCount + 1, 200),
            alerts_total: totalCount + 1,
          },
        }
      })
    })

    const unsubscribeBlock = subscribeToIDSEvents('block', async () => {
      try {
        const blocksData = await idsBlocks()
        const activeBlocksCount = Array.isArray(blocksData.active) ? blocksData.active.length : 0
        setStats((prevStats) => {
          if (!prevStats) return prevStats
          const totalCount = prevStats.counts?.blocks_total ?? prevStats.counts?.blocks_200 ?? 0
          return {
            ...prevStats,
            counts: {
              ...prevStats.counts,
              blocks_200: activeBlocksCount,
              blocks_total: Math.max(totalCount, activeBlocksCount),
            },
          }
        })
      } catch (e) {
        // Just Ignore (doesnt rlly matter)
      }
    })

    const unsubscribeScan = subscribeToIDSEvents('scan', (data: any) => {
      if (data?.scan) {
        setScanInfo(data.scan)
        const isRunning = data.scan.status === 'running'
        setScanning((prevScanning) => {
          if (!isRunning && prevScanning && data.scan.progress === 100) {
            setScanCompleteHold(true)
            setTimeout(() => {
              setScanCompleteHold(false)
            }, 3500)
            loadData()
          }
          return isRunning
        })
        if (!isRunning && data.scan.progress === 100) {
          updateLastScanTimestamp(data.scan)
        }
      }
    })

    return () => {
      unsubscribeAlert()
      unsubscribeBlock()
      unsubscribeScan()
    }
  }, [loadData, updateLastScanTimestamp])

  useEffect(() => {
    if (!scanning) return
    const interval = setInterval(async () => {
      const stillRunning = await checkScanStatus()
      if (!stillRunning) {
        setScanning(false)
        loadData()
      } else {
        try {
          const devicesData = await idsDevices()
          applyDeviceList(devicesData)
        } catch (e) {
          // Agani here
        }
      }
    }, 2000)
    return () => clearInterval(interval)
  }, [scanning, checkScanStatus, loadData, applyDeviceList])

  useEffect(() => {
    return () => {
      deviceFreshTimers.current.forEach((id) => clearTimeout(id))
      deviceFreshTimers.current = []
    }
  }, [])

  return (
    <div className="ids-layout-shell">
        <div className="ids-view-header">
          <div>
            <h1>AI-IDS Dashboard</h1>
            <p>Intrusion Detection and Network Security</p>
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
          <div className="ids-alert-banner">
            {error}
          </div>
        )}
        <div className="ids-card-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))' }}>
          <div className="ids-surface ids-fade-in" style={{ animationDelay: '0s' }}>
            <div className="ids-small" style={{ marginBottom: '8px' }}>Alerts Logged</div>
            <div style={{ fontSize: '2.5rem', fontWeight: 700, color: 'var(--ids-danger)' }}>
              {alertDisplay}
            </div>
          </div>
          <div className="ids-surface ids-fade-in" style={{ animationDelay: '0.1s' }}>
            <div className="ids-small" style={{ marginBottom: '8px' }}>Active Blocks</div>
            <div style={{ fontSize: '2.5rem', fontWeight: 700, color: 'var(--ids-warning)' }}>
              {blockCount}
            </div>
          </div>
          <div className="ids-surface ids-fade-in" style={{ animationDelay: '0.2s' }}>
            <div className="ids-small" style={{ marginBottom: '8px' }}>Total Devices</div>
            <div style={{ fontSize: '2.5rem', fontWeight: 700, color: 'var(--ids-accent)' }}>
              {devices.length}
            </div>
          </div>
          <div className="ids-surface ids-fade-in" style={{ animationDelay: '0.3s' }}>
            <div className="ids-small" style={{ marginBottom: '8px' }}>Unknown Devices</div>
            <div style={{ fontSize: '2.5rem', fontWeight: 700, color: 'var(--ids-warning)' }}>
              {unknownDevices}
            </div>
          </div>
        </div>
        <div className="ids-surface ids-scan-status-card ids-fade-in" style={{ animationDelay: '0.4s' }}>
          <div className="ids-scan-status-card__meta">
            <div className="ids-scan-status-card__status" style={{ gap: '20px' }}>
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
        <div style={{ display: 'grid', gap: '24px', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', marginTop: '24px' }}>
          <div className="ids-surface ids-surface--reveal ids-fade-in" style={{ animationDelay: '0.5s', display: 'flex', flexDirection: 'column' }}>
            <h2 style={{ margin: '0 0 16px', fontSize: '1.25rem', color: 'var(--ids-fg)' }}>
              Detected Devices ({devices.length})
            </h2>
            {loading ? (
              <div className="ids-small">Loading...</div>
            ) : devices.length === 0 ? (
              <div className="ids-small">No devices detected.</div>
            ) : (
              <div style={{ flex: 1 }}>
                <ul className="ids-recent-alerts" style={{ maxHeight: '360px', overflowY: 'auto' }}>
                  {devices.map((device, idx) => {
                    const riskLabel = device.risk || 'Unknown'
                    const riskClass = `ids-badge ${(riskLabel || '').toLowerCase()}`
                    return (
                      <li
                        key={device.ip || idx}
                        className={`ids-recent-alert ${device.fresh ? 'ids-recent-alert--new' : ''}`}
                      >
                        <div className="ids-recent-alert__top">
                          <span className="ids-recent-alert__ip ids-mono">{device.ip}</span>
                          <span className={riskClass}>{riskLabel}</span>
                        </div>
                        <div className="ids-recent-alert__label">
                          {device.name || 'Unnamed device'}
                        </div>
                        <div className="ids-recent-alert__time">
                          Last seen: {device.last_seen ? new Date(device.last_seen).toLocaleString() : '—'}
                        </div>
                        <div className="ids-small" style={{ marginTop: '4px' }}>
                          Open ports: {device.open_ports || '—'}
                        </div>
                      </li>
                    )
                  })}
                </ul>
              </div>
            )}
          </div>
          <div className="ids-surface ids-surface--reveal ids-fade-in" style={{ animationDelay: '0.6s' }}>
            <h2 style={{ margin: '0 0 16px', fontSize: '1.25rem', color: 'var(--ids-fg)' }}>Recent Alerts</h2>
            {loading ? (
              <div className="ids-small">Loading...</div>
            ) : alerts.length === 0 ? (
              <div className="ids-small">No recent alerts</div>
            ) : (
              <ul className="ids-recent-alerts" style={{ maxHeight: '360px', overflowY: 'auto' }}>
              {alerts.map((alert) => (
                <li
                  key={alert.id}
                  className={`ids-recent-alert ${alert.fresh ? 'ids-recent-alert--new' : ''}`}
                >
                    <div className="ids-recent-alert__top">
                      <span className="ids-recent-alert__ip ids-mono">{alert.src_ip}</span>
                      <span className={`ids-badge ${alert.severity}`}>{alert.severity}</span>
                    </div>
                    <div className="ids-recent-alert__label">{alert.label}</div>
                    <div className="ids-recent-alert__time">
                      {new Date(alert.ts).toLocaleString()}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
    </div>
  )
}

export default IDSDashboard
