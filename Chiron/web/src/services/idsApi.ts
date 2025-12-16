const TOKEN_KEY = 'ids.auth.token'
const TOKEN_EXP_KEY = 'ids.auth.expiry'

function clearStoredToken() {
  localStorage.removeItem(TOKEN_KEY)
  localStorage.removeItem(TOKEN_EXP_KEY)
}

function getStoredToken(): string | null {
  const token = localStorage.getItem(TOKEN_KEY)
  if (!token) return null
  const expiryRaw = localStorage.getItem(TOKEN_EXP_KEY)
  if (expiryRaw) {
    const expiry = Number(expiryRaw)
    if (!Number.isFinite(expiry) || expiry <= Date.now()) {
      clearStoredToken()
      return null
    }
  }
  return token
}

function storeToken(token: string, expiresAt?: string, ttlSeconds?: number) {
  if (!token) {
    clearStoredToken()
    return
  }
  localStorage.setItem(TOKEN_KEY, token)
  let expiry: number | null = null
  if (expiresAt) {
    const parsed = Date.parse(expiresAt)
    if (!Number.isNaN(parsed)) expiry = parsed
  }
  if (!expiry && ttlSeconds) {
    expiry = Date.now() + Number(ttlSeconds) * 1000
  }
  if (expiry) {
    localStorage.setItem(TOKEN_EXP_KEY, String(expiry))
  } else {
    localStorage.removeItem(TOKEN_EXP_KEY)
  }
}

const parseJson = async (res: Response) => {
  let body: any = null
  try {
    body = await res.json()
  } catch (err) {
    body = null
  }
  if (res.status === 401) {
    clearStoredToken()
  }
  if (!res.ok) {
    const error: any = new Error(body?.error || `HTTP ${res.status}`)
    if (body && typeof body === 'object') Object.assign(error, body)
    error.status = res.status
    throw error
  }
  return body ?? {}
}

const IDS_API_BASE = import.meta.env.VITE_IDS_API_BASE || 'http://localhost:5050'
const authFetch = (path: string, options: RequestInit = {}) => {
  const token = getStoredToken()
  const headers: Record<string, string> = { ...(options.headers as Record<string, string> || {}) }
  if (token) headers.Authorization = `Bearer ${token}`
  const finalOptions: RequestInit = {
    credentials: 'include',
    ...options,
    headers,
  }
  return fetch(`${IDS_API_BASE}${path}`, finalOptions)
}

const authJson = (path: string, options: RequestInit = {}) => authFetch(path, options).then(parseJson)
export const idsLogin = async (username: string, password: string) => {
  const data = await authJson('/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  })
  if (data.token) {
    storeToken(data.token, data.expires_at, data.ttl)
  }
  return data
}

export const idsLogout = async () => {
  try {
    await authJson('/logout', { method: 'POST' })
  } finally {
    clearStoredToken()
  }
}

export const idsWhoami = () => authJson('/whoami')
export const idsStats = () => authJson('/api/stats')
export const idsAlerts = (limit?: number) => {
  const query = limit ? `?limit=${limit}` : ''
  return authJson(`/api/alerts${query}`)
}

export const idsBlocks = () => authJson('/api/blocks')
export const idsBlockIp = (ip: string, reason?: string, duration_minutes?: number) => {
  const payload: any = { ip, reason: reason || '' }
  if (duration_minutes != null) payload.duration_minutes = duration_minutes
  return authJson('/api/blocks', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export const idsUnblockIp = (ip: string) => {
  return authJson('/api/unblock', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip }),
  })
}

export const idsDevices = () => authJson('/api/devices')
export const idsStartDeviceScan = () => {
  return authJson('/api/scan', { method: 'POST' })
}

export const idsDeviceScanStatus = () => authJson('/api/scan/status')
export const idsUpdateDeviceName = (ip: string, name: string) => {
  return authJson('/api/device', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip, name }),
  })
}
export const idsSettings = () => authJson('/api/settings')
export const idsUpdateSettings = (settings: any) => {
  return authJson('/api/settings', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(settings),
  })
}

export const idsTrustedList = () => authJson('/api/trusted')
export const idsTrustIp = (ip: string, note?: string) => {
  return authJson('/api/trusted', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip, note: note || '' }),
  })
}
export const idsUntrustIp = (ip: string) => {
  return authJson(`/api/trusted/${encodeURIComponent(ip)}`, {
    method: 'DELETE',
  })
}

interface LogsParams {
  limit?: number
  ip?: string
  severity?: string
  type?: string
  from?: string
  to?: string
  cursor?: string
}

export const idsLogs = (params: LogsParams = {}) => {
  const queryParams = new URLSearchParams()
  if (params.limit) queryParams.append('limit', String(params.limit))
  if (params.ip) queryParams.append('ip', params.ip)
  if (params.severity) queryParams.append('severity', params.severity)
  if (params.type) queryParams.append('type', params.type)
  if (params.from) queryParams.append('from', params.from)
  if (params.to) queryParams.append('to', params.to)
  if (params.cursor) queryParams.append('cursor', params.cursor)
  const query = queryParams.toString() ? `?${queryParams.toString()}` : ''
  return authJson(`/api/logs${query}`)
}

export const idsExportLogs = async (params: LogsParams = {}, format: 'json' | 'csv' = 'json') => {
  const queryParams = new URLSearchParams()
  queryParams.append('format', format)
  if (params.ip) queryParams.append('ip', params.ip)
  if (params.severity) queryParams.append('severity', params.severity)
  if (params.type) queryParams.append('type', params.type)
  if (params.from) queryParams.append('from', params.from)
  if (params.to) queryParams.append('to', params.to)
  const res = await authFetch(`/api/logs/export?${queryParams.toString()}`)
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  const blob = await res.blob()
  const url = window.URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `ids-logs-${Date.now()}.${format}`
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  window.URL.revokeObjectURL(url)
  return blob
}

export const idsHealthCheck = () => fetch(`${IDS_API_BASE}/healthz`).then((res) => res.ok)
export const idsIsAuthenticated = (): boolean => {
  return getStoredToken() !== null
}

export const idsRunRetention = () => {
  return authJson('/api/retention/run', { method: 'POST' })
}

export const idsDownloadBackup = async () => {
  const res = await authFetch('/api/backup/db')
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  const blob = await res.blob()
  const url = window.URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `ids-backup-${Date.now()}.db`
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  window.URL.revokeObjectURL(url)
  return blob
}

export const idsResetData = () => {
  return authJson('/api/ops/reset', { method: 'POST' })
}

export const idsHealthCheckDetailed = () => authJson('/api/healthz')

export { clearStoredToken as idsClearToken }
