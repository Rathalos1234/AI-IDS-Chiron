type EventHandler<T = any> = (data: T) => void

interface EventListeners {
  alert: Set<EventHandler>
  block: Set<EventHandler>
  scan: Set<EventHandler>
}

let eventSource: EventSource | null = null
const listeners: EventListeners = {
  alert: new Set(),
  block: new Set(),
  scan: new Set(),
}

function getTotalListeners(): number {
  return listeners.alert.size + listeners.block.size + listeners.scan.size
}

function dispatch<T>(type: keyof EventListeners, payload: T) {
  const handlerSet = listeners[type]
  if (!handlerSet) return

  handlerSet.forEach((handler) => {
    try {
      handler(payload)
    } catch (err) {
      console.error(`Error in ${type} event handler:`, err)
    }
  })
}

function getToken(): string | null {
  const token = localStorage.getItem('ids.auth.token')
  if (!token) return null

  const expiryRaw = localStorage.getItem('ids.auth.expiry')
  if (expiryRaw) {
    const expiry = Number(expiryRaw)
    if (Number.isFinite(expiry) && expiry <= Date.now()) {
      return null
    }
  }
  return token
}

function ensureEventSource() {
  if (eventSource) return

  const IDS_API_BASE = import.meta.env.VITE_IDS_API_BASE || 'http://localhost:5050'
  const url = new URL('/api/events', IDS_API_BASE)

  const token = getToken()
  if (token) {
    url.searchParams.set('token', token)
  }

  console.log('[IDS EventStream] Connecting to:', url.toString())
  eventSource = new EventSource(url.toString())

  eventSource.addEventListener('alert', (event: MessageEvent) => {
    try {
      const data = JSON.parse(event.data)
      console.log('[IDS EventStream] Received alert:', data)
      dispatch('alert', data)
    } catch (err) {
      console.error('Failed to parse alert event:', err)
    }
  })

  eventSource.addEventListener('block', (event: MessageEvent) => {
    try {
      const data = JSON.parse(event.data)
      console.log('[IDS EventStream] Received block:', data)
      dispatch('block', data)
    } catch (err) {
      console.error('Failed to parse block event:', err)
    }
  })

  eventSource.addEventListener('scan', (event: MessageEvent) => {
    try {
      const data = JSON.parse(event.data)
      console.log('[IDS EventStream] Received scan update:', data)
      dispatch('scan', data)
    } catch (err) {
      console.error('Failed to parse scan event:', err)
    }
  })

  eventSource.onerror = (error) => {
    console.warn('Event stream error, waiting for reconnect:', error)
  }

  eventSource.onopen = () => {
    console.info('Event stream connected to AI-IDS backend')
  }
}

export function subscribeToIDSEvents(
  type: keyof EventListeners,
  handler: EventHandler
): () => void {
  const handlerSet = listeners[type]
  handlerSet.add(handler)
  ensureEventSource()

  return () => {
    handlerSet.delete(handler)
    if (getTotalListeners() === 0 && eventSource) {
      eventSource.close()
      eventSource = null
      console.info('Event stream closed (no active listeners)')
    }
  }
}

export function closeIDSEventStream() {
  if (eventSource) {
    eventSource.close()
    eventSource = null
  }
  listeners.alert.clear()
  listeners.block.clear()
  listeners.scan.clear()
  console.info('Event stream closed and listeners cleared')
}
