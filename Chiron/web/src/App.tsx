import { useEffect, useMemo, useState } from 'react'
import { Link, Route, Routes, useLocation, useNavigate, useSearchParams } from 'react-router-dom'
import type { Control, Status } from './types'
import SidebarShell from './components/SidebarShell'
import ControlsList from './pages/ControlsList'
import ControlDetail from './pages/ControlDetail'
import Home from './pages/Home'
import Poams from './pages/Poams'
import Policies from './pages/Policies'
import EvidenceLibrary from './pages/EvidenceLibrary'
import SprScore from './pages/SprScore'
import Login from './pages/Login'
import ResetPassword from './pages/ResetPassword' 
import AuthRoute, { AUTH_CHANGE_EVENT, AUTH_COMPLETE_KEY, getCurrentUserID, logout } from './context/AuthRoute'
import { useBusinessContext } from './context/BusinessContext'
import BusinessSelector from './components/BusinessSelector'
import UnifiedSettings from './pages/UnifiedSettings'
// IDS stuff
import IDSDashboard from './pages/ids/Dashboard'
import IDSAlerts from './pages/ids/Alerts'
import IDSBlocks from './pages/ids/Blocks'
import IDSDevices from './pages/ids/Devices'
import IDSLogs from './pages/ids/Logs'

function sortControls(arr: Control[]): Control[] {
  const familyOrder = ['AC', 'AT', 'AU', 'CM', 'IA', 'IR', 'MA', 'MP', 'PS', 'PE', 'RA', 'CA', 'SC', 'SI']
  function familyIndex(f?: string) {
    const idx = f ? familyOrder.indexOf(f) : -1
    return idx === -1 ? 999 : idx
  }
  function parseParts(code: string) {
    const match = code.match(/(\d+)\.(\d+)\.(\d+)/)
    return match ? [Number(match[1]), Number(match[2]), Number(match[3])] : [999, 999, 999]
  }
  return [...arr].sort((a, b) => {
    const fa = familyIndex(a.family)
    const fb = familyIndex(b.family)
    if (fa !== fb) return fa - fb
    const [a1, a2, a3] = parseParts(a.code)
    const [b1, b2, b3] = parseParts(b.code)
    if (a1 !== b1) return a1 - b1
    if (a2 !== b2) return a2 - b2
    if (a3 !== b3) return a3 - b3
    return a.code.localeCompare(b.code)
  })
}

function resolveTitle(pathname: string) {
  if (pathname.startsWith('/controls/')) return 'Control Detail'
  if (pathname.startsWith('/ids')) {
    const idsTitle = pathname.replace('/ids', 'IDS')
    return idsTitle.split('/').pop()?.replace(/^./, c => c.toUpperCase()) || 'IDS'
  }
  const titles: Record<string, string> = {
    '/': 'Dashboard',
    '/controls': 'Controls',
    '/spr': 'SPR Score',
    '/poams': 'POAMs',
    '/policies': 'Policies',
    '/settings': 'Settings',
  }
  return titles[pathname] ?? 'Overview'
}

type FilterStatus = Status | 'unanswered' | null

export default function App() {
  const [searchParams] = useSearchParams()
  const [hasLoginSession, setHasLoginSession] = useState(() => readAuthCompletionFlag())
  const {
    loading,
    error,
    currentUserId,
    memberBusinesses,
    controls,
    selectedBusiness,
    selectBusiness,
    clearSelectedBusiness,
    updateControl,
    canCreateBusiness,
    canManageSelected,
    pendingInvites,
    leaveBusiness,
  } = useBusinessContext()

  const [accountMenuOpen, setAccountMenuOpen] = useState(false)
  const [showBusinessPicker, setShowBusinessPicker] = useState(false)
  const [businessMenuOpen, setBusinessMenuOpen] = useState(false)
  const shouldShowLogin = !hasLoginSession
  const navigate = useNavigate()
  const location = useLocation()
  const requiresWorkspace = !shouldShowLogin && !loading && memberBusinesses.length === 0

  const sortedControls = useMemo(() => sortControls(controls), [controls])

  const handleControlUpdate = (control: Control) => {
    const userId = getCurrentUserID() ?? currentUserId ?? 'local-user'
    const timestamp = new Date().toISOString()
    updateControl({ ...control, updatedBy: userId, updatedAt: timestamp }, { updatedBy: userId, updatedAt: timestamp })
  }

  const statusFilter: FilterStatus = (searchParams.get('status') as FilterStatus) || null
  const filtered = useMemo(() => {
    if (!statusFilter) return sortedControls
    if (statusFilter === 'unanswered') return sortedControls.filter(c => !c.status)
    return sortedControls.filter(c => c.status === statusFilter)
  }, [sortedControls, statusFilter])


  useEffect(() => {
    setAccountMenuOpen(false)
    setBusinessMenuOpen(false)
  }, [location.pathname])

  useEffect(() => {
    if (typeof window === 'undefined') return
    const handler = () => setHasLoginSession(readAuthCompletionFlag())
    window.addEventListener('storage', handler)
    window.addEventListener(AUTH_CHANGE_EVENT, handler)
    return () => {
      window.removeEventListener('storage', handler)
      window.removeEventListener(AUTH_CHANGE_EVENT, handler)
    }
  }, [])

  useEffect(() => {
    if (shouldShowLogin && location.pathname !== '/login') {
      navigate('/login', { replace: true })
    }
  }, [shouldShowLogin, location.pathname, navigate])

  useEffect(() => {
    if (!shouldShowLogin && location.pathname === '/login') {
      navigate('/', { replace: true })
    }
  }, [shouldShowLogin, location.pathname, navigate])

  useEffect(() => {
    if (location.pathname === '/login') {
      setShowBusinessPicker(false)
      return
    }

    if (!loading && requiresWorkspace) {
      setShowBusinessPicker(false) // ensure manual flag cleared
    }
  }, [loading, location.pathname, requiresWorkspace])

  const routes = (
    <Routes>
      <Route path="/" element={<AuthRoute><Home controls={sortedControls} /></AuthRoute>} />
      <Route path="/controls" element={<AuthRoute><ControlsList controls={filtered} /></AuthRoute>} />
      <Route
        path="/controls/:id"
        element={(
          <AuthRoute>
            <ControlDetail
              allControls={sortedControls}
              onUpdateControl={handleControlUpdate}
              readOnly={!canManageSelected}
            />
          </AuthRoute>
        )}
      />
      <Route path="/spr" element={<AuthRoute><SprScore controls={sortedControls} /></AuthRoute>} />
      <Route path="/poams" element={<AuthRoute><Poams /></AuthRoute>} />
      <Route path="/policies" element={<AuthRoute><Policies /></AuthRoute>} />
      <Route path="/evidence" element={<AuthRoute><EvidenceLibrary /></AuthRoute>} />
      <Route path="/settings" element={<AuthRoute><UnifiedSettings /></AuthRoute>} />
      
      {/* IDS Stuff */}
      <Route path="/ids" element={<AuthRoute><IDSDashboard /></AuthRoute>} />
      <Route path="/ids/dashboard" element={<AuthRoute><IDSDashboard /></AuthRoute>} />
      <Route path="/ids/alerts" element={<AuthRoute><IDSAlerts /></AuthRoute>} />
      <Route path="/ids/blocks" element={<AuthRoute><IDSBlocks /></AuthRoute>} />
      <Route path="/ids/devices" element={<AuthRoute><IDSDevices /></AuthRoute>} />
      <Route path="/ids/logs" element={<AuthRoute><IDSLogs /></AuthRoute>} />


      <Route path="/login" element={<Login />} />
      <Route path="/reset-password" element={<ResetPassword />} />
    </Routes>
  )

  const isLoginRoute = location.pathname === '/login'

  const shellActions = (
    <div style={{ display: 'flex', gap: 12, alignItems: 'center' }} 
      onClick={() => {
        if (accountMenuOpen) setAccountMenuOpen(false)}
      }>
      {location.pathname === '/controls' && (
        <StatusFilters
          selected={statusFilter}
          onSelect={(value) => navigate(value ? `/controls?status=${value}` : '/controls')}
        />

      )}
      {!isLoginRoute && (
        <button
          type="button"
          onClick={() => setBusinessMenuOpen(prev => !prev)}
          style={{
            background: 'transparent',
            border: '1px solid var(--border)',
            padding: '6px 12px',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            color: 'var(--text)',
          }}
        >
          {selectedBusiness ? selectedBusiness.name : 'Choose a company'}
          <span style={{ fontSize: '.8rem' }}>▾</span>
        </button>
      )}
      {!isLoginRoute && (
        <button
          type="button"
          onClick={() => { if (!showBusinessPicker) setAccountMenuOpen(true) } }
          style={{ background: 'transparent', border: '1px solid var(--border)', padding: '6px 12px', cursor: 'pointer', color: 'var(--text)',} }
        >
          Account
        </button>
      )}
    </div>
  )

  const accountMenu = accountMenuOpen && !isLoginRoute ? (
    <div
      style={{ position: 'fixed', inset: 1, background: 'rgba(0,0,0,0.4)'}}
      onClick={() => setAccountMenuOpen(false)}
    >
      <aside
        onClick={(event) => event.stopPropagation()}
        style={{ position: 'fixed', top: 72, right: 24, width: 220, background: '#fff', boxShadow: '-2px 0 8px rgba(0,0,0,0.15)', padding: 16, display: 'grid', gap: 8 }}
      >
        <strong>Account</strong>
        <Link to="/settings" onClick={() => setAccountMenuOpen(false)}>Settings</Link>
        <button
          type="button"
          onClick={() => {

            clearSelectedBusiness()
            setAccountMenuOpen(false)
            setShowBusinessPicker(true)
          }}
          disabled={!selectedBusiness}
          style={{
            background: 'transparent',
            border: '1px solid var(--border)',
            padding: '6px 12px',
            cursor: selectedBusiness ? 'pointer' : 'not-allowed',
            opacity: selectedBusiness ? 1 : 0.6,
          }}
        >
          Switch company
        </button>
        <button
          type="button"
          onClick={() => {
            setAccountMenuOpen(false)
            logout()
          }}
          style={{ background: 'transparent', border: '1px solid var(--border)', padding: '6px 12px', cursor: 'pointer', color: 'var(--text)', }}
        >
          Logout
        </button>
      </aside>
    </div>
  ) : null

  const businessMenu = businessMenuOpen && !isLoginRoute ? (
    <div
      style={{ position: 'fixed', inset: 0, background: 'transparent' }}
      onClick={() => setBusinessMenuOpen(false)}
    >
      <aside
        onClick={(event) => event.stopPropagation()}
        style={{ position: 'absolute', top: 72, right: 148, width: 260, background: '#fff', boxShadow: '0 8px 26px rgba(15,23,42,0.15)', padding: 16, display: 'grid', gap: 12, borderRadius: 12 }}
      >
        <strong style={{ fontSize: '.95rem' }}>Company actions</strong>
        {memberBusinesses.length > 0 ? (
          <div style={{ display: 'grid', gap: 6 }}>
            {memberBusinesses.map(business => (
              <button
                key={business.id}
                type="button"
                onClick={() => {
                  selectBusiness(business.id)
                  setBusinessMenuOpen(false)
                }}
                style={{
                  textAlign: 'left',
                  border: '1px solid var(--border)',
                  padding: '6px 8px',
                  borderRadius: 6,
                  background: business.id === selectedBusiness?.id ? 'rgba(37,99,235,0.08)' : 'transparent',
                  cursor: 'pointer',
                }}
              >
                {business.name}
              </button>
            ))}
          </div>
        ) : (
          <p style={{ fontSize: '.85rem', color: '#64748b', margin: 0 }}>You are not part of any companies yet.</p>
        )}
        <button
          type="button"
          onClick={() => {
            setShowBusinessPicker(true)
            setBusinessMenuOpen(false)
          }}
          style={{ border: '1px solid var(--border)', padding: '6px 10px', borderRadius: 6, background: 'transparent', cursor: 'pointer' }}
        >
          {memberBusinesses.length ? 'Join another company' : 'Join a company'}
        </button>
        <button
          type="button"
          onClick={() => {
            setShowBusinessPicker(true)
            setBusinessMenuOpen(false)
          }}
          disabled={!canCreateBusiness}
          style={{
            border: '1px solid var(--border)',
            padding: '6px 10px',
            borderRadius: 6,
            background: canCreateBusiness ? '#2563eb' : 'rgba(148,163,184,0.2)',
            color: canCreateBusiness ? '#fff' : 'var(--muted)',
            cursor: canCreateBusiness ? 'pointer' : 'not-allowed',
          }}
        >
          Create a company
        </button>
        <button
          type="button"
          onClick={() => {
            if (selectedBusiness) {
              leaveBusiness(selectedBusiness.id)
            }
            setBusinessMenuOpen(false)
          }}
          disabled={!selectedBusiness}
          style={{
            border: '1px solid var(--border)',
            padding: '6px 10px',
            borderRadius: 6,
            background: 'transparent',
            color: selectedBusiness ? '#b91c1c' : 'var(--muted)',
            cursor: selectedBusiness ? 'pointer' : 'not-allowed',
          }}
        >
          Leave current company
        </button>
      </aside>
    </div>
  ) : null

  if (isLoginRoute) {
    return routes
  }

  return (
    <>
      <SidebarShell title={resolveTitle(location.pathname)} actions={shellActions}>
        {routes}
      </SidebarShell>
      {businessMenu}
      {accountMenu}
      <BusinessSelector
        open={!shouldShowLogin && (requiresWorkspace || showBusinessPicker)}
        memberBusinesses={memberBusinesses}
        loading={loading}
        error={error}
        selectedId={selectedBusiness?.id ?? null}
        canCreateBusiness={canCreateBusiness}
        pendingInvites={pendingInvites}
        onSelect={(businessId) => {
          selectBusiness(businessId)
          setShowBusinessPicker(false)
        }}
        onClose={() => {
          if (requiresWorkspace || !selectedBusiness) return
          setShowBusinessPicker(false)
        }}
      />

    </>
  )
}

function readAuthCompletionFlag(): boolean {
  if (typeof window === 'undefined') return false
  return window.localStorage.getItem(AUTH_COMPLETE_KEY) === 'true'
}

function StatusFilters({ selected, onSelect }: { selected: FilterStatus; onSelect: (value: FilterStatus) => void }) {
  const options: FilterStatus[] = [null, 'unanswered', 'not_implemented', 'partially_implemented', 'fully_implemented']
  return (
    <select
      value={selected ?? ''}
      onChange={(event) => onSelect((event.target.value || null) as FilterStatus)}
      style={{ padding: '6px 8px' }}
      aria-label="Filter controls by status"
    >
      {options.map(option => (
        <option key={option ?? 'all'} value={option ?? ''}>{option ?? 'all'}</option>
      ))}
    </select>
  )
}
