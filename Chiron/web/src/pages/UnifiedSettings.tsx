import { useEffect, useState, type FC, type CSSProperties } from 'react'
import { auth, db, isFirebaseConfigured } from '../firebase'
import { doc, getDoc, setDoc, serverTimestamp } from 'firebase/firestore'
import {
  updateProfile,
  updateEmail,
  reauthenticateWithCredential,
  EmailAuthProvider,
} from 'firebase/auth'
import { idsSettings, idsUpdateSettings, idsRunRetention, idsDownloadBackup, idsResetData, idsHealthCheckDetailed } from '../services/idsApi'

type SettingsTab = 'chiron' | 'ai-ids'
type ChironSection = 'user' | 'password' | 'mfa' | 'support' | 'operations'
type IconProps = { className?: string }
type IconComponent = FC<IconProps>

const UserIcon: IconComponent = () => null
const LockIcon: IconComponent = () => null
const ShieldIcon: IconComponent = () => null
const HelpIcon: IconComponent = () => null
const EyeIcon: IconComponent = () => null
const EyeOffIcon: IconComponent = () => null
const SaveIcon: IconComponent = () => null
const SettingsIcon: IconComponent = () => null

export default function UnifiedSettings() {
  const ALERT_DISMISS_MS = 2000
  const alertLifeSeconds = `${Math.max(ALERT_DISMISS_MS - 200, 400) / 1000}s`
  const [activeTab, setActiveTab] = useState<SettingsTab>('chiron')
  const [activeChironSection, setActiveChironSection] = useState<ChironSection>('user')

  // CHIRON settings 
  const [fullName, setFullName] = useState('')
  const [email, setEmail] = useState('')
  const [showCurrentPassword, setShowCurrentPassword] = useState(false)
  const [showNewPassword, setShowNewPassword] = useState(false)
  const [mfaEnabled, setMfaEnabled] = useState(false)
  const [saving, setSaving] = useState(false)
  const [saveMsg, setSaveMsg] = useState<string | null>(null)
  const [saveErr, setSaveErr] = useState<string | null>(null)

  // AIIDS settings
  const [idsConfig, setIdsConfig] = useState<any>({})
  const [idsDefaults, setIdsDefaults] = useState<any>({})
  const [idsLoading, setIdsLoading] = useState(false)
  const [idsSaving, setIdsSaving] = useState(false)
  const [idsErr, setIdsErr] = useState<string | null>(null)
  const [idsMsg, setIdsMsg] = useState<string | null>(null)
  const [idsFieldErrors, setIdsFieldErrors] = useState<Record<string, string | null>>({})
  const [idsFieldTouched, setIdsFieldTouched] = useState<Record<string, boolean>>({})
  const [showAllErrors, setShowAllErrors] = useState(false)

  // Stuff from AI-IDS Operations (in settings on the old UI)
  const [opsLoading, setOpsLoading] = useState<string | null>(null)
  const [opsMsg, setOpsMsg] = useState<string | null>(null)
  const [opsErr, setOpsErr] = useState<string | null>(null)
  const [healthStatus, setHealthStatus] = useState<any>(null)
  useEffect(() => {
    if (!healthStatus) return
    const timer = setTimeout(() => setHealthStatus(null), 12000)
    return () => clearTimeout(timer)
  }, [healthStatus])

  const settingFields = [
    {
      key: 'Signatures.Enable',
      label: 'Signatures.Enable',
      tooltip: 'True: turn rule-based detector on\nFalse: turn rule-based detector off'
    },
    {
      key: 'Logging.LogLevel',
      label: 'Logging.LogLevel',
      tooltip: 'DEBUG: everything - detailed developer messages, useful while diagnosing issues.\nINFO: normal operational messages\nWARNING: unusual conditions that aren\'t failures\nERROR: actual failures that prevented something from working\nChooses how chatty the backend logging is. Use INFO for normal use, DEBUG when troubleshooting'
    },
    {
      key: 'Logging.EnableFileLogging',
      label: 'Logging.EnableFileLogging',
      tooltip: 'True: backend also writes logs to a file'
    },
    {
      key: 'Monitoring.AlertThresholds',
      label: 'Monitoring.AlertThresholds',
      tooltip: 'E.g., -0.10, -0.05\nAlerts whose scores are more negative than -0.10 are labeled "High", between -0.10 and -0.05 are labeled "Medium" and above -0.05 are "Low"'
    },
    {
      key: 'Retention.AlertsDays',
      label: 'Retention.AlertsDays',
      placeholder: 'e.g. 7',
      tooltip: 'How long to keep alerts in the web database.'
    },
    {
      key: 'Retention.BlocksDays',
      label: 'Retention.BlocksDays',
      placeholder: 'e.g. 14',
      tooltip: 'How long to keep blocked or trusted IP records in the web database.'
    }
  ]

  useEffect(() => {
    if (!isFirebaseConfigured || !auth) return
    const u = auth.currentUser
    if (!u) return
    setEmail(u.email ?? '')
    setFullName(u.displayName ?? '')
    if (!db) return
    ;(async () => {
      const ref = doc(db, 'users', u.uid)
      const snap = await getDoc(ref)
      if (snap.exists()) {
        const data = snap.data() as { fullName?: string; email?: string }
        if (data.fullName) setFullName(data.fullName)
        if (data.email) setEmail(data.email)
      }
    })().catch(() => {})
  }, [])

  const loadIdsSettings = async () => {
    try {
      setIdsLoading(true)
      setIdsErr(null)
      const res = await idsSettings()
      const incoming = res.settings || {}
      const defaults = res.defaults || {}
      const normalized: Record<string, string> = {}
      for (const field of settingFields) {
        normalized[field.key] = String(incoming[field.key] ?? defaults[field.key] ?? '')
      }

      setIdsConfig(normalized)
      setIdsDefaults(defaults)
      const errors: Record<string, string | null> = {}
      const touched: Record<string, boolean> = {}
      for (const field of settingFields) {
        errors[field.key] = null
        touched[field.key] = false
      }

      setIdsFieldErrors(errors)
      setIdsFieldTouched(touched)
      setShowAllErrors(false)

    } catch (e: any) {
      setIdsErr(e?.error || e?.message || 'Failed to load IDS settings')
    } finally {
      setIdsLoading(false)
    }
  }

  useEffect(() => {
    loadIdsSettings()
  }, [])

  const handleSaveAccount = async () => {
    setSaving(true)
    setSaveMsg(null)
    setSaveErr(null)
    try {
      if (!isFirebaseConfigured || !auth) {
        throw new Error('Firebase isn\'t configured in this environment. Changes won\'t persist.')
      }
      const u = auth.currentUser
      if (!u) throw new Error('You must be signed in to save changes.')
      if (fullName && fullName !== (u.displayName ?? '')) {
        await updateProfile(u, { displayName: fullName })
      }

      if (email && email !== (u.email ?? '')) {
        try {
          await updateEmail(u, email)
        } catch (err: any) {
          if (err?.code === 'auth/requires-recent-login') {
            const pw = window.prompt('Enter your password again to change email:')
            if (!pw) throw new Error('Email change cancelled.')
            const cred = EmailAuthProvider.credential(u.email!, pw)
            await reauthenticateWithCredential(u, cred)
            await updateEmail(u, email)
          } else {
            throw err
          }
        }
      }

      if (db) {
        await setDoc(
          doc(db, 'users', u.uid),
          { fullName, email, updatedAt: serverTimestamp() },
          { merge: true }
        )
      }

      setSaveMsg('Profile saved!')
      setTimeout(() => setSaveMsg(null), ALERT_DISMISS_MS)
    } catch (e: any) {
      setSaveErr(e?.message ?? 'Failed to save changes.')
        setTimeout(() => setSaveErr(null), ALERT_DISMISS_MS)
    } finally {
      setSaving(false)
    }
  }

  const handleIdsFieldChange = (key: string, value: string) => {
    setIdsConfig((prev: any) => ({ ...prev, [key]: value }))
    setIdsFieldTouched((prev) => ({ ...prev, [key]: true }))
  }

  const validateIdsField = (key: string, value: string): string | null => {
    const LOG_LEVELS = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
    const TRUE_LITERALS = new Set(['true', '1', 'yes', 'on'])
    const FALSE_LITERALS = new Set(['false', '0', 'no', 'off'])

    try {
      if (key === 'Signatures.Enable' || key === 'Logging.EnableFileLogging') {
        const text = value.trim().toLowerCase()
        if (!text) return 'Must be true or false.'
        if (!TRUE_LITERALS.has(text) && !FALSE_LITERALS.has(text)) {
          return 'Must be true or false (for example, "true").'
        }
      } else if (key === 'Logging.LogLevel') {
        const text = value.trim().toUpperCase()
        if (!text) return 'Log level is required.'
        if (!LOG_LEVELS.includes(text)) {
          return `Log level must be one of ${LOG_LEVELS.join(', ')}.`
        }
      } else if (key === 'Monitoring.AlertThresholds') {
        const text = value.trim()
        if (!text) return 'Must include two numbers like "-0.10, -0.05".'
        const parts = text.split(',').map((p) => p.trim()).filter(Boolean)
        if (parts.length !== 2) {
          return 'Must include exactly two comma-separated numbers (high, medium).'
        }
        const hi = Number(parts[0])
        const med = Number(parts[1])
        if (!Number.isFinite(hi) || !Number.isFinite(med)) {
          return 'Must be two numbers like "-0.10, -0.05".'
        }
        if (hi > med) {
          return 'First value must be less than or equal to the second.'
        }
      } else if (key === 'Retention.AlertsDays' || key === 'Retention.BlocksDays') {
        const text = value.trim()
        if (!text) return 'Must be a whole number (0 or greater).'
        if (!/^\d+$/.test(text)) return 'Must be a whole number (0 or greater).'
        const num = Number.parseInt(text, 10)
        if (!Number.isFinite(num) || num < 0) {
          return 'Must be a whole number (0 or greater).'
        }
      }
      return null
    } catch {
      return 'Invalid value.'
    }
  }

  const handleSaveIdsSettings = async () => {
    setIdsSaving(true)
    setIdsErr(null)
    setIdsMsg(null)
    setShowAllErrors(false)

    const errors: Record<string, string | null> = {}
    let hasErrors = false
    for (const field of settingFields) {
      const error = validateIdsField(field.key, idsConfig[field.key] || '')
      errors[field.key] = error
      if (error) hasErrors = true
    }

    if (hasErrors) {
      setIdsFieldErrors(errors)
      setShowAllErrors(true)
      setIdsErr('Please check the highlighted values.')
      setIdsSaving(false)
      return
    }

    try {
      await idsUpdateSettings(idsConfig)
      setIdsMsg('Settings saved.')
      setTimeout(() => setIdsMsg(null), ALERT_DISMISS_MS)
      const touched: Record<string, boolean> = {}
      for (const field of settingFields) {
        touched[field.key] = false
      }
      setIdsFieldTouched(touched)
      setShowAllErrors(false)
    } catch (e: any) {
      setIdsErr(e?.error || e?.message || 'Failed to save settings')
      setTimeout(() => setIdsErr(null), ALERT_DISMISS_MS)
    } finally {
      setIdsSaving(false)
    }
  }

  const handleResetIdsSettings = () => {
    const resetValues: Record<string, string> = {}
    for (const field of settingFields) {
      resetValues[field.key] = String(idsDefaults[field.key] ?? '')
    }
    setIdsConfig(resetValues)

    const errors: Record<string, string | null> = {}
    const touched: Record<string, boolean> = {}
    for (const field of settingFields) {
      errors[field.key] = null
      touched[field.key] = false
    }
    setIdsFieldErrors(errors)
    setIdsFieldTouched(touched)
    setShowAllErrors(false)
    setIdsMsg('Settings reset to defaults. Make sure to Save')
    setTimeout(() => setIdsMsg(null), ALERT_DISMISS_MS)
  }

  useEffect(() => {
    const errors: Record<string, string | null> = {}
    for (const field of settingFields) {
      errors[field.key] = validateIdsField(field.key, idsConfig[field.key] || '')
    }
    setIdsFieldErrors(errors)
  }, [idsConfig])

  const renderChironUserSettings = () => (
    <div className="stack">
      <h3 style={{ margin: '0 0 12px' }}>Account Information</h3>

      {!isFirebaseConfigured && (
        <div className="ids-alert-banner" style={{ marginBottom: '16px' }}>
          Firebase isn't configured in this environment. Changes won't persist.
        </div>
      )}
      {saveMsg && (
        <div className="ids-alert-banner success" style={{ marginBottom: '16px' }}>
          {saveMsg}
        </div>
      )}
      {saveErr && (
        <div className="ids-alert-banner" style={{ marginBottom: '16px' }}>
          {saveErr}
        </div>
      )}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
        <label className="setting-field">
          <span className="setting-label">Full Name</span>
          <input
            className="input"
            type="text"
            value={fullName}
            onChange={(e) => setFullName(e.target.value)}
          />
        </label>
        <label className="setting-field">
          <span className="setting-label">Email Address</span>
          <input
            className="input"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
        </label>
      </div>
      <button
        onClick={handleSaveAccount}
        disabled={saving}
        className="btn btn--primary"
        style={{ marginTop: '8px' }}
      >
        <SaveIcon />
        {saving ? 'Saving…' : 'Save Changes'}
      </button>
    </div>
  )

  const renderChironPasswordSettings = () => (
    <div className="stack">
      <h3 style={{ margin: '0 0 12px' }}>Change Password</h3>
      <label className="setting-field">
        <span className="setting-label">Current Password</span>
        <div style={{ position: 'relative', width: '100%' }}>
          <input
            className="input"
            type={showCurrentPassword ? 'text' : 'password'}
            style={{ paddingRight: '40px', width: '100%' }}
          />
          <button
            type="button"
            onClick={() => setShowCurrentPassword(!showCurrentPassword)}
            className="btn--link"
            style={{ position: 'absolute', right: '12px', top: '50%', transform: 'translateY(-50%)' }}
          >
            {showCurrentPassword ? <EyeOffIcon /> : <EyeIcon />}
          </button>
        </div>
      </label>
      <label className="setting-field">
        <span className="setting-label">New Password</span>
        <div style={{ position: 'relative', width: '100%' }}>
          <input
            className="input"
            type={showNewPassword ? 'text' : 'password'}
            style={{ paddingRight: '40px', width: '100%' }}
          />
          <button
            type="button"
            onClick={() => setShowNewPassword(!showNewPassword)}
            className="btn--link"
            style={{ position: 'absolute', right: '12px', top: '50%', transform: 'translateY(-50%)' }}
          >
            {showNewPassword ? <EyeOffIcon /> : <EyeIcon />}
          </button>
        </div>
      </label>
      <button className="btn btn--primary" style={{ marginTop: '8px' }}>
        <LockIcon />
        Update Password
      </button>
    </div>
  )

  const renderChironMfaSettings = () => (
    <div className="stack">
      <h3 style={{ margin: '0 0 12px' }}>Multi-Factor Authentication</h3>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ flex: 1 }}>
          <p style={{ margin: '0 0 4px', fontWeight: 600 }}>Enable MFA</p>
          <p className="small" style={{ margin: 0 }}>Add an extra layer of security to your account.</p>
        </div>
        <button
          type="button"
          onClick={() => setMfaEnabled(!mfaEnabled)}
          className="btn"
          style={{
            width: '44px',
            height: '24px',
            padding: 0,
            borderRadius: '999px',
            background: mfaEnabled ? 'var(--success)' : 'var(--muted)',
            position: 'relative',
            border: 'none',
            flexShrink: 0
          }}
        >
          <span
            style={{
              position: 'absolute',
              width: '16px',
              height: '16px',
              borderRadius: '50%',
              background: '#fff',
              transition: 'transform 0.2s ease',
              transform: mfaEnabled ? 'translateX(20px)' : 'translateX(4px)',
              top: '4px',
              left: 0
            }}
          />
        </button>
      </div>
      {mfaEnabled && (
        <div className="ids-alert-banner success" style={{ marginTop: '16px' }}>
          MFA is enabled!
        </div>
      )}
    </div>
  )

  const renderChironSupportSettings = () => (
    <div className="stack">
      <h3 style={{ margin: '0 0 12px' }}>Support</h3>
      <button className="btn" style={{ justifyContent: 'space-between' }}>
        <span>Contact Support</span>
        <span className="small">support@example.com</span>
      </button>
    </div>
  )

  const handleRunRetention = async () => {
    setOpsLoading('retention')
    setOpsMsg(null)
    setOpsErr(null)
    try {
      await idsRunRetention()
      setOpsMsg('Retention job completed done')
      setTimeout(() => setOpsMsg(null), ALERT_DISMISS_MS)
    } catch (e: any) {
      setOpsErr(e?.error || e?.message || 'Failed to run retention')
      setTimeout(() => setOpsErr(null), ALERT_DISMISS_MS)
    } finally {
      setOpsLoading(null)
    }
  }

  const handleDownloadBackup = async () => {
    setOpsLoading('backup')
    setOpsMsg(null)
    setOpsErr(null)
    try {
      await idsDownloadBackup()
      setOpsMsg('Database backup downloaded')
      setTimeout(() => setOpsMsg(null), ALERT_DISMISS_MS)
    } catch (e: any) {
      setOpsErr(e?.error || e?.message || 'Failed to download backup')
      setTimeout(() => setOpsErr(null), ALERT_DISMISS_MS)
    } finally {
      setOpsLoading(null)
    }
  }

  const handleResetData = async () => {
    const confirmed = window.confirm('Are you sure you want to reset all data? This will clear alerts, blocks, devices, and banned/trusted IPs. This action cannot be undone.')
    if (!confirmed) return

    setOpsLoading('reset')
    setOpsMsg(null)
    setOpsErr(null)
    try {
      await idsResetData()
      setOpsMsg('Data reset completed')
      setTimeout(() => setOpsMsg(null), ALERT_DISMISS_MS)
    } catch (e: any) {
      setOpsErr(e?.error || e?.message || 'Failed to reset data')
      setTimeout(() => setOpsErr(null), ALERT_DISMISS_MS)
    } finally {
      setOpsLoading(null)
    }
  }

  const handleHealthCheck = async () => {
    setOpsLoading('health')
    setOpsMsg(null)
    setOpsErr(null)
    setHealthStatus(null)
    try {
      const status = await idsHealthCheckDetailed()
      setHealthStatus(status)
      setOpsMsg('Health check done')
      setTimeout(() => setOpsMsg(null), ALERT_DISMISS_MS)
    } catch (e: any) {
      setOpsErr(e?.error || e?.message || 'Health check failed')
      setTimeout(() => setOpsErr(null), ALERT_DISMISS_MS)
    } finally {
      setOpsLoading(null)
    }
  }

  const renderChironContent = () => {
    const chironNavigationItems: { id: ChironSection; label: string; icon: IconComponent }[] = [
      { id: 'user', label: 'Account', icon: UserIcon },
      { id: 'password', label: 'Change Password', icon: LockIcon },
      { id: 'mfa', label: 'Multi-Factor Authentication', icon: ShieldIcon },
      { id: 'support', label: 'Support', icon: HelpIcon },
    ]

    return (
      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(220px, 260px) 1fr', gap: '28px' }}>
        <nav className="stack" style={{ gap: '10px' }}>
          {chironNavigationItems.map((item, idx) => {
            const Icon = item.icon
            const isActive = activeChironSection === item.id
            return (
              <button
                key={item.id}
                onClick={() => setActiveChironSection(item.id)}
                className={`ids-surface ids-fade-in ${isActive ? 'ids-surface--active' : ''}`}
                style={{
                  animationDelay: `${idx * 0.06}s`,
                  padding: '16px 18px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '12px',
                  cursor: 'pointer',
                  transition: 'transform 0.2s ease, box-shadow 0.22s ease, border-color 0.2s ease, background 0.22s ease',
                  border: isActive ? '1px solid var(--ids-accent)' : '1px solid var(--ids-border)',
                  background: isActive ? 'var(--ids-accent-soft)' : 'var(--ids-panel)',
                  color: isActive ? 'var(--ids-accent)' : 'var(--ids-fg)'
                }}
                onMouseEnter={(e) => {
                  if (!isActive) {
                    e.currentTarget.style.transform = 'translateY(-1px)'
                    e.currentTarget.style.boxShadow = '0 12px 28px rgba(5, 8, 15, 0.42)'
                  }
                }}
                onMouseLeave={(e) => {
                  if (!isActive) {
                    e.currentTarget.style.transform = 'translateY(0)'
                    e.currentTarget.style.boxShadow = 'var(--ids-shadow)'
                  }
                }}
              >
                <Icon />
                <span style={{ fontWeight: 600 }}>{item.label}</span>
              </button>
            )
          })}
        </nav>
        <div className="surface surface--soft">
          {activeChironSection === 'user' && renderChironUserSettings()}
          {activeChironSection === 'password' && renderChironPasswordSettings()}
          {activeChironSection === 'mfa' && renderChironMfaSettings()}
          {activeChironSection === 'support' && renderChironSupportSettings()}
        </div>
      </div>
    )
  }

  const renderAiIdsContent = () => {
    if (idsLoading) {
      return (
        <div className="surface surface--soft">
          <p className="small">Loading IDS settings...</p>
        </div>
      )
    }

    const renderOpsCard = (
      <section className="surface surface--soft">
        <div style={{ marginBottom: '16px' }}>
          <h3 style={{ margin: 0 }}>Operations</h3>
          <p className="small" style={{ marginTop: '4px', color: 'var(--ids-muted)' }}>
            Maintenance and backup utilities for the AI-IDS backend.
          </p>
        </div>

        {opsMsg && (
          <div className="ids-alert-banner success" style={{ marginBottom: '16px', '--alert-life': '2s' } as CSSProperties}>
            {opsMsg}
          </div>
        )}
        {opsErr && (
          <div className="ids-alert-banner" style={{ marginBottom: '16px', '--alert-life': '2s' } as CSSProperties}>
            {opsErr}
          </div>
        )}

        <div
          className="ids-actions-row"
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
            gap: '14px',
            width: '100%',
          }}
        >
          <button
            onClick={handleRunRetention}
            disabled={opsLoading === 'retention'}
            className="ids-btn"
            style={{
              width: '100%',
              background: 'linear-gradient(135deg, rgba(91, 140, 255, 0.22), rgba(91, 140, 255, 0.08))',
              borderColor: 'rgba(91, 140, 255, 0.35)',
              color: 'var(--ids-fg)',
            }}
          >
            {opsLoading === 'retention' ? 'Running…' : 'Run Retention Now'}
          </button>

          <button
            onClick={handleDownloadBackup}
            disabled={opsLoading === 'backup'}
            className="ids-btn"
            style={{
              width: '100%',
              background: 'linear-gradient(135deg, rgba(91, 140, 255, 0.18), rgba(91, 140, 255, 0.06))',
              borderColor: 'rgba(91, 140, 255, 0.3)',
              color: 'var(--ids-fg)',
            }}
          >
            {opsLoading === 'backup' ? 'Downloading…' : 'Download DB Backup'}
          </button>

          <button
            onClick={handleHealthCheck}
            disabled={opsLoading === 'health'}
            className="ids-btn"
            style={{
              width: '100%',
              background: 'linear-gradient(135deg, rgba(67, 211, 173, 0.22), rgba(67, 211, 173, 0.08))',
              borderColor: 'rgba(67, 211, 173, 0.35)',
              color: 'var(--ids-fg)',
            }}
          >
            {opsLoading === 'health' ? 'Checking…' : 'Health Check'}
          </button>

          <button
            onClick={handleResetData}
            disabled={opsLoading === 'reset'}
            className="ids-btn"
            style={{
              width: '100%',
              background: 'linear-gradient(135deg, rgba(226, 77, 77, 0.25), rgba(226, 77, 77, 0.1))',
              color: 'var(--ids-danger)',
              borderColor: 'rgba(226, 77, 77, 0.4)',
            }}
          >
            {opsLoading === 'reset' ? 'Resetting…' : 'Reset Data'}
          </button>
        </div>

      </section>
    )

    return (
      <div className="stack" style={{ gap: '20px' }}>
        {idsErr && <div className="ids-alert-banner" style={{ marginBottom: '16px' }}>{idsErr}</div>}
        {idsMsg && <div className="ids-alert-banner success" style={{ marginBottom: '16px' }}>{idsMsg}</div>}
        <section className="surface surface--soft">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <h3 style={{ margin: 0 }}>IDS Configuration</h3>
            <div className="actions-row">
              <button className="btn btn--primary" onClick={handleSaveIdsSettings} disabled={idsSaving}>
                {idsSaving ? 'Saving…' : 'Save'}
              </button>
              <button className="btn btn--ghost" onClick={handleResetIdsSettings}>Reset</button>
            </div>
          </div>
          <div className="stack">
            {settingFields.map((field) => {
              const hasError = (showAllErrors || idsFieldTouched[field.key]) && idsFieldErrors[field.key]
              return (
                <label key={field.key} className="setting-field">
                  <span className="setting-label">
                    {field.label}
                    <span
                      className="info-tooltip"
                      tabIndex={0}
                      role="img"
                      aria-label="More information"
                      data-tooltip={field.tooltip}
                    >
                      ?
                    </span>
                  </span>
                  <input
                    className={`input ${hasError ? 'input--error' : ''}`}
                    placeholder={field.placeholder}
                    value={idsConfig[field.key] || ''}
                    onChange={(e) => handleIdsFieldChange(field.key, e.target.value)}
                    aria-invalid={!!hasError}
                  />
                  {hasError && (
                    <div className="input-error" role="alert">
                      {idsFieldErrors[field.key]}
                    </div>
                  )}
                </label>
              )
            })}
          </div>
        </section>
        {renderOpsCard}
        {healthStatus && (
          <section
            className="surface surface--soft ids-health-panel-enter"
            style={{ padding: '12px', '--health-life': '11s' } as CSSProperties}
          >
            <h4 style={{ margin: '0 0 8px', fontSize: '14px' }}>Health Status</h4>
            <div className="stack small" style={{ gap: '6px' }}>
              <div>
                <strong>Status:</strong> {healthStatus.ok ? 'Healthy' : 'Unhealthy'}
              </div>
              {healthStatus.time && (
                <div>
                  <strong>Timestamp:</strong> {new Date(healthStatus.time).toLocaleString()}
                </div>
              )}
              {typeof healthStatus.uptime_sec === 'number' && (
                <div>
                  <strong>Uptime:</strong> {Math.round(healthStatus.uptime_sec)} seconds
                </div>
              )}
            </div>
            <div className="small" style={{ marginTop: '6px', color: 'var(--ids-muted)' }}>
              This panel will disappear shortly.
            </div>
          </section>
        )}
      </div>
    )
  }
  
  return (
    <div className="fade-in" style={{ minHeight: '100vh' }}>
      <div className="layout-shell">
        <div className="view-header">
          <div>
            <h1>Settings</h1>
            <p>Configure CHIRON and AI-IDS system preferences.</p>
          </div>
        </div>
        <div className="ids-surface ids-fade-in" style={{ marginTop: '24px', padding: '12px', animationDelay: '0s' }}>
          <div className="ids-actions-row">
            <button
              className={`ids-btn ${activeTab === 'chiron' ? 'active' : ''}`}
              onClick={() => setActiveTab('chiron')}
            >
              CHIRON Settings
            </button>
            <button
              className={`ids-btn ${activeTab === 'ai-ids' ? 'active' : ''}`}
              onClick={() => setActiveTab('ai-ids')}
            >
              AI-IDS Settings
            </button>
          </div>
        </div>
        <div style={{ marginTop: '24px' }}>
          {activeTab === 'chiron' && renderChironContent()}
          {activeTab === 'ai-ids' && renderAiIdsContent()}
        </div>
      </div>
    </div>
  )
}
