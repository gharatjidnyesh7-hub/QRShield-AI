import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { LockKeyhole, ShieldCheck } from 'lucide-react'
import {
  AUTHORITY_NAME,
  AUTHORITY_USERNAME,
  validateAuthorityCredentials,
  saveAuthorityToken,
} from '../auth/auth.js'

export default function AuthorityLogin() {
  const navigate = useNavigate()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')

  const handleSubmit = (e) => {
    e.preventDefault()
    setError('')

    if (!validateAuthorityCredentials(username.trim(), password)) {
      setError('Invalid authority name or password.')
      return
    }

    // Frontend-only demo session. The backend must still protect real authority data in production.
    saveAuthorityToken('frontend-demo-authority-session')
    navigate('/authority', { replace: true })
  }

  return (
    <div className="page-container" style={{ maxWidth: 500 }}>
      <div className="panel" style={{ marginTop: 30 }}>
        <div style={{
          width: 48, height: 48, borderRadius: 12,
          background: 'var(--shield-glow)',
          display: 'grid', placeItems: 'center',
          marginBottom: 18
        }}>
          <ShieldCheck size={25} color="var(--shield)" />
        </div>

        <span className="eyebrow">Restricted access</span>
        <h1 style={{ marginTop: 10, fontSize: '1.9rem' }}>Authority Login</h1>
        <p style={{ marginTop: 8 }}>
          Only the authorized QRShield authority can access the dashboard.
        </p>

        <form onSubmit={handleSubmit} style={{
          marginTop: 28,
          display: 'flex',
          flexDirection: 'column',
          gap: 14
        }}>
          <div>
            <label style={{ display: 'block', marginBottom: 7, fontSize: '0.84rem' }}>
              Authority name
            </label>
            <input
              className="input"
              value={username}
              onChange={e => setUsername(e.target.value)}
              autoComplete="username"
              placeholder="Enter authority name"
            />
          </div>

          <div>
            <label style={{ display: 'block', marginBottom: 7, fontSize: '0.84rem' }}>
              Password
            </label>
            <input
              className="input"
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              autoComplete="current-password"
              placeholder="Enter password"
            />
          </div>

          {error && (
            <div className="panel" style={{ padding: 14, borderColor: 'var(--danger)' }}>
              <p style={{ color: 'var(--danger)' }}>{error}</p>
            </div>
          )}

          <button className="btn btn-primary" type="submit">
            <LockKeyhole size={17} />
            Authority Sign In
          </button>
        </form>
      </div>
    </div>
  )
}
