import React, { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Activity, ShieldCheck, ShieldAlert, ShieldX, LogOut,
  RefreshCw, LockKeyhole
} from 'lucide-react'
import { fetchDashboard, fetchHistory } from '../api/client.js'
import { clearAuthorityToken } from '../auth/auth.js'

const COLORS = {
  SAFE: '#1FE6B5',
  SUSPICIOUS: '#FFB648',
  PHISHING: '#FF5468'
}

export default function AuthorityDashboard() {
  const navigate = useNavigate()
  const [stats, setStats] = useState(null)
  const [history, setHistory] = useState([])
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('ALL')

  const loadData = async () => {
    setLoading(true)
    setError(null)
    try {
      const [dashboard, rows] = await Promise.all([
        fetchDashboard(),
        fetchHistory(200),
      ])
      setStats(dashboard)
      setHistory(rows || [])
    } catch (err) {
      if (err?.response?.status === 401 || err?.response?.status === 403) {
        clearAuthorityToken()
        navigate('/authority-login', { replace: true })
        return
      }
      setError(
        err?.response?.data?.error ||
        'Could not reach the authority backend.'
      )
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadData()
  }, [])

  const logout = () => {
    clearAuthorityToken()
    navigate('/authority-login', { replace: true })
  }

  if (loading && !stats) {
    return (
      <div className="page-container">
        <p>Loading authority dashboard...</p>
      </div>
    )
  }

  return (
    <div className="page-container">
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'flex-start',
        gap: 16,
        flexWrap: 'wrap'
      }}>
        <div>
          <span className="eyebrow">Restricted area</span>
          <h1 style={{ marginTop: 10, fontSize: '1.9rem' }}>Authority Dashboard</h1>
          <p style={{ marginTop: 8 }}>
            Monitoring and records available to authenticated authority users.
          </p>
        </div>

        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn btn-ghost" onClick={loadData} disabled={loading}>
            <RefreshCw size={16} />
            Refresh
          </button>
          <button className="btn btn-ghost" onClick={logout}>
            <LogOut size={16} />
            Logout
          </button>
        </div>
      </div>

      {error && (
        <div className="panel" style={{ marginTop: 24, borderColor: 'var(--danger)' }}>
          <p style={{ color: 'var(--danger)' }}>{error}</p>
        </div>
      )}

      {stats && (
        <>
          <div className="grid-4" style={{ marginTop: 28 }}>
            <StatCard icon={<Activity size={18} />} label="Total Scans" value={stats.total_scans} />
            <StatCard icon={<ShieldCheck size={18} color={COLORS.SAFE} />} label="Safe" value={stats.safe_count} color={COLORS.SAFE} />
            <StatCard icon={<ShieldAlert size={18} color={COLORS.SUSPICIOUS} />} label="Suspicious" value={stats.suspicious_count} color={COLORS.SUSPICIOUS} />
            <StatCard icon={<ShieldX size={18} color={COLORS.PHISHING} />} label="Phishing" value={stats.phishing_count} color={COLORS.PHISHING} />
          </div>

          <div className="panel" style={{ marginTop: 24 }}>
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              gap: 12,
              flexWrap: 'wrap'
            }}>
              <div>
                <h3 style={{ fontSize: '1.1rem' }}>Scan history</h3>
                <p style={{ marginTop: 5 }}>Authority-only records.</p>
              </div>
              <div style={{ display: 'flex', gap: 7, flexWrap: 'wrap' }}>
                {['ALL', 'SAFE', 'SUSPICIOUS', 'PHISHING'].map(f => (
                  <button
                    key={f}
                    className="btn btn-ghost"
                    style={{
                      padding: '7px 12px',
                      fontSize: '0.76rem',
                      borderColor: filter === f ? 'var(--shield)' : undefined,
                      color: filter === f ? 'var(--shield)' : undefined,
                    }}
                    onClick={() => setFilter(f)}
                  >
                    {f}
                  </button>
                ))}
              </div>
            </div>

            <div style={{ overflowX: 'auto', marginTop: 18 }}>
              {history.length === 0 ? (
                <p>No scans recorded yet.</p>
              ) : (
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Date</th>
                      <th>Time</th>
                      <th>URL</th>
                      <th>Source</th>
                      <th>Prediction</th>
                      <th>Confidence</th>
                      <th>Risk</th>
                    </tr>
                  </thead>
                  <tbody>
                    {history
                      .filter(row => filter === 'ALL' || row.prediction === filter)
                      .map(row => (
                        <tr key={row.id}>
                          <td>{row.scan_date}</td>
                          <td>{row.scan_time}</td>
                          <td style={{
                            maxWidth: 320,
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap'
                          }}>
                            {row.url}
                          </td>
                          <td>{row.source}</td>
                          <td style={{ color: COLORS[row.prediction] }}>
                            {row.prediction}
                          </td>
                          <td>{row.confidence}%</td>
                          <td>{row.risk_score}</td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>

          <div className="panel" style={{
            marginTop: 24,
            display: 'flex',
            alignItems: 'center',
            gap: 12
          }}>
            <LockKeyhole size={18} color="var(--shield)" />
            <p>
              Authority data is protected by the authentication token supplied by the backend.
            </p>
          </div>
        </>
      )}
    </div>
  )
}

function StatCard({ icon, label, value, color }) {
  return (
    <div className="panel panel-tight">
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: 8,
        marginBottom: 10
      }}>
        {icon}
        <span style={{
          fontSize: '0.78rem',
          color: 'var(--text-muted)',
          textTransform: 'uppercase',
          letterSpacing: '0.04em'
        }}>
          {label}
        </span>
      </div>
      <div style={{
        fontFamily: 'var(--font-display)',
        fontSize: '1.8rem',
        fontWeight: 700,
        color: color || 'var(--text)'
      }}>
        {value ?? 0}
      </div>
    </div>
  )
}
