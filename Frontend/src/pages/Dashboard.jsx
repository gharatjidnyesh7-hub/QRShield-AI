import React, { useEffect, useState } from 'react'
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts'
import { ShieldCheck, ShieldAlert, ShieldX, Activity } from 'lucide-react'
import { fetchDashboard } from '../api/client.js'

const COLORS = { SAFE: '#1FE6B5', SUSPICIOUS: '#FFB648', PHISHING: '#FF5468' }

export default function Dashboard() {
  const [stats, setStats] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    fetchDashboard().then(setStats).catch(() =>
      setError('Could not reach the analysis backend. Is Flask running on port 5000?')
    )
  }, [])

  if (error) {
    return (
      <div className="page-container">
        <div className="panel"><p style={{ color: 'var(--danger)' }}>{error}</p></div>
      </div>
    )
  }

  if (!stats) {
    return <div className="page-container"><p>Loading dashboard...</p></div>
  }

  const pieData = [
    { name: 'Safe', value: stats.safe_count },
    { name: 'Suspicious', value: stats.suspicious_count },
    { name: 'Phishing', value: stats.phishing_count },
  ]
  const barData = [
    { name: 'Safe', count: stats.safe_count },
    { name: 'Suspicious', count: stats.suspicious_count },
    { name: 'Phishing', count: stats.phishing_count },
  ]

  return (
    <div className="page-container">
      <span className="eyebrow">Overview</span>
      <h1 style={{ marginTop: 10, fontSize: '1.9rem' }}>Dashboard</h1>

      <div className="grid-4" style={{ marginTop: 28 }}>
        <StatCard icon={<Activity size={18} color="var(--text)" />} label="Total Scans" value={stats.total_scans} />
        <StatCard icon={<ShieldCheck size={18} color={COLORS.SAFE} />} label="Safe" value={stats.safe_count} color={COLORS.SAFE} />
        <StatCard icon={<ShieldAlert size={18} color={COLORS.SUSPICIOUS} />} label="Suspicious" value={stats.suspicious_count} color={COLORS.SUSPICIOUS} />
        <StatCard icon={<ShieldX size={18} color={COLORS.PHISHING} />} label="Phishing" value={stats.phishing_count} color={COLORS.PHISHING} />
      </div>

      <div className="grid-2" style={{ marginTop: 24 }}>
        <div className="panel">
          <h4 style={{ marginBottom: 18, fontSize: '1rem' }}>Scan distribution</h4>
          {stats.total_scans === 0 ? <EmptyNote /> : (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={pieData} dataKey="value" nameKey="name" innerRadius={55} outerRadius={85} paddingAngle={3}>
                  {pieData.map((entry, i) => (
                    <Cell key={i} fill={COLORS[entry.name.toUpperCase()]} stroke="none" />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ background: '#161E27', border: '1px solid #212B36', borderRadius: 8 }} />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>

        <div className="panel">
          <h4 style={{ marginBottom: 18, fontSize: '1rem' }}>Scan counts</h4>
          {stats.total_scans === 0 ? <EmptyNote /> : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={barData}>
                <CartesianGrid stroke="#1A222C" vertical={false} />
                <XAxis dataKey="name" stroke="#7C8A9A" fontSize={12} />
                <YAxis stroke="#7C8A9A" fontSize={12} allowDecimals={false} />
                <Tooltip contentStyle={{ background: '#161E27', border: '1px solid #212B36', borderRadius: 8 }} />
                <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                  {barData.map((entry, i) => (
                    <Cell key={i} fill={COLORS[entry.name.toUpperCase()]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      <div className="panel" style={{ marginTop: 24 }}>
        <h4 style={{ marginBottom: 16, fontSize: '1rem' }}>Recent activity</h4>
        {stats.recent_activity.length === 0 ? <EmptyNote /> : (
          <table className="data-table">
            <thead>
              <tr><th>Date</th><th>URL</th><th>Prediction</th><th>Risk</th></tr>
            </thead>
            <tbody>
              {stats.recent_activity.map(row => (
                <tr key={row.id}>
                  <td>{row.scan_date} {row.scan_time}</td>
                  <td style={{ maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{row.url}</td>
                  <td style={{ color: COLORS[row.prediction] }}>{row.prediction}</td>
                  <td>{row.risk_score}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}

function StatCard({ icon, label, value, color }) {
  return (
    <div className="panel panel-tight">
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>{icon}
        <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>{label}</span>
      </div>
      <div style={{ fontFamily: 'var(--font-display)', fontSize: '1.8rem', fontWeight: 700, color: color || 'var(--text)' }}>{value}</div>
    </div>
  )
}

function EmptyNote() {
  return <p>No scans yet. Run a scan from Scan QR, Upload QR, or Paste URL to see data here.</p>
}
