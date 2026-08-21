import React, { useEffect, useState } from 'react'
import { fetchHistory } from '../api/client.js'

const COLORS = { SAFE: '#1FE6B5', SUSPICIOUS: '#FFB648', PHISHING: '#FF5468' }

export default function History() {
  const [rows, setRows] = useState(null)
  const [error, setError] = useState(null)
  const [filter, setFilter] = useState('ALL')

  useEffect(() => {
    fetchHistory(200).then(setRows).catch(() =>
      setError('Could not reach the analysis backend. Is Flask running on port 5000?')
    )
  }, [])

  return (
    <div className="page-container">
      <span className="eyebrow">Records</span>
      <h1 style={{ marginTop: 10, fontSize: '1.9rem' }}>Scan history</h1>
      <p style={{ marginTop: 8 }}>Every scan performed via webcam, upload, or manual entry, stored locally in SQLite.</p>

      <div style={{ display: 'flex', gap: 8, marginTop: 20 }}>
        {['ALL', 'SAFE', 'SUSPICIOUS', 'PHISHING'].map(f => (
          <button
            key={f}
            className="btn btn-ghost"
            style={{
              padding: '8px 16px', fontSize: '0.82rem',
              borderColor: filter === f ? 'var(--shield)' : undefined,
              color: filter === f ? 'var(--shield)' : undefined,
            }}
            onClick={() => setFilter(f)}
          >
            {f}
          </button>
        ))}
      </div>

      <div className="panel" style={{ marginTop: 20, overflowX: 'auto' }}>
        {error && <p style={{ color: 'var(--danger)' }}>{error}</p>}
        {!error && rows === null && <p>Loading history...</p>}
        {!error && rows && rows.length === 0 && <p>No scans recorded yet.</p>}
        {!error && rows && rows.length > 0 && (
          <table className="data-table">
            <thead>
              <tr>
                <th>Date</th><th>Time</th><th>URL</th><th>Source</th>
                <th>Prediction</th><th>Confidence</th><th>Risk</th>
              </tr>
            </thead>
            <tbody>
              {rows.filter(r => filter === 'ALL' || r.prediction === filter).map(row => (
                <tr key={row.id}>
                  <td>{row.scan_date}</td>
                  <td>{row.scan_time}</td>
                  <td style={{ maxWidth: 320, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{row.url}</td>
                  <td>{row.source}</td>
                  <td style={{ color: COLORS[row.prediction] }}>{row.prediction}</td>
                  <td>{row.confidence}%</td>
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
