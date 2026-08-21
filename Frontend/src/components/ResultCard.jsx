import React from 'react'
import { ShieldCheck, ShieldAlert, ShieldX, Clock } from 'lucide-react'
import ShieldRing from './ShieldRing.jsx'

const CONFIG = {
  SAFE: { icon: ShieldCheck, badgeClass: 'badge-safe', label: 'SAFE' },
  SUSPICIOUS: { icon: ShieldAlert, badgeClass: 'badge-suspicious', label: 'SUSPICIOUS' },
  PHISHING: { icon: ShieldX, badgeClass: 'badge-phishing', label: 'PHISHING' },
}

export default function ResultCard({ result }) {
  if (!result) return null

  if (result.applicable === false) {
    return (
      <div className="panel" style={{ borderColor: '#2A3542' }}>
        <p style={{ color: 'var(--text)', fontWeight: 500 }}>{result.message}</p>
        {result.raw_data && (
          <p style={{ marginTop: 10, fontFamily: 'var(--font-mono)', fontSize: '0.82rem' }}>
            Decoded content: {result.raw_data}
          </p>
        )}
      </div>
    )
  }

  const cfg = CONFIG[result.prediction] || CONFIG.SUSPICIOUS
  const Icon = cfg.icon

  return (
    <div className="panel">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 20, flexWrap: 'wrap' }}>
        <div style={{ flex: 1, minWidth: 240 }}>
          <span className={`badge ${cfg.badgeClass}`}>
            <Icon size={14} /> {cfg.label}
          </span>
          <p className="mono" style={{ marginTop: 14, wordBreak: 'break-all', color: 'var(--text)', fontSize: '0.88rem' }}>
            {result.url}
          </p>

          <div style={{ marginTop: 18 }}>
            <span className="eyebrow">Why</span>
            <ul style={{ margin: '10px 0 0', paddingLeft: 18, color: 'var(--text-muted)', fontSize: '0.88rem', lineHeight: 1.8 }}>
              {result.reasons.map((r, i) => <li key={i}>{r}</li>)}
            </ul>
          </div>

          <div style={{ marginTop: 18, display: 'flex', gap: 18, flexWrap: 'wrap', color: 'var(--text-muted)', fontSize: '0.8rem' }}>
            <span>Confidence: <b style={{ color: 'var(--text)' }}>{result.confidence}%</b></span>
            {result.prediction_time_ms != null && (
              <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                <Clock size={13} /> {result.prediction_time_ms} ms
              </span>
            )}
          </div>
        </div>

        <ShieldRing score={result.risk_score} size={128} label="RISK SCORE" />
      </div>
    </div>
  )
}
