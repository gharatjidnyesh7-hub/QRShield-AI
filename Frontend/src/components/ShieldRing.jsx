import React from 'react'

/**
 * ShieldRing — the app's signature recurring visual: a radial risk gauge.
 * Used on every result card and the dashboard so risk is always
 * communicated the same visual way throughout the product.
 */
export default function ShieldRing({ score = 0, size = 120, label = 'RISK' }) {
  const radius = (size - 14) / 2
  const circumference = 2 * Math.PI * radius
  const clamped = Math.max(0, Math.min(100, score))
  const offset = circumference - (clamped / 100) * circumference

  let color = '#1FE6B5'
  if (clamped >= 65) color = '#FF5468'
  else if (clamped >= 35) color = '#FFB648'

  return (
    <div className="shield-ring-wrap" style={{ width: size, height: size }}>
      <svg width={size} height={size} style={{ transform: 'rotate(-90deg)' }}>
        <circle
          cx={size / 2} cy={size / 2} r={radius}
          fill="none" stroke="#1A222C" strokeWidth="8"
        />
        <circle
          cx={size / 2} cy={size / 2} r={radius}
          fill="none" stroke={color} strokeWidth="8"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          style={{ transition: 'stroke-dashoffset 0.8s ease, stroke 0.3s ease' }}
        />
      </svg>
      <div className="shield-ring-label">
        <span className="shield-ring-value" style={{ color }}>{clamped}</span>
        <span className="shield-ring-unit">{label}</span>
      </div>
    </div>
  )
}
