



import React, { useState } from 'react'
import { analyzeMessage } from '../api/client'

export default function AnalyzeMessage() {
  const [message, setMessage] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const colors = {
    bg: '#0b1013',
    card: '#10171d',
    input: '#17212b',
    border: '#26333e',
    teal: '#19e6b3',
    muted: '#8da4b8',
    white: '#f4f7fb',
    red: '#ef4444',
  }

  async function handleAnalyze(e) {
    e.preventDefault()
    setError('')
    setResult(null)

    if (!message.trim()) {
      setError('Please paste a message to analyze.')
      return
    }

    setLoading(true)

    try {
      const data = await analyzeMessage(message)
      setResult(data)
    } catch (err) {
      setError(
        err.response?.data?.error ||
        'Analysis failed. Please check that the backend is running.'
      )
    } finally {
      setLoading(false)
    }
  }

  function resetAnalysis() {
    setMessage('')
    setResult(null)
    setError('')
  }

  const classification = result?.classification || {}

  const label =
    typeof classification === 'string'
      ? classification
      : classification.label || result?.label || 'Analysis complete'

  const riskLevel =
    classification.risk_level || result?.risk_level || 'Not specified'

  const riskScore = Number(
    classification.risk_score ?? result?.risk_score
  )

  const isHighRisk =
    /high|likely phishing|malicious/i.test(`${label} ${riskLevel}`)

  const indicators = Array.isArray(result?.message_indicators)
    ? result.message_indicators
    : []

  const recommendations = Array.isArray(result?.recommendations)
    ? result.recommendations
    : []

  const limitations = Array.isArray(result?.limitations)
    ? result.limitations
    : []

  const cardStyle = {
    background: colors.card,
    border: `1px solid ${colors.border}`,
    borderRadius: '14px',
    padding: '22px',
    marginTop: '18px',
    color: colors.white,
    boxSizing: 'border-box',
    width: '100%',
  }

  return (
    <main
      className="page-container"
      style={{
        maxWidth: '1000px',
        width: '100%',
        margin: '0 auto',
        padding: 'clamp(18px, 4vw, 36px)',
        boxSizing: 'border-box',
        color: colors.white,
      }}
    >
      <header style={{ marginBottom: '28px' }}>
        <div
          style={{
            color: colors.teal,
            fontSize: '12px',
            fontWeight: 700,
            letterSpacing: '2px',
            marginBottom: '12px',
          }}
        >
          ● QRSHIELD SECURITY
        </div>

        <h1
          style={{
            fontSize: 'clamp(27px, 4vw, 36px)',
            margin: '0 0 10px',
            fontWeight: 750,
          }}
        >
          Message Phishing Detector
        </h1>

        <p style={{ color: colors.muted, lineHeight: 1.7, margin: 0 }}>
          Check suspicious SMS messages, emails, and links for possible
          phishing attempts.
        </p>
      </header>

      <form
        onSubmit={handleAnalyze}
        style={{
          ...cardStyle,
          marginTop: 0,
          padding: 'clamp(18px, 3vw, 28px)',
        }}
      >
        <label
          htmlFor="message"
          style={{
            display: 'block',
            fontWeight: 600,
            marginBottom: '12px',
            fontSize: '14px',
          }}
        >
          Paste your message
        </label>

        <textarea
          id="message"
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          placeholder="Paste a suspicious SMS or email here..."
          rows={7}
          maxLength={5000}
          required
          style={{
            display: 'block',
            width: '100%',
            boxSizing: 'border-box',
            resize: 'vertical',
            padding: '15px',
            borderRadius: '9px',
            border: `1px solid ${colors.border}`,
            background: colors.input,
            color: colors.white,
            fontSize: '14px',
            lineHeight: 1.7,
            outlineColor: colors.teal,
            marginBottom: '16px',
          }}
        />

        <div
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            gap: '12px',
          }}
        >
          <button
            type="submit"
            disabled={loading}
            style={{
              padding: '13px 20px',
              borderRadius: '8px',
              border: 'none',
              background: colors.teal,
              color: '#061411',
              fontWeight: 750,
              fontSize: '14px',
              cursor: loading ? 'wait' : 'pointer',
              opacity: loading ? 0.7 : 1,
            }}
          >
            {loading ? 'Analyzing...' : '⌕  Analyze Message'}
          </button>

          {(message || result) && (
            <button
              type="button"
              onClick={resetAnalysis}
              style={{
                padding: '12px 18px',
                borderRadius: '8px',
                border: `1px solid ${colors.border}`,
                background: colors.input,
                color: colors.white,
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              Clear / Start Again
            </button>
          )}
        </div>
      </form>

      {error && (
        <div
          role="alert"
          style={{
            marginTop: '16px',
            padding: '14px',
            borderRadius: '9px',
            border: '1px solid #7f1d1d',
            background: '#291519',
            color: '#fecaca',
          }}
        >
          {error}
        </div>
      )}

      {result && (
        <section aria-live="polite" style={{ marginTop: '30px' }}>
          <h2 style={{ fontSize: '23px', marginBottom: '18px' }}>
            Analysis Result
          </h2>

          <div
            style={{
              ...cardStyle,
              borderColor: isHighRisk ? '#7f2933' : '#176b59',
            }}
          >
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                flexWrap: 'wrap',
                gap: '12px',
              }}
            >
              <span
                style={{
                  color: colors.muted,
                  fontSize: '13px',
                  letterSpacing: '1px',
                }}
              >
                CLASSIFICATION
              </span>

              <span
                style={{
                  padding: '7px 12px',
                  borderRadius: '20px',
                  fontSize: '11px',
                  fontWeight: 800,
                  letterSpacing: '0.5px',
                  background: isHighRisk ? '#541d26' : '#103d32',
                  color: isHighRisk ? '#ffb4bd' : colors.teal,
                  border: `1px solid ${isHighRisk ? '#b83246' : '#167a60'}`,
                }}
              >
                {isHighRisk ? 'HIGH RISK' : String(riskLevel).toUpperCase()}
              </span>
            </div>

            <h2 style={{ fontSize: '25px', margin: '17px 0 8px' }}>
              {label}
            </h2>

            <p style={{ color: colors.muted, marginBottom: '22px' }}>
              Risk level: <strong style={{ color: colors.white }}>
                {riskLevel}
              </strong>
            </p>

            {Number.isFinite(riskScore) && (
              <div>
                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    marginBottom: '10px',
                    fontSize: '14px',
                  }}
                >
                  <span>Risk score</span>
                  <strong>{riskScore}/100</strong>
                </div>

                <div
                  style={{
                    height: '8px',
                    borderRadius: '20px',
                    overflow: 'hidden',
                    background: '#293541',
                  }}
                >
                  <div
                    style={{
                      height: '100%',
                      width: `${Math.max(0, Math.min(100, riskScore))}%`,
                      borderRadius: '20px',
                      background: isHighRisk ? colors.red : colors.teal,
                      transition: 'width 0.3s ease',
                    }}
                  />
                </div>
              </div>
            )}
          </div>

          <div
            style={{
              ...cardStyle,
              borderColor: isHighRisk ? '#63303a' : '#176b59',
            }}
          >
            <h3 style={{ marginTop: 0, fontSize: '18px' }}>
              Recommended Action
            </h3>

            {isHighRisk ? (
              <ul style={{ paddingLeft: '22px', lineHeight: 2 }}>
                <li>Do not click links in this suspicious message.</li>
                <li>Never share your password, OTP, or banking details.</li>
                <li>
                  Verify the message using the official app or website
                  that you open independently.
                </li>
                <li>
                  If you already shared sensitive details, contact your
                  bank or service provider immediately.
                </li>
              </ul>
            ) : (
              <p style={{ color: colors.muted, lineHeight: 1.8 }}>
                No high-risk classification was returned. Still verify
                unexpected requests and avoid sharing passwords or OTPs.
              </p>
            )}
          </div>

          {indicators.length > 0 && (
            <div style={cardStyle}>
              <h3 style={{ marginTop: 0 }}>Warning Signs Detected</h3>

              {indicators.map((item, index) => (
                <div
                  key={item.id || index}
                  style={{
                    padding: '14px 0',
                    borderBottom:
                      index < indicators.length - 1
                        ? `1px solid ${colors.border}`
                        : 'none',
                  }}
                >
                  <strong>{item.label || item.id || 'Warning sign'}</strong>

                  {item.evidence && (
                    <p
                      style={{
                        color: colors.muted,
                        lineHeight: 1.7,
                        overflowWrap: 'anywhere',
                      }}
                    >
                      Evidence: {item.evidence}
                    </p>
                  )}

                  {item.severity && (
                    <small style={{ color: '#fbbf24' }}>
                      Severity: {item.severity}
                    </small>
                  )}
                </div>
              ))}
            </div>
          )}

          {recommendations.length > 0 && (
            <div style={cardStyle}>
              <h3 style={{ marginTop: 0 }}>Additional Recommendations</h3>
              <ul style={{ paddingLeft: '22px', lineHeight: 1.8 }}>
                {recommendations.map((item, index) => (
                  <li key={index}>
                    {typeof item === 'string'
                      ? item
                      : item.text || item.message || 'Review this recommendation'}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {limitations.length > 0 && (
            <details style={cardStyle}>
              <summary style={{ cursor: 'pointer', fontWeight: 600 }}>
                Analysis limitations
              </summary>
              <ul style={{ lineHeight: 1.8 }}>
                {limitations.map((item, index) => (
                  <li key={index}>{item}</li>
                ))}
              </ul>
            </details>
          )}

          <p
            style={{
              color: colors.muted,
              fontSize: '13px',
              lineHeight: 1.7,
              marginTop: '18px',
            }}
          >
            Automated detection can make mistakes. This assessment is
            guidance, not a guarantee of safety or fraud.
          </p>

          <button
            type="button"
            onClick={resetAnalysis}
            style={{
              padding: '13px 20px',
              borderRadius: '8px',
              border: 'none',
              background: colors.teal,
              color: '#061411',
              fontWeight: 750,
              cursor: 'pointer',
              marginTop: '8px',
            }}
          >
            Analyze Another Message
          </button>
        </section>
      )}
    </main>
  )
}
