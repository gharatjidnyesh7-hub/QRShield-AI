import React, { useState } from 'react'
import { Link2, Loader2 } from 'lucide-react'
import { analyzeUrl } from '../api/client.js'
import ResultCard from '../components/ResultCard.jsx'

export default function PasteURL() {
  const [url, setUrl] = useState('')
  const [analyzing, setAnalyzing] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!url.trim()) return
    setError(null)
    setResult(null)
    setAnalyzing(true)
    try {
      const res = await analyzeUrl(url.trim(), 'manual')
      setResult(res)
    } catch (err) {
      setError(err?.response?.data?.error || 'Could not reach the analysis backend. Is Flask running on port 5000?')
    } finally {
      setAnalyzing(false)
    }
  }

  return (
    <div className="page-container">
      <span className="eyebrow">Direct check</span>
      <h1 style={{ marginTop: 10, fontSize: '1.9rem' }}>Paste a URL to analyze</h1>
      <p style={{ marginTop: 8, maxWidth: 560 }}>
        Skip the QR code entirely — paste any link and get an instant ML-based risk
        assessment.
      </p>

      <form onSubmit={handleSubmit} style={{ marginTop: 28, maxWidth: 560, display: 'flex', gap: 10 }}>
        <input
          className="input"
          placeholder="https://example.com/login"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
        />
        <button className="btn btn-primary" disabled={analyzing} type="submit">
          {analyzing ? <Loader2 size={17} style={{ animation: 'spin 1s linear infinite' }} /> : <Link2 size={17} />}
          Analyze
        </button>
      </form>
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>

      {error && (
        <div className="panel" style={{ marginTop: 28, maxWidth: 560 }}>
          <p style={{ color: 'var(--danger)' }}>{error}</p>
        </div>
      )}

      {result && !analyzing && (
        <div style={{ marginTop: 28 }}>
          <ResultCard result={result} />
        </div>
      )}
    </div>
  )
}
