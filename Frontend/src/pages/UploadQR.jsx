import React, { useState, useRef } from 'react'
import { Upload, Loader2, ImageOff } from 'lucide-react'
import { scanQrImage } from '../api/client.js'
import ResultCard from '../components/ResultCard.jsx'

export default function UploadQR() {
  const [dragOver, setDragOver] = useState(false)
  const [preview, setPreview] = useState(null)
  const [analyzing, setAnalyzing] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)
  const inputRef = useRef(null)

  const handleFile = async (file) => {
    if (!file) return
    setError(null)
    setResult(null)

    const validTypes = ['image/png', 'image/jpeg', 'image/jpg']
    if (!validTypes.includes(file.type)) {
      setError('Only PNG, JPG, and JPEG files are supported.')
      return
    }

    setPreview(URL.createObjectURL(file))
    setAnalyzing(true)
    try {
      const res = await scanQrImage(file)
      if (res.decoded === false) {
        setError(res.message)
      } else {
        setResult(res)
      }
    } catch (err) {
      setError(err?.response?.data?.error || 'Could not reach the analysis backend. Is Flask running on port 5000?')
    } finally {
      setAnalyzing(false)
    }
  }

  return (
    <div className="page-container">
      <span className="eyebrow">Image upload</span>
      <h1 style={{ marginTop: 10, fontSize: '1.9rem' }}>Upload a QR code image</h1>
      <p style={{ marginTop: 8, maxWidth: 560 }}>
        Drag a PNG or JPG onto the box below, or click to browse. The image is decoded
        on the server and analyzed immediately.
      </p>

      <div
        className="scan-frame"
        onDragOver={(e) => { e.preventDefault(); setDragOver(true) }}
        onDragLeave={() => setDragOver(false)}
        onDrop={(e) => {
          e.preventDefault()
          setDragOver(false)
          handleFile(e.dataTransfer.files[0])
        }}
        onClick={() => inputRef.current?.click()}
        style={{
          marginTop: 28, maxWidth: 560, minHeight: 260,
          display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
          cursor: 'pointer', gap: 14, padding: 24,
          borderColor: dragOver ? 'var(--shield)' : undefined,
        }}
      >
        {preview ? (
          <img src={preview} alt="Uploaded QR preview" style={{ maxHeight: 180, borderRadius: 8 }} />
        ) : (
          <>
            <Upload size={32} color="var(--text-faint)" />
            <p>Drop an image here, or click to browse</p>
          </>
        )}
        <input
          ref={inputRef}
          type="file"
          accept=".png,.jpg,.jpeg,image/png,image/jpeg"
          style={{ display: 'none' }}
          onChange={(e) => handleFile(e.target.files[0])}
        />
      </div>

      {analyzing && (
        <div className="panel" style={{ marginTop: 28, display: 'flex', alignItems: 'center', gap: 12 }}>
          <Loader2 size={18} style={{ animation: 'spin 1s linear infinite' }} />
          <span>Decoding and analyzing...</span>
          <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
        </div>
      )}

      {error && (
        <div className="panel" style={{ marginTop: 28, display: 'flex', gap: 12, alignItems: 'flex-start' }}>
          <ImageOff size={18} color="var(--warning)" style={{ flexShrink: 0, marginTop: 2 }} />
          <p style={{ color: 'var(--text)' }}>{error}</p>
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
