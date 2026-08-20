import React, { useEffect, useRef, useState, useCallback } from 'react'
import jsQR from 'jsqr'
import { Camera, CameraOff, Loader2 } from 'lucide-react'
import { analyzeUrl } from '../api/client.js'
import ResultCard from '../components/ResultCard.jsx'

export default function ScanQR() {
  const videoRef = useRef(null)
  const canvasRef = useRef(document.createElement('canvas'))
  const streamRef = useRef(null)
  const rafRef = useRef(null)

  const [cameraOn, setCameraOn] = useState(false)
  const [cameraError, setCameraError] = useState(null)
  const [lastDecoded, setLastDecoded] = useState(null)
  const [analyzing, setAnalyzing] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)

  const stopCamera = useCallback(() => {
    if (rafRef.current) cancelAnimationFrame(rafRef.current)
    if (streamRef.current) {
      streamRef.current.getTracks().forEach(t => t.stop())
      streamRef.current = null
    }
    setCameraOn(false)
  }, [])

  const startCamera = useCallback(async () => {
    setCameraError(null)
    setResult(null)
    setError(null)
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: 'environment' },
      })
      streamRef.current = stream
      if (videoRef.current) {
        videoRef.current.srcObject = stream
        await videoRef.current.play()
      }
      setCameraOn(true)
      tick()
    } catch (err) {
      setCameraError(
        err.name === 'NotAllowedError'
          ? 'Camera access was denied. Please allow camera permission and try again.'
          : `Could not access the webcam: ${err.message}`
      )
    }
  }, [])

  const tick = useCallback(() => {
    const video = videoRef.current
    const canvas = canvasRef.current
    if (video && video.readyState === video.HAVE_ENOUGH_DATA) {
      canvas.width = video.videoWidth
      canvas.height = video.videoHeight
      const ctx = canvas.getContext('2d')
      ctx.drawImage(video, 0, 0, canvas.width, canvas.height)
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height)
      const code = jsQR(imageData.data, imageData.width, imageData.height)
      if (code && code.data) {
        handleDecoded(code.data)
        return // stop the scan loop once we've found something
      }
    }
    rafRef.current = requestAnimationFrame(tick)
  }, [])

  const handleDecoded = async (data) => {
    setLastDecoded(data)
    stopCamera()
    setAnalyzing(true)
    try {
      const res = await analyzeUrl(data, 'webcam')
      setResult(res)
    } catch (err) {
      setError(err?.response?.data?.error || 'Could not reach the analysis backend. Is Flask running on port 5000?')
    } finally {
      setAnalyzing(false)
    }
  }

  useEffect(() => stopCamera, [stopCamera])

  return (
    <div className="page-container">
      <span className="eyebrow">Live scan</span>
      <h1 style={{ marginTop: 10, fontSize: '1.9rem' }}>Scan a QR code with your webcam</h1>
      <p style={{ marginTop: 8, maxWidth: 560 }}>
        Grant camera access and hold a QR code steady in frame. Detection happens
        automatically — no capture button needed.
      </p>

      <div className="scan-frame" style={{ marginTop: 28, aspectRatio: '16/10', maxWidth: 640, position: 'relative' }}>
        {cameraOn && <div className="scan-line" />}
        <video
          ref={videoRef}
          muted
          playsInline
          style={{ width: '100%', height: '100%', objectFit: 'cover', display: cameraOn ? 'block' : 'none', borderRadius: 'var(--radius-lg)' }}
        />
        {!cameraOn && (
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', gap: 14 }}>
            <Camera size={36} color="var(--text-faint)" />
            <p>Camera is off</p>
          </div>
        )}
      </div>

      <div style={{ marginTop: 20, display: 'flex', gap: 12 }}>
        {!cameraOn ? (
          <button className="btn btn-primary" onClick={startCamera}>
            <Camera size={17} /> Start camera
          </button>
        ) : (
          <button className="btn btn-ghost" onClick={stopCamera}>
            <CameraOff size={17} /> Stop camera
          </button>
        )}
      </div>

      {cameraError && (
        <p style={{ marginTop: 16, color: 'var(--danger)', maxWidth: 560 }}>{cameraError}</p>
      )}

      {analyzing && (
        <div className="panel" style={{ marginTop: 28, display: 'flex', alignItems: 'center', gap: 12 }}>
          <Loader2 size={18} className="spin" style={{ animation: 'spin 1s linear infinite' }} />
          <span>Decoded: <span className="mono">{lastDecoded}</span> — analyzing...</span>
        </div>
      )}

      {error && (
        <div className="panel" style={{ marginTop: 28, borderColor: 'var(--danger)' }}>
          <p style={{ color: 'var(--danger)' }}>{error}</p>
        </div>
      )}

      {result && !analyzing && (
        <div style={{ marginTop: 28 }}>
          <ResultCard result={result} />
          <button className="btn btn-ghost" style={{ marginTop: 16 }} onClick={startCamera}>
            Scan another code
          </button>
        </div>
      )}

      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  )
}
