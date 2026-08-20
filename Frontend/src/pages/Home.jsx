import React from 'react'
import { Link } from 'react-router-dom'
import { Camera, Upload, Link2, ArrowRight } from 'lucide-react'
import ShieldRing from '../components/ShieldRing.jsx'

export default function Home() {
  return (
    <div className="page-container">
      <div className="scan-frame" style={{ padding: '56px 40px', marginBottom: 40 }}>
        <div className="scan-line" />
        <span className="eyebrow">ML-powered · Real-time · Local-first</span>
        <h1 style={{ fontSize: '2.6rem', marginTop: 14, maxWidth: 640, lineHeight: 1.15 }}>
          Know what a QR code really points to <span style={{ color: 'var(--shield)' }}>before you tap it.</span>
        </h1>
        <p style={{ marginTop: 16, maxWidth: 560, fontSize: '1.02rem' }}>
          QRShield AI decodes any QR code — from your webcam, an uploaded image, or a
          pasted link — and runs the destination URL through a trained machine learning
          model to flag phishing attempts before they reach you.
        </p>
        <div style={{ display: 'flex', gap: 12, marginTop: 30, flexWrap: 'wrap' }}>
          <Link to="/scan" className="btn btn-primary"><Camera size={17} /> Scan with webcam</Link>
          <Link to="/upload" className="btn btn-ghost"><Upload size={17} /> Upload an image</Link>
          <Link to="/paste" className="btn btn-ghost"><Link2 size={17} /> Paste a URL</Link>
        </div>
      </div>

      <div className="grid-3" style={{ marginBottom: 40 }}>
        <FeatureCard
          icon={<Camera size={20} color="var(--shield)" />}
          title="Live webcam scan"
          text="Point your camera at a QR code. Detection and decoding happen automatically, no button-mashing required."
        />
        <FeatureCard
          icon={<Upload size={20} color="var(--shield)" />}
          title="Image upload"
          text="Already have a screenshot? Upload a PNG or JPG and we'll decode it the same way."
        />
        <FeatureCard
          icon={<Link2 size={20} color="var(--shield)" />}
          title="Direct URL check"
          text="Skip the QR entirely and paste a link straight in for instant analysis."
        />
      </div>

      <div className="panel" style={{ display: 'flex', alignItems: 'center', gap: 28, flexWrap: 'wrap' }}>
        <ShieldRing score={92} size={110} label="EXAMPLE RISK" />
        <div style={{ flex: 1, minWidth: 240 }}>
          <span className="eyebrow">How scoring works</span>
          <h3 style={{ marginTop: 10, fontSize: '1.2rem' }}>13 URL features, one Random Forest model</h3>
          <p style={{ marginTop: 8 }}>
            Every URL is reduced to structural signals — HTTPS use, domain length, IP
            addressing, suspicious keywords, subdomain count, and more — and scored by a
            model trained and cross-validated on a labeled phishing-URL dataset. The
            result is a 0–100 risk score and a SAFE / SUSPICIOUS / PHISHING verdict, not
            a claim that every phishing site will be caught.
          </p>
          <Link to="/about" style={{ display: 'inline-flex', alignItems: 'center', gap: 6, marginTop: 14, fontWeight: 600, fontSize: '0.9rem' }}>
            Read the methodology <ArrowRight size={15} />
          </Link>
        </div>
      </div>
    </div>
  )
}

function FeatureCard({ icon, title, text }) {
  return (
    <div className="panel panel-tight">
      <div style={{ marginBottom: 12 }}>{icon}</div>
      <h4 style={{ fontSize: '1.02rem', marginBottom: 8 }}>{title}</h4>
      <p style={{ fontSize: '0.88rem' }}>{text}</p>
    </div>
  )
}
