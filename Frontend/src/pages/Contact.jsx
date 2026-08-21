import React, { useState } from 'react'
import { Mail, Github } from 'lucide-react'

export default function Contact() {
  const [sent, setSent] = useState(false)

  const handleSubmit = (e) => {
    e.preventDefault()
    // Academic-demo form: stores nothing server-side by default.
    // Wire this up to a real endpoint (e.g. /api/contact) if needed for your viva.
    setSent(true)
  }

  return (
    <div className="page-container" style={{ maxWidth: 560 }}>
      <span className="eyebrow">Get in touch</span>
      <h1 style={{ marginTop: 10, fontSize: '1.9rem' }}>Contact</h1>
      <p style={{ marginTop: 8 }}>Questions about the project, the dataset, or the model? Reach out.</p>

      <div style={{ display: 'flex', gap: 20, marginTop: 20, color: 'var(--text-muted)', fontSize: '0.88rem' }}>
        <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><Mail size={15} /> project@qrshield.example</span>
        <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><Github size={15} /> github.com/your-username/qrshield-ai</span>
      </div>

      {sent ? (
        <div className="panel" style={{ marginTop: 28 }}>
          <p style={{ color: 'var(--shield)' }}>Message noted. (This demo form doesn't send anywhere yet — hook it up to a backend endpoint if your viva needs it live.)</p>
        </div>
      ) : (
        <form onSubmit={handleSubmit} style={{ marginTop: 28, display: 'flex', flexDirection: 'column', gap: 14 }}>
          <input className="input" placeholder="Your name" required />
          <input className="input" type="email" placeholder="Your email" required />
          <textarea className="input" rows={5} placeholder="Your message" required />
          <button className="btn btn-primary" type="submit" style={{ alignSelf: 'flex-start' }}>Send message</button>
        </form>
      )}
    </div>
  )
}
