import React from 'react'
import { NavLink } from 'react-router-dom'
import { ShieldHalf } from 'lucide-react'

const LINKS = [
  { to: '/', label: 'Home', end: true },
  { to: '/scan', label: 'Scan QR' },
  { to: '/upload', label: 'Upload QR' },
  { to: '/paste', label: 'Paste URL' },
  { to: '/dashboard', label: 'Dashboard' },
  { to: '/history', label: 'History' },
  { to: '/about', label: 'About' },
  { to: '/contact', label: 'Contact' },
]

export default function Navbar() {
  return (
    <nav className="navbar">
      <div className="navbar-inner">
        <div className="brand">
          <ShieldHalf size={22} color="#1FE6B5" strokeWidth={2.2} />
          QRShield <span style={{ color: '#1FE6B5' }}>AI</span>
        </div>
        <div className="nav-links">
          {LINKS.map(link => (
            <NavLink
              key={link.to}
              to={link.to}
              end={link.end}
              className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}
            >
              {link.label}
            </NavLink>
          ))}
        </div>
      </div>
    </nav>
  )
}
