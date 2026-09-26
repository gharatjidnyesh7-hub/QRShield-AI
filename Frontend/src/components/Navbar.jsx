import React from 'react'
import { NavLink } from 'react-router-dom'
import { ShieldHalf, LockKeyhole } from 'lucide-react'

const LINKS = [
  { to: '/', label: 'Home', end: true },
  { to: '/scan', label: 'Scan QR' },
  { to: '/upload', label: 'Upload QR' },
  { to: '/paste', label: 'Paste URL' },
]

export default function Navbar() {
  return (
    <nav className="navbar">
      <div className="navbar-inner">

        {/* Logo */}
        <div className="brand">
          <ShieldHalf
            size={22}
            color="#1FE6B5"
            strokeWidth={2.2}
          />
          QRShield <span style={{ color: '#1FE6B5' }}>AI</span>
        </div>

        {/* Public navigation */}
        <div className="nav-links">

          {LINKS.map(link => (
            <NavLink
              key={link.to}
              to={link.to}
              end={link.end}
              className={({ isActive }) =>
                `nav-link${isActive ? ' active' : ''}`
              }
            >
              {link.label}
            </NavLink>
          ))}

          {/* Authority Login */}
          <NavLink
            to="/authority-login"
            className={({ isActive }) =>
              `nav-link authority-link${isActive ? ' active' : ''}`
            }
          >
            <LockKeyhole
              size={14}
              style={{
                marginRight: '5px',
                verticalAlign: '-2px'
              }}
            />
            Authority Login
          </NavLink>

        </div>
      </div>
    </nav>
  )
}