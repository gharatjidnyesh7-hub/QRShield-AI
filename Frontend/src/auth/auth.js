const TOKEN_KEY = 'qrshield_authority_token'

// DEMO / FRONTEND-ONLY AUTHENTICATION
// Change these two values if you want different fixed credentials.
export const AUTHORITY_NAME = 'QRShield_Memeber'
export const AUTHORITY_USERNAME = 'authority'
export const AUTHORITY_PASSWORD = 'maverick77'

export function getAuthorityToken() {
  return localStorage.getItem(TOKEN_KEY)
}

export function isAuthorityLoggedIn() {
  return Boolean(getAuthorityToken())
}

export function saveAuthorityToken(token) {
  localStorage.setItem(TOKEN_KEY, token)
}

export function clearAuthorityToken() {
  localStorage.removeItem(TOKEN_KEY)
}

export function validateAuthorityCredentials(username, password) {
  return username === AUTHORITY_USERNAME && password === AUTHORITY_PASSWORD
}
