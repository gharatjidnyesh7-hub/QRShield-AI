
import axios from 'axios'

export const API_BASE =
  import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000/api'

const client = axios.create({
  baseURL: API_BASE,
  timeout: 120000,
})

/** Analyze a manually-entered or already-decoded URL. */
export async function analyzeUrl(url, source = 'manual') {
  const res = await client.post('/analyze-url', { url, source })
  return res.data
}

/** Upload a QR image file for decoding + analysis. */
export async function scanQrImage(file) {
  const formData = new FormData()
  formData.append('file', file)
  const res = await client.post('/scan-qr', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  })
  return res.data
}

export async function fetchHistory(limit = 200) {
  const res = await client.get(`/history?limit=${limit}`)
  return res.data.history
}

export async function fetchDashboard() {
  const res = await client.get('/dashboard')
  return res.data
}

export async function checkHealth() {
  const res = await client.get('/health')
  return res.data
}

/** Explain why a URL was classified as safe or risky. */
export async function explainUrl(url) {
  const res = await client.post('/explain-url', { url })
  return res.data
}

/** Check URL security details. */
export async function analyzeSecurity(url) {
  const res = await client.post('/analyze-security', { url })
  return res.data
}

/** Analyze a suspicious SMS, email, or message. */
export async function analyzeMessage(message) {
  const res = await client.post('/analyze-message', { body: message })
  return res.data
}

/** Check availability of advanced backend features. */
export async function checkAdvancedStatus() {
  const res = await client.get('/advanced/status')
  return res.data
}

export default client

