import axios from 'axios'

// Change this if your Flask backend runs on a different host/port.
export const API_BASE = 'http://localhost:5000/api'

const client = axios.create({
  baseURL: API_BASE,
  timeout: 15000,
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

export default client
