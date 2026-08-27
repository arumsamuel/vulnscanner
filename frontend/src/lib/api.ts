import { ScanConfig, ScanResult, ScanProgress } from '@/types'

const API_BASE = '/api'

export async function startScan(config: ScanConfig): Promise<ScanResult> {
  const res = await fetch(`${API_BASE}/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(config),
  })
  if (!res.ok) throw new Error(await res.text())
  return res.json()
}

export async function getScanResult(scanId: string): Promise<ScanResult> {
  const res = await fetch(`${API_BASE}/scan/${scanId}`)
  if (!res.ok) throw new Error('Scan not found')
  return res.json()
}

export async function getScanHistory(): Promise<ScanResult[]> {
  const res = await fetch(`${API_BASE}/scans`)
  if (!res.ok) throw new Error('Failed to fetch history')
  return res.json()
}

export async function deleteScan(scanId: string): Promise<void> {
  const res = await fetch(`${API_BASE}/scan/${scanId}`, { method: 'DELETE' })
  if (!res.ok) throw new Error('Failed to delete')
}

export async function exportJson(scanId: string): Promise<Blob> {
  const res = await fetch(`${API_BASE}/scan/${scanId}/export/json`)
  if (!res.ok) throw new Error('Export failed')
  return res.blob()
}

export function connectWebSocket(scanId: string, onMessage: (progress: ScanProgress) => void): WebSocket {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const ws = new WebSocket(`${protocol}//${window.location.host}/ws/scan/${scanId}`)

  ws.onopen = () => {
    const interval = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) ws.send('ping')
    }, 30000)
    ws.onclose = () => clearInterval(interval)
  }

  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data)
      onMessage(data as ScanProgress)
    } catch {
      // pong or non-JSON
    }
  }

  return ws
}
