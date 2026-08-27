import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Shield, Trash2, Clock, AlertTriangle, CheckCircle, XCircle, Zap } from 'lucide-react'
import { getScanHistory, deleteScan } from '@/lib/api'
import { formatDate } from '@/lib/utils'
import type { ScanResult } from '@/types'

export default function History() {
  const [scans, setScans] = useState<ScanResult[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    loadHistory()
  }, [])

  const loadHistory = () => {
    setLoading(true)
    getScanHistory().then(setScans).finally(() => setLoading(false))
  }

  const handleDelete = async (scanId: string) => {
    if (!confirm('Delete this scan permanently?')) return
    await deleteScan(scanId)
    loadHistory()
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-slate-100 mb-1">Scan History</h2>
        <p className="text-slate-400 text-sm">All previous vulnerability assessments.</p>
      </div>

      <div className="glass-panel overflow-hidden">
        {loading ? (
          <div className="p-12 text-center text-slate-500">Loading scans...</div>
        ) : scans.length === 0 ? (
          <div className="p-12 text-center">
            <Shield className="h-10 w-10 text-slate-600 mx-auto mb-3" />
            <p className="text-slate-400 mb-4">No scan history found.</p>
            <Link to="/scan" className="btn-primary text-sm">Start First Scan</Link>
          </div>
        ) : (
          <div className="divide-y divide-navy-700/30">
            {scans.map((scan) => (
              <div
                key={scan.scan_id}
                className="flex items-center justify-between p-4 hover:bg-navy-800/30 transition-colors"
              >
                <Link
                  to={`/scan/${scan.scan_id}`}
                  className="flex items-center gap-4 flex-1 min-w-0"
                >
                  <div className={
                    scan.status === 'completed' ? 'text-success' :
                    scan.status === 'failed' ? 'text-danger' :
                    scan.status === 'running' ? 'text-copper-400' : 'text-slate-500'
                  }>
                    {scan.status === 'running' ? <Zap className="h-5 w-5 animate-pulse" /> :
                     scan.status === 'completed' ? <CheckCircle className="h-5 w-5" /> :
                     scan.status === 'failed' ? <XCircle className="h-5 w-5" /> :
                     <Clock className="h-5 w-5" />}
                  </div>

                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-medium text-slate-200 truncate">{scan.target}</p>
                    <div className="flex items-center gap-3 mt-0.5">
                      <span className="text-xs text-slate-500">{formatDate(scan.started_at)}</span>
                      {scan.vulnerabilities && scan.vulnerabilities.length > 0 && (
                        <span className="text-xs text-danger bg-danger/10 px-1.5 py-0.5 rounded">
                          {scan.vulnerabilities.length} issues
                        </span>
                      )}
                      <span className="text-xs text-slate-600 capitalize">{scan.status}</span>
                    </div>
                  </div>
                </Link>

                <button
                  onClick={() => handleDelete(scan.scan_id)}
                  className="p-2 text-slate-600 hover:text-danger transition-colors shrink-0 ml-4"
                  title="Delete scan"
                >
                  <Trash2 className="h-4 w-4" />
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}