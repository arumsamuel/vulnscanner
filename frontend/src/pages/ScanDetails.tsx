import { useEffect, useState, useRef } from 'react'
import { useParams, Link } from 'react-router-dom'
import {
  Shield, AlertTriangle, Bug, CheckCircle, XCircle, Loader2,
  Download, ArrowLeft, Clock, Target, FileJson
} from 'lucide-react'
import { getScanResult, connectWebSocket, exportJson } from '@/lib/api'
import { formatDate, downloadBlob } from '@/lib/utils'
import { SEVERITY_ORDER, SEVERITY_COLORS, type ScanResult, type ScanProgress, type Severity } from '@/types'

function SeverityBadge({ severity }: { severity: Severity }) {
  const styles: Record<Severity, string> = {
    critical: 'bg-danger/10 text-danger border-danger/30',
    high: 'bg-warning/10 text-warning border-warning/30',
    medium: 'bg-copper-500/10 text-copper-400 border-copper-500/30',
    low: 'bg-info/10 text-info border-info/30',
    info: 'bg-slate-500/10 text-slate-400 border-slate-500/30',
  }
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold border ${styles[severity]}`}>
      {severity.toUpperCase()}
    </span>
  )
}

function ProgressBar({ percent, status }: { percent: number; status: string }) {
  return (
    <div className="w-full h-2 bg-navy-700 rounded-full overflow-hidden">
      <div
        className={`h-full transition-all duration-500 rounded-full ${
          status === 'failed' ? 'bg-danger' : status === 'completed' ? 'bg-success' : 'bg-copper-500'
        }`}
        style={{ width: `${percent}%` }}
      />
    </div>
  )
}

export default function ScanDetails() {
  const { scanId } = useParams<{ scanId: string }>()
  const [result, setResult] = useState<ScanResult | null>(null)
  const [progress, setProgress] = useState<ScanProgress | null>(null)
  const [filter, setFilter] = useState<Severity | 'all'>('all')
  const [loading, setLoading] = useState(true)
  const wsRef = useRef<WebSocket | null>(null)

  useEffect(() => {
    if (!scanId) return

    getScanResult(scanId).then((data) => {
      setResult(data)
      setLoading(false)
    }).catch(() => setLoading(false))

    const ws = connectWebSocket(scanId, (p) => {
      setProgress(p)
      if (p.status === 'completed' || p.status === 'failed') {
        getScanResult(scanId).then(setResult)
      }
    })
    wsRef.current = ws

    return () => {
      ws.close()
    }
  }, [scanId])

  const handleExport = async () => {
    if (!scanId) return
    const blob = await exportJson(scanId)
    downloadBlob(blob, `aegisscan-report-${scanId}.json`)
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 text-copper-400 animate-spin" />
      </div>
    )
  }

  if (!result) {
    return (
      <div className="text-center py-16">
        <XCircle className="h-12 w-12 text-danger mx-auto mb-4" />
        <h2 className="text-xl font-bold text-slate-100 mb-2">Scan Not Found</h2>
        <Link to="/history" className="text-copper-400 hover:underline">View history</Link>
      </div>
    )
  }

  const isRunning = result.status === 'running' || result.status === 'pending'
  const vulns = result.vulnerabilities || []
  const filtered = filter === 'all' ? vulns : vulns.filter(v => v.severity === filter)

  const severityCounts = SEVERITY_ORDER.reduce((acc, sev) => {
    acc[sev] = vulns.filter(v => v.severity === sev).length
    return acc
  }, {} as Record<Severity, number>)

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <Link to="/history" className="p-2 rounded-lg hover:bg-navy-800 transition-colors text-slate-400">
            <ArrowLeft className="h-5 w-5" />
          </Link>
          <div>
            <h2 className="text-xl font-bold text-slate-100">Scan Results</h2>
            <div className="flex items-center gap-2 text-sm text-slate-500">
              <Target className="h-3.5 w-3.5" />
              {result.target}
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {result.status === 'completed' && (
            <button onClick={handleExport} className="btn-secondary flex items-center gap-2 text-sm">
              <FileJson className="h-4 w-4" />
              Export JSON
            </button>
          )}
        </div>
      </div>

      {/* Status Card */}
      <div className="glass-panel p-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            {isRunning ? (
              <Loader2 className="h-6 w-6 text-copper-400 animate-spin" />
            ) : result.status === 'completed' ? (
              <CheckCircle className="h-6 w-6 text-success" />
            ) : (
              <XCircle className="h-6 w-6 text-danger" />
            )}
            <div>
              <p className="font-semibold text-slate-100 capitalize">{result.status}</p>
              <p className="text-xs text-slate-500">
                Started {formatDate(result.started_at)}
              </p>
            </div>
          </div>
          {progress && (
            <span className="text-sm font-mono text-copper-400">{progress.progress_percent}%</span>
          )}
        </div>

        {(isRunning && progress) ? (
          <>
            <ProgressBar percent={progress.progress_percent} status={result.status} />
            <p className="mt-2 text-sm text-slate-400">{progress.message}</p>
            {progress.current_module && (
              <p className="text-xs text-slate-500 mt-1">Module: {progress.current_module}</p>
            )}
          </>
        ) : (
          <ProgressBar percent={100} status={result.status} />
        )}
      </div>

      {/* Stats */}
      {vulns.length > 0 && (
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
          {SEVERITY_ORDER.map((sev) => (
            <button
              key={sev}
              onClick={() => setFilter(filter === sev ? 'all' : sev)}
              className={`glass-panel p-3 text-center transition-all ${
                filter === sev ? 'ring-1 ring-copper-500/50' : ''
              }`}
            >
              <p className="text-2xl font-bold" style={{ color: SEVERITY_COLORS[sev] }}>
                {severityCounts[sev]}
              </p>
              <p className="text-xs text-slate-500 capitalize">{sev}</p>
            </button>
          ))}
        </div>
      )}

      {/* Vulnerabilities */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="font-semibold text-slate-100 flex items-center gap-2">
            <Bug className="h-4 w-4 text-copper-400" />
            Findings
            <span className="text-sm text-slate-500 font-normal">({filtered.length})</span>
          </h3>
          {filter !== 'all' && (
            <button
              onClick={() => setFilter('all')}
              className="text-xs text-copper-400 hover:text-copper-300"
            >
              Clear filter
            </button>
          )}
        </div>

        {filtered.length === 0 ? (
          <div className="glass-panel p-12 text-center">
            <Shield className="h-10 w-10 text-success/50 mx-auto mb-3" />
            <p className="text-slate-400">
              {vulns.length === 0
                ? "No vulnerabilities detected in this scan."
                : "No vulnerabilities match the selected filter."}
            </p>
          </div>
        ) : (
          filtered.map((vuln) => (
            <div
              key={vuln.id}
              className="glass-panel p-5 space-y-3 hover:border-navy-600/50 transition-colors"
            >
              <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
                <div className="flex items-start gap-3">
                  <AlertTriangle
                    className="h-5 w-5 shrink-0 mt-0.5"
                    style={{ color: SEVERITY_COLORS[vuln.severity] }}
                  />
                  <div>
                    <h4 className="font-semibold text-slate-100">{vuln.name}</h4>
                    <div className="flex flex-wrap items-center gap-2 mt-1">
                      <SeverityBadge severity={vuln.severity} />
                      <span className="text-xs text-slate-500">{vuln.category}</span>
                      {vuln.cvss_score !== undefined && (
                        <span className="text-xs font-mono text-slate-500">
                          CVSS: {vuln.cvss_score}
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              </div>

              <p className="text-sm text-slate-400 leading-relaxed">{vuln.description}</p>

              {vuln.evidence && (
                <div className="bg-navy-950/50 rounded-lg p-3 border border-navy-700/30">
                  <p className="text-xs text-slate-500 mb-1">Evidence</p>
                  <code className="text-xs font-mono text-copper-400 break-all">{vuln.evidence}</code>
                </div>
              )}

              {vuln.url && (
                <p className="text-xs text-slate-500">
                  URL: <span className="text-slate-400">{vuln.url}</span>
                </p>
              )}

              <div className="bg-success/5 rounded-lg p-3 border border-success/10">
                <p className="text-xs text-success font-medium mb-1">Remediation</p>
                <p className="text-sm text-slate-400">{vuln.remediation}</p>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  )
}