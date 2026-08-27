import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Shield, AlertTriangle, Bug, CheckCircle, Zap, ArrowRight, Clock } from 'lucide-react'
import { getScanHistory } from '@/lib/api'
import { formatDate } from '@/lib/utils'
import type { ScanResult } from '@/types'

function StatCard({ icon: Icon, label, value, color }: { icon: any; label: string; value: number; color: string }) {
  return (
    <div className="glass-panel p-5">
      <div className="flex items-center gap-3 mb-3">
        <div className="p-2 rounded-lg" style={{ backgroundColor: color + '15' }}>
          <Icon className="h-5 w-5" style={{ color }} />
        </div>
        <span className="text-sm text-slate-400 font-medium">{label}</span>
      </div>
      <p className="text-2xl font-bold text-slate-100">{value}</p>
    </div>
  )
}

export default function Dashboard() {
  const [history, setHistory] = useState<ScanResult[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    getScanHistory().then(setHistory).finally(() => setLoading(false))
  }, [])

  const totalScans = history.length
  const completedScans = history.filter(s => s.status === 'completed').length
  const totalVulns = history.reduce((sum, s) => sum + (s.vulnerabilities?.length || 0), 0)
  const criticalVulns = history.reduce((sum, s) => sum + (s.stats?.critical || 0), 0)

  const recentScans = history.slice(0, 5)

  return (
    <div className="space-y-8">
      {/* Hero */}
      <div className="relative overflow-hidden rounded-2xl border border-navy-700/50 bg-navy-800/40 p-8">
        <div className="absolute top-0 right-0 h-64 w-64 bg-copper-500/5 rounded-full blur-3xl -translate-y-1/2 translate-x-1/2" />
        <div className="relative">
          <h2 className="text-3xl font-bold tracking-tight text-slate-100 mb-2">
            Welcome to <span className="text-copper-400">AegisScan</span>
          </h2>
          <p className="text-slate-400 max-w-xl mb-6">
            Professional-grade vulnerability scanner. Assess web applications for security flaws 
            including injection attacks, misconfigurations, and information disclosure.
          </p>
          <Link to="/scan" className="btn-primary inline-flex items-center gap-2">
            <Zap className="h-4 w-4" />
            Start New Scan
            <ArrowRight className="h-4 w-4" />
          </Link>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard icon={Shield} label="Total Scans" value={totalScans} color="#f59e0b" />
        <StatCard icon={CheckCircle} label="Completed" value={completedScans} color="#10b981" />
        <StatCard icon={Bug} label="Vulnerabilities" value={totalVulns} color="#ef4444" />
        <StatCard icon={AlertTriangle} label="Critical" value={criticalVulns} color="#f97316" />
      </div>

      {/* Recent Scans */}
      <div className="glass-panel">
        <div className="flex items-center justify-between p-5 border-b border-navy-700/50">
          <h3 className="font-semibold text-slate-100">Recent Scans</h3>
          <Link to="/history" className="text-sm text-copper-400 hover:text-copper-300 transition-colors">
            View all
          </Link>
        </div>
        <div className="divide-y divide-navy-700/30">
          {loading ? (
            <div className="p-8 text-center text-slate-500">Loading...</div>
          ) : recentScans.length === 0 ? (
            <div className="p-8 text-center text-slate-500">
              <Shield className="h-8 w-8 mx-auto mb-3 text-slate-600" />
              <p>No scans yet. Start your first assessment.</p>
            </div>
          ) : (
            recentScans.map((scan) => (
              <Link
                key={scan.scan_id}
                to={`/scan/${scan.scan_id}`}
                className="flex items-center justify-between p-4 hover:bg-navy-800/40 transition-colors"
              >
                <div className="flex items-center gap-4 min-w-0">
                  <div className={
                    scan.status === 'completed' ? 'text-success' :
                    scan.status === 'failed' ? 'text-danger' :
                    scan.status === 'running' ? 'text-copper-400' : 'text-slate-500'
                  }>
                    {scan.status === 'running' ? <Zap className="h-4 w-4 animate-pulse" /> :
                     scan.status === 'completed' ? <CheckCircle className="h-4 w-4" /> :
                     <AlertTriangle className="h-4 w-4" />}
                  </div>
                  <div className="min-w-0">
                    <p className="text-sm font-medium text-slate-200 truncate">{scan.target}</p>
                    <div className="flex items-center gap-2 text-xs text-slate-500">
                      <Clock className="h-3 w-3" />
                      {formatDate(scan.started_at)}
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-3 shrink-0">
                  {scan.vulnerabilities && scan.vulnerabilities.length > 0 && (
                    <span className="text-xs font-medium text-danger bg-danger/10 px-2 py-1 rounded">
                      {scan.vulnerabilities.length} issues
                    </span>
                  )}
                  <ArrowRight className="h-4 w-4 text-slate-600" />
                </div>
              </Link>
            ))
          )}
        </div>
      </div>
    </div>
  )
}
