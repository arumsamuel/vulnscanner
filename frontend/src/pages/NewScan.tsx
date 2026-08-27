import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Target, Settings, Check, Loader2, Shield } from 'lucide-react'
import { startScan } from '@/lib/api'
import { ALL_MODULES, type ScanModule } from '@/types'
import { cn } from '@/lib/utils'

export default function NewScan() {
  const navigate = useNavigate()
  const [target, setTarget] = useState('')
  const [selectedModules, setSelectedModules] = useState<ScanModule[]>(ALL_MODULES.map(m => m.value))
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const toggleModule = (mod: ScanModule) => {
    setSelectedModules(prev =>
      prev.includes(mod) ? prev.filter(m => m !== mod) : [...prev, mod]
    )
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!target.trim()) return
    if (selectedModules.length === 0) {
      setError('Select at least one module')
      return
    }

    setLoading(true)
    setError('')
    try {
      let url = target.trim()
      if (!url.startsWith('http')) url = 'https://' + url

      const result = await startScan({
        target: url,
        modules: selectedModules,
        depth: 1,
        timeout: 10,
        max_concurrent: 20,
        follow_redirects: true,
        user_agent: 'AegisScan/1.0 Security Scanner',
      })
      navigate(`/scan/${result.scan_id}`)
    } catch (err: any) {
      setError(err.message || 'Failed to start scan')
      setLoading(false)
    }
  }

  return (
    <div className="max-w-2xl mx-auto space-y-8">
      <div>
        <h2 className="text-2xl font-bold text-slate-100 mb-1">New Scan</h2>
        <p className="text-slate-400 text-sm">Configure your target and select modules to run.</p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Target Input */}
        <div className="glass-panel p-6 space-y-4">
          <div className="flex items-center gap-2 text-copper-400 mb-2">
            <Target className="h-4 w-4" />
            <h3 className="text-sm font-semibold uppercase tracking-wider">Target</h3>
          </div>
          <div>
            <label className="block text-sm text-slate-400 mb-2">Target URL</label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="https://example.com"
              className="input-field"
              required
            />
            <p className="mt-1.5 text-xs text-slate-500">Enter the full URL including protocol (https://)</p>
          </div>
        </div>

        {/* Module Selection */}
        <div className="glass-panel p-6 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-copper-400">
              <Settings className="h-4 w-4" />
              <h3 className="text-sm font-semibold uppercase tracking-wider">Modules</h3>
            </div>
            <button
              type="button"
              onClick={() => setSelectedModules(ALL_MODULES.map(m => m.value))}
              className="text-xs text-copper-400 hover:text-copper-300 transition-colors"
            >
              Select all
            </button>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {ALL_MODULES.map((mod) => {
              const isSelected = selectedModules.includes(mod.value)
              return (
                <button
                  key={mod.value}
                  type="button"
                  onClick={() => toggleModule(mod.value)}
                  className={cn(
                    "relative flex items-start gap-3 p-4 rounded-lg border text-left transition-all",
                    isSelected
                      ? "border-copper-500/40 bg-copper-500/5"
                      : "border-navy-700/50 bg-navy-800/30 hover:border-navy-600"
                  )}
                >
                  <div className={cn(
                    "mt-0.5 h-5 w-5 rounded border flex items-center justify-center transition-colors shrink-0",
                    isSelected ? "bg-copper-500 border-copper-500" : "border-navy-600"
                  )}>
                    {isSelected && <Check className="h-3.5 w-3.5 text-navy-950" />}
                  </div>
                  <div>
                    <p className="text-sm font-medium text-slate-200">{mod.label}</p>
                    <p className="text-xs text-slate-500 mt-0.5">{mod.description}</p>
                  </div>
                </button>
              )
            })}
          </div>
        </div>

        {error && (
          <div className="p-4 rounded-lg bg-danger/10 border border-danger/20 text-danger text-sm">
            {error}
          </div>
        )}

        <button
          type="submit"
          disabled={loading || !target.trim()}
          className="btn-primary w-full flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {loading ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" />
              Initializing Scan...
            </>
          ) : (
            <>
              <Shield className="h-4 w-4" />
              Start Scan
            </>
          )}
        </button>
      </form>
    </div>
  )
}
