export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'
export type ScanModule = 
  | 'headers' | 'ssl_tls' | 'sqli' | 'xss' | 'csrf' 
  | 'sensitive_files' | 'tech_detect' | 'port_scan' | 'subdomain'

export interface Vulnerability {
  id: string
  name: string
  severity: Severity
  category: string
  description: string
  evidence?: string
  remediation: string
  url?: string
  parameter?: string
  cvss_score?: number
}

export interface ScanConfig {
  target: string
  modules: ScanModule[]
  depth: number
  timeout: number
  max_concurrent: number
  follow_redirects: boolean
  user_agent: string
}

export interface ScanResult {
  scan_id: string
  target: string
  status: ScanStatus
  started_at: string
  completed_at?: string
  config: ScanConfig
  vulnerabilities: Vulnerability[]
  stats: Record<string, number>
  error_message?: string
}

export interface ScanProgress {
  scan_id: string
  status: ScanStatus
  current_module?: string
  progress_percent: number
  message: string
  vulnerabilities_found: number
  timestamp: string
}

export const ALL_MODULES: { value: ScanModule; label: string; description: string }[] = [
  { value: 'headers', label: 'Security Headers', description: 'HSTS, CSP, X-Frame-Options, cookies' },
  { value: 'ssl_tls', label: 'SSL/TLS', description: 'Certificate, protocol version, cipher suites' },
  { value: 'sqli', label: 'SQL Injection', description: 'Error-based and time-based detection' },
  { value: 'xss', label: 'Cross-Site Scripting', description: 'Reflected XSS payload testing' },
  { value: 'csrf', label: 'CSRF Protection', description: 'Token validation and SameSite checks' },
  { value: 'sensitive_files', label: 'Sensitive Files', description: 'Exposed backups, configs, admin panels' },
  { value: 'tech_detect', label: 'Tech Detection', description: 'Framework and server fingerprinting' },
  { value: 'port_scan', label: 'Port Scan', description: 'Top 20 common ports' },
  { value: 'subdomain', label: 'Subdomain Enum', description: 'Wordlist-based discovery' },
]

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']
export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#f59e0b',
  low: '#06b6d4',
  info: '#94a3b8',
}
