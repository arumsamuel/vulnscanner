import { Link, useLocation } from 'react-router-dom'
import { Shield, LayoutDashboard, PlusCircle, History, Github } from 'lucide-react'
import { cn } from '@/lib/utils'

const navItems = [
  { href: '/', label: 'Dashboard', icon: LayoutDashboard },
  { href: '/scan', label: 'New Scan', icon: PlusCircle },
  { href: '/history', label: 'History', icon: History },
]

export default function Layout({ children }: { children: React.ReactNode }) {
  const location = useLocation()

  return (
    <div className="min-h-screen flex flex-col">
      {/* Top Navigation */}
      <header className="sticky top-0 z-50 border-b border-navy-700/50 bg-navy-900/80 backdrop-blur-xl">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="flex h-16 items-center justify-between">
            <Link to="/" className="flex items-center gap-3 group">
              <div className="relative flex h-9 w-9 items-center justify-center rounded-lg bg-copper-500/10 border border-copper-500/20 group-hover:border-copper-500/40 transition-colors">
                <Shield className="h-5 w-5 text-copper-400" />
                <div className="absolute inset-0 rounded-lg bg-copper-400/10 blur-md opacity-0 group-hover:opacity-100 transition-opacity" />
              </div>
              <div>
                <h1 className="text-lg font-bold tracking-tight text-slate-100">AegisScan</h1>
                <p className="text-[10px] uppercase tracking-widest text-slate-500 font-medium">Vulnerability Scanner</p>
              </div>
            </Link>

            <nav className="hidden md:flex items-center gap-1">
              {navItems.map((item) => (
                <Link
                  key={item.href}
                  to={item.href}
                  className={cn(
                    "flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all",
                    location.pathname === item.href
                      ? "bg-copper-500/10 text-copper-400 border border-copper-500/20"
                      : "text-slate-400 hover:text-slate-200 hover:bg-navy-800"
                  )}
                >
                  <item.icon className="h-4 w-4" />
                  {item.label}
                </Link>
              ))}
            </nav>

            <a
              href="https://github.com"
              target="_blank"
              rel="noopener noreferrer"
              className="text-slate-500 hover:text-slate-300 transition-colors"
            >
              <Github className="h-5 w-5" />
            </a>
          </div>
        </div>
      </header>

      {/* Mobile nav */}
      <nav className="md:hidden border-b border-navy-700/50 bg-navy-900/80 backdrop-blur-xl">
        <div className="flex overflow-x-auto px-4 py-2 gap-2">
          {navItems.map((item) => (
            <Link
              key={item.href}
              to={item.href}
              className={cn(
                "flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap transition-all",
                location.pathname === item.href
                  ? "bg-copper-500/10 text-copper-400 border border-copper-500/20"
                  : "text-slate-400 hover:text-slate-200 hover:bg-navy-800"
              )}
            >
              <item.icon className="h-3.5 w-3.5" />
              {item.label}
            </Link>
          ))}
        </div>
      </nav>

      {/* Main Content */}
      <main className="flex-1 mx-auto w-full max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
        {children}
      </main>

      {/* Footer */}
      <footer className="border-t border-navy-700/50 bg-navy-900/50">
        <div className="mx-auto max-w-7xl px-4 py-6 text-center text-xs text-slate-600">
          AegisScan v1.0 — Professional vulnerability assessment tool. Use responsibly on systems you own or have permission to test.
        </div>
      </footer>
    </div>
  )
}
