'use client'

import Link from 'next/link'
import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { ArrowRight, BarChart3, FileText, Gauge, History, ScanLine, ShieldAlert } from 'lucide-react'

type ScanType = 'url_scan' | 'website_reputation' | 'domain_age' | 'ssl_certificate' | 'malicious_url_database' | 'url_pattern_analysis' | 'visual_comparison' | 'ocr'
type HistoryItem = { id: string; scanType: ScanType; scanDate: string; target: string | null; riskCategory: string; confidenceLevel: string; finalReport: string }
type DashboardData = {
  totals: { totalScans: number; visualComparisons: number; suspiciousDetected: number; highRisk: number }
  riskCounts: Record<string, number>
  dailyCounts: Record<string, number>
  recent: HistoryItem[]
}
const typeLabels: Record<ScanType, string> = { url_scan: 'URL Scan', website_reputation: 'Website Reputation', domain_age: 'Domain Age', ssl_certificate: 'SSL Certificate', malicious_url_database: 'Malicious URL Database', url_pattern_analysis: 'URL Pattern Analysis', visual_comparison: 'Visual Comparison', ocr: 'OCR' }
const riskLabels = ['Low', 'Medium', 'High', 'Inconclusive']

export default function DashboardPage() {
  const [data, setData] = useState<DashboardData | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    fetch('/api/dashboard')
      .then(async (response) => {
        const payload = await response.json()
        if (!response.ok) throw new Error(payload.error)
        setData(payload)
      })
      .catch((dashboardError) => setError(dashboardError instanceof Error ? dashboardError.message : 'Unable to load dashboard data.'))
      .finally(() => setLoading(false))
  }, [])

  const maxDailyCount = useMemo(() => Math.max(1, ...Object.values(data?.dailyCounts ?? {})), [data])

  return (
    <main className="min-h-screen bg-[#eef2f5] text-slate-950">
      <header className="mx-auto flex max-w-5xl items-center justify-between px-6 py-7">
        <Link href="/" className="flex items-center gap-2.5"><img src="https://hebbkx1anhila5yf.public.blob.vercel-storage.com/image-TMC6J8OtTrw06fQx00D797ADPNMbbv.png" alt="FindFake AI logo" className="h-10 w-10 rounded-lg object-cover" /><span className="text-lg font-semibold tracking-tight">FindFake<span className="text-slate-400"> AI</span></span></Link>
        <nav className="flex items-center gap-2 text-sm font-medium"><Link href="/" className="rounded-full px-3 py-1.5 text-slate-500 hover:bg-slate-100">Scan</Link><Link href="/dashboard" className="rounded-full bg-slate-950 px-3 py-1.5 text-white">Dashboard</Link></nav>
      </header>

      <section className="mx-auto max-w-5xl px-6 pb-16 pt-10 sm:pt-16">
        <div className="flex flex-col justify-between gap-5 sm:flex-row sm:items-end"><div><p className="text-sm font-semibold uppercase tracking-[0.18em] text-slate-400">FindFake AI</p><h1 className="mt-3 text-4xl font-semibold tracking-[-0.04em] sm:text-5xl">Security dashboard</h1><p className="mt-4 max-w-xl text-base leading-7 text-slate-500">A clear view of your saved scans, risk trends, and recent reports.</p></div><div className="flex gap-2"><QuickAction href="/" icon={<ScanLine size={16} />} label="Scan a URL" /><QuickAction href="/#comparison-heading" icon={<BarChart3 size={16} />} label="Compare screenshots" /></div></div>

        {error && <div role="alert" className="mt-8 rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">{error}</div>}
        {loading ? <p className="mt-10 text-sm text-slate-500">Loading dashboard data…</p> : data && <>
          <div className="mt-10 grid gap-3 sm:grid-cols-2 lg:grid-cols-4"><StatCard label="Total URL scans" value={data.totals.totalScans} icon={<ScanLine size={18} />} /><StatCard label="Visual comparisons" value={data.totals.visualComparisons} icon={<BarChart3 size={18} />} /><StatCard label="Suspicious detected" value={data.totals.suspiciousDetected} icon={<ShieldAlert size={18} />} /><StatCard label="High-risk reports" value={data.totals.highRisk} icon={<Gauge size={18} />} /></div>

          <div className="mt-10 grid gap-6 lg:grid-cols-[1.2fr_0.8fr]">
            <section className="rounded-2xl border border-slate-200 bg-white p-6" aria-labelledby="recent-heading"><div className="flex items-center justify-between"><div><p className="text-xs font-semibold uppercase tracking-widest text-slate-400">Recent activity</p><h2 id="recent-heading" className="mt-1 text-xl font-semibold tracking-tight">Latest reports</h2></div><Link href="/#history-heading" className="flex items-center gap-1 text-xs font-semibold text-slate-600 hover:text-slate-950">View history <ArrowRight size={14} /></Link></div>{data.recent.length === 0 ? <EmptyState /> : <div className="mt-5 divide-y divide-slate-100">{data.recent.map((record) => <RecentRecord key={record.id} record={record} />)}</div>}</section>
            <div className="space-y-6"><section className="rounded-2xl border border-slate-200 bg-white p-6" aria-labelledby="stats-heading"><div className="flex items-center gap-2"><BarChart3 size={18} className="text-slate-500" /><h2 id="stats-heading" className="text-lg font-semibold">Scan statistics</h2></div><div className="mt-6 space-y-4">{riskLabels.map((risk) => <div key={risk}><div className="mb-1 flex justify-between text-xs font-medium text-slate-500"><span>{risk}</span><span>{data.riskCounts[risk] ?? 0}</span></div><div className="h-2 overflow-hidden rounded-full bg-slate-100"><div className={`h-full rounded-full ${risk === 'High' ? 'bg-red-400' : risk === 'Medium' ? 'bg-amber-400' : risk === 'Low' ? 'bg-emerald-400' : 'bg-slate-400'}`} style={{ width: `${((data.riskCounts[risk] ?? 0) / Math.max(1, data.totals.totalScans)) * 100}%` }} /></div></div>)}</div></section><section className="rounded-2xl border border-slate-200 bg-slate-50 p-6"><p className="text-xs font-semibold uppercase tracking-widest text-slate-400">Quick actions</p><div className="mt-4 space-y-2"><QuickLink href="/" label="Scan a URL" /><QuickLink href="/#comparison-heading" label="Compare website screenshots" /><QuickLink href="/#history-heading" label="View scan history" /></div></section></div>
          </div>

          <section className="mt-6 rounded-2xl border border-slate-200 bg-white p-6" aria-labelledby="over-time-heading"><div className="flex items-center gap-2"><History size={18} className="text-slate-500" /><h2 id="over-time-heading" className="text-lg font-semibold">Total scans over time</h2></div>{Object.keys(data.dailyCounts).length === 0 ? <p className="mt-5 text-sm text-slate-500">Your scan activity will appear here after the first report.</p> : <div className="mt-6 flex h-32 items-end gap-2 overflow-x-auto">{Object.entries(data.dailyCounts).sort(([a], [b]) => a.localeCompare(b)).slice(-14).map(([day, count]) => <div key={day} className="flex min-w-8 flex-1 flex-col items-center justify-end gap-2"><span className="text-xs font-medium text-slate-500">{count}</span><div className="w-full rounded-t-md bg-slate-900" style={{ height: `${Math.max(8, (count / maxDailyCount) * 88)}px` }} /><span className="text-[10px] text-slate-400">{day.slice(5)}</span></div>)}</div>}</section>
        </>}
      </section>
    </main>
  )
}

function StatCard({ label, value, icon }: { label: string; value: number; icon: ReactNode }) { return <div className="rounded-2xl border border-slate-200 bg-white p-5"><div className="flex items-center justify-between text-slate-400"><span className="text-xs font-semibold uppercase tracking-wide">{label}</span>{icon}</div><p className="mt-4 text-3xl font-semibold tracking-tight">{value}</p></div> }
function QuickAction({ href, icon, label }: { href: string; icon: ReactNode; label: string }) { return <Link href={href} className="flex items-center gap-2 rounded-xl bg-slate-950 px-3 py-2.5 text-xs font-semibold text-white hover:bg-slate-800">{icon}{label}</Link> }
function QuickLink({ href, label }: { href: string; label: string }) { return <Link href={href} className="flex items-center justify-between rounded-xl border border-slate-200 bg-white px-4 py-3 text-sm font-medium text-slate-700 hover:border-slate-400">{label}<ArrowRight size={15} className="text-slate-400" /></Link> }
function RecentRecord({ record }: { record: HistoryItem }) { return <Link href={`/#history-heading?report=${record.id}`} className="block py-4 first:pt-0 last:pb-0"><div className="flex items-start justify-between gap-4"><div className="min-w-0"><p className="text-sm font-semibold text-slate-800">{typeLabels[record.scanType]}</p><p className="mt-1 truncate text-xs text-slate-500">{record.target || 'Saved report'}</p><p className="mt-1 text-xs text-slate-400">{new Date(record.scanDate).toLocaleString()} · {record.riskCategory}</p></div><span className="shrink-0 rounded-full bg-slate-100 px-2.5 py-1 text-xs font-medium text-slate-600">{record.confidenceLevel}</span></div></Link> }
function EmptyState() { return <div className="mt-6 rounded-xl border border-dashed border-slate-200 p-6 text-center"><FileText className="mx-auto text-slate-300" size={22} /><p className="mt-3 text-sm font-medium text-slate-700">No scans yet</p><p className="mt-1 text-xs leading-5 text-slate-500">Run a URL scan or screenshot comparison to start your dashboard.</p><Link href="/" className="mt-4 inline-flex items-center gap-1 text-xs font-semibold text-slate-700 hover:text-slate-950">Start a scan <ArrowRight size={14} /></Link></div> }
