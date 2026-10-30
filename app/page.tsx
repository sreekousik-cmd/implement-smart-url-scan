'use client'

import { FormEvent, useState } from 'react'
import { AlertTriangle, Check, ChevronDown, CircleHelp, Search, ShieldCheck, X } from 'lucide-react'

type Status = 'passed' | 'warning' | 'failed' | 'unavailable'
type Indicator = { label: string; status: Status; explanation: string; evidence: string }
type Result = { normalizedUrl: string; risk: string; indicators: Indicator[]; note: string }

const statusMeta = {
  passed: { label: 'Passed', icon: Check, className: 'text-emerald-700 bg-emerald-50' },
  warning: { label: 'Warning', icon: AlertTriangle, className: 'text-amber-700 bg-amber-50' },
  failed: { label: 'Failed', icon: X, className: 'text-red-700 bg-red-50' },
  unavailable: { label: 'Unavailable', icon: CircleHelp, className: 'text-slate-600 bg-slate-100' },
}

export default function Page() {
  const [url, setUrl] = useState('')
  const [result, setResult] = useState<Result | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setLoading(true); setError(''); setResult(null)
    try {
      const response = await fetch('/api/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url }) })
      const data = await response.json()
      if (!response.ok) throw new Error(data.error)
      setResult(data)
    } catch (scanError) { setError(scanError instanceof Error ? scanError.message : 'Unable to scan this URL.') } finally { setLoading(false) }
  }

  return (
    <main className="min-h-screen bg-white text-slate-950">
      <header className="mx-auto flex max-w-5xl items-center justify-between px-6 py-7">
        <div className="flex items-center gap-2.5"><div className="flex h-8 w-8 items-center justify-center rounded-lg bg-slate-950 text-white"><ShieldCheck size={18} /></div><span className="text-lg font-semibold tracking-tight">FindFake<span className="text-slate-400"> AI</span></span></div>
        <span className="rounded-full border border-slate-200 px-3 py-1 text-xs font-medium text-slate-500">Smart URL Scan</span>
      </header>
      <section className="mx-auto max-w-3xl px-6 pb-16 pt-16 text-center sm:pt-24">
        <p className="mb-4 text-sm font-semibold uppercase tracking-[0.18em] text-slate-400">Check before you click</p>
        <h1 className="text-4xl font-semibold tracking-[-0.04em] sm:text-6xl">Is this website <span className="text-slate-400">real?</span></h1>
        <p className="mx-auto mt-5 max-w-xl text-base leading-7 text-slate-500">Scan a URL for common phishing patterns, suspicious domains, and deceptive link structures.</p>
        <form onSubmit={handleSubmit} className="mx-auto mt-10 flex max-w-2xl flex-col gap-3 sm:flex-row">
          <label className="sr-only" htmlFor="website-url">Website URL</label>
          <input id="website-url" value={url} onChange={(event) => setUrl(event.target.value)} placeholder="https://example.com" className="h-14 min-w-0 flex-1 rounded-xl border border-slate-200 bg-slate-50 px-5 text-sm outline-none transition focus:border-slate-500 focus:bg-white focus:ring-4 focus:ring-slate-100" />
          <button disabled={loading} className="flex h-14 items-center justify-center gap-2 rounded-xl bg-slate-950 px-7 text-sm font-semibold text-white transition hover:bg-slate-800 disabled:cursor-wait disabled:opacity-60"><Search size={17} />{loading ? 'Scanning…' : 'Scan URL'}</button>
        </form>
        {error && <p role="alert" className="mt-4 text-sm font-medium text-red-600">{error}</p>}
        {result && <Results result={result} />}
      </section>
    </main>
  )
}

function Results({ result }: { result: Result }) {
  const concernClass = result.risk === 'High concern' ? 'bg-red-50 text-red-700' : result.risk === 'Medium concern' ? 'bg-amber-50 text-amber-700' : result.risk === 'Inconclusive' ? 'bg-slate-100 text-slate-700' : 'bg-emerald-50 text-emerald-700'
  return <section aria-live="polite" className="mx-auto mt-12 max-w-2xl text-left">
    <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-[0_12px_40px_rgba(15,23,42,0.06)] sm:p-8">
      <div className="flex flex-col justify-between gap-4 border-b border-slate-100 pb-6 sm:flex-row sm:items-start"><div><p className="text-xs font-semibold uppercase tracking-widest text-slate-400">Scan summary</p><p className="mt-2 break-all text-sm text-slate-600">{result.normalizedUrl}</p></div><span className={`w-fit rounded-full px-3 py-1.5 text-sm font-semibold ${concernClass}`}>{result.risk}</span></div>
      <div className="divide-y divide-slate-100">{result.indicators.map((item) => { const meta = statusMeta[item.status]; const Icon = meta.icon; return <details key={item.label} className="group py-5 first:pb-4"><summary className="flex cursor-pointer list-none items-center gap-3"><span className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-full ${meta.className}`}><Icon size={15} strokeWidth={2.5} /></span><span className="flex-1 text-sm font-semibold text-slate-800">{item.label}</span><span className={`hidden rounded-full px-2.5 py-1 text-xs font-medium sm:inline ${meta.className}`}>{meta.label}</span><ChevronDown size={16} className="text-slate-400 transition group-open:rotate-180" /></summary><div className="ml-10 mt-3 space-y-1 text-sm leading-6 text-slate-500"><p>{item.explanation}</p><p className="text-xs text-slate-400"><span className="font-semibold">Evidence:</span> {item.evidence}</p></div></details> })}</div>
      <p className="mt-2 border-t border-slate-100 pt-5 text-xs leading-5 text-slate-400">{result.note}</p>
    </div>
  </section>
}
