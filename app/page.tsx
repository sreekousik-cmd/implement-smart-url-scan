'use client'

import Link from 'next/link'
import { FormEvent, useEffect, useState } from 'react'
import { AlertTriangle, Check, ChevronDown, CircleHelp, FileText, Search, Sparkles, Trash2, Upload, X } from 'lucide-react'

type Status = 'passed' | 'warning' | 'failed' | 'unavailable'
type Indicator = { label: string; status: Status; explanation: string; evidence: string }
type Result = { normalizedUrl: string; risk: string; riskScore: number; indicators: Indicator[]; note: string }
type Explanation = { available: boolean; explanation?: string; error?: string }
type HistoryType = 'url_scan' | 'website_reputation' | 'domain_age' | 'ssl_certificate' | 'malicious_url_database' | 'url_pattern_analysis' | 'visual_comparison' | 'ocr'
type HistoryRecord = { id: string; scanType: HistoryType; scanDate: string; target: string | null; riskCategory: string; confidenceLevel: string; finalReport: string; findings: Record<string, unknown> }
type OCRReport = { riskLevel: 'Likely legitimate' | 'Suspicious' | 'High risk' | 'Inconclusive'; confidence: string; identifiedBrand: string; identifiedDomain: string; limitations: string[]; suspiciousText: string[]; officialText: string[]; matchingText: string[]; changedText: { suspicious: string; official: string; reason: string }[]; missingText: { text: string; presentOn: 'suspicious' | 'official' }[]; highlights: string[]; note: string }

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
  const [explanation, setExplanation] = useState<Explanation | null>(null)
  const [explanationLoading, setExplanationLoading] = useState(false)
  const [history, setHistory] = useState<HistoryRecord[]>([])
  const [historyFilter, setHistoryFilter] = useState<'all' | HistoryType>('all')
  const [historyFrom, setHistoryFrom] = useState('')
  const [historyTo, setHistoryTo] = useState('')
  const [historyLoading, setHistoryLoading] = useState(true)
  const [historyError, setHistoryError] = useState('')
  const [openHistoryId, setOpenHistoryId] = useState<string | null>(null)
  const [comparisonFile, setComparisonFile] = useState<File | null>(null)
  const [comparison, setComparison] = useState<OCRReport | null>(null)
  const [comparisonLoading, setComparisonLoading] = useState(false)
  const [comparisonError, setComparisonError] = useState('')

  async function loadHistory(filter = historyFilter, from = historyFrom, to = historyTo) {
    setHistoryLoading(true)
    try {
      const params = new URLSearchParams()
      if (filter !== 'all') params.set('type', filter)
      if (from) params.set('from', from)
      if (to) params.set('to', to)
      const query = params.toString() ? `?${params.toString()}` : ''
      const response = await fetch(`/api/history${query}`)
      const data = await response.json()
      if (!response.ok) throw new Error(data.error)
      setHistory(data.records)
      setHistoryError('')
    } catch {
      setHistoryError('Scan history is temporarily unavailable.')
    } finally {
      setHistoryLoading(false)
    }
  }

  useEffect(() => { void loadHistory() }, [historyFilter, historyFrom, historyTo])

  async function saveScanHistory(record: { scanType: HistoryType; requestId?: string; target?: string; riskCategory: string; confidenceLevel: string; finalReport: string; findings: Record<string, unknown> }) {
    try {
      const response = await fetch('/api/history', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(record) })
      const data = await response.json().catch(() => null)
      if (!response.ok) throw new Error(data?.error || 'History save failed')
      await loadHistory()
      return true
    } catch (error) {
      console.error('[v0] History save failed', error)
      setHistoryError(error instanceof Error ? error.message : 'The scan finished, but it could not be saved to history.')
      return false
    }
  }

  async function compressScreenshot(file: File) {
    if (file.size <= 4.5 * 1024 * 1024) return file
    const sourceUrl = URL.createObjectURL(file)
    try {
      const image = new Image()
      image.crossOrigin = 'anonymous'
      image.src = sourceUrl
      await new Promise<void>((resolve, reject) => { image.onload = () => resolve(); image.onerror = () => reject(new Error('Unable to read screenshot for OCR.')) })
      const scale = Math.min(1, 2400 / Math.max(image.naturalWidth, image.naturalHeight))
      const canvas = document.createElement('canvas')
      canvas.width = Math.max(1, Math.round(image.naturalWidth * scale))
      canvas.height = Math.max(1, Math.round(image.naturalHeight * scale))
      const context = canvas.getContext('2d')
      if (!context) return file
      context.drawImage(image, 0, 0, canvas.width, canvas.height)
      const outputType = file.type === 'image/webp' ? 'image/webp' : 'image/jpeg'
      const blob = await new Promise<Blob | null>((resolve) => canvas.toBlob(resolve, outputType, 0.88))
      return blob ? new File([blob], `${file.name.replace(/\.[^.]+$/, '')}.${outputType === 'image/webp' ? 'webp' : 'jpg'}`, { type: outputType }) : file
    } finally {
      URL.revokeObjectURL(sourceUrl)
    }
  }

  async function handleDeleteHistory(id: string) {
    try {
      const response = await fetch(`/api/history?id=${encodeURIComponent(id)}`, { method: 'DELETE' })
      if (!response.ok) throw new Error()
      setHistory((records) => records.filter((record) => record.id !== id))
      if (openHistoryId === id) setOpenHistoryId(null)
    } catch { setHistoryError('Unable to delete that history record.') }
  }

  async function handleComparison(event: FormEvent) {
    event.preventDefault()
    if (!comparisonFile) return
    setComparisonLoading(true)
    setComparisonError('')
    setComparison(null)
    const requestId = crypto.randomUUID()
    try {
      const screenshot = await compressScreenshot(comparisonFile)
      const form = new FormData()
      form.set('screenshot', screenshot)
      const response = await fetch('/api/compare', { method: 'POST', body: form })
      const data = await response.json()
      if (!response.ok) throw new Error(data.error)
      setComparison(data.report)
      const riskCategory = data.report.riskLevel
      const report = `${data.report.note}\n\nConfidence: ${data.report.confidence}${data.report.identifiedDomain ? `\nIdentified domain: ${data.report.identifiedDomain}` : ''}`
      const comparisonRecord = {
        target: 'Screenshot comparison',
        riskCategory,
        confidenceLevel: 'Medium',
        finalReport: report,
        findings: data.report,
      }
      await saveScanHistory({ ...comparisonRecord, requestId: `${requestId}:visual_comparison`, scanType: 'visual_comparison' })
      await saveScanHistory({ ...comparisonRecord, requestId: `${requestId}:ocr`, scanType: 'ocr' })
    } catch (comparisonError) {
      const message = comparisonError instanceof Error ? comparisonError.message : 'Unable to compare these screenshots.'
      setComparisonError(message)
      await Promise.all(['visual_comparison', 'ocr'].map((scanType) => saveScanHistory({ requestId: `${requestId}:${scanType}`, scanType: scanType as 'visual_comparison' | 'ocr', target: 'Screenshot comparison', riskCategory: 'Unable to verify', confidenceLevel: 'Low', finalReport: message, findings: { status: 'Unable to verify', error: message } })))
    } finally {
      setComparisonLoading(false)
    }
  }

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setLoading(true); setError(''); setResult(null); setExplanation(null)
    const requestId = crypto.randomUUID()
    try {
      const response = await fetch('/api/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url }) })
      const data = await response.json()
      if (!response.ok) throw new Error(data.error)
      setResult(data)
      setExplanationLoading(true)
      try {
        const explanationResponse = await fetch('/api/explain', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ result: data }), signal: AbortSignal.timeout(20000) })
        const explanationData = await explanationResponse.json()
        setExplanation(explanationData)
          const report = `${explanationData.available ? explanationData.explanation : data.note}\n\nRisk score: ${data.riskScore}/100 (higher means more risk).`
          const findings = { riskScore: data.riskScore, indicators: data.indicators }
          const confidenceLevel = data.indicators.some((item: Indicator) => item.status === 'unavailable') ? 'Medium' : 'High'
          const activityLabels: Record<Exclude<HistoryType, 'url_scan' | 'website_reputation' | 'visual_comparison' | 'ocr'>, string[]> = {
            domain_age: ['Domain age'],
            ssl_certificate: ['SSL certificate'],
            malicious_url_database: ['Phishing detection'],
            url_pattern_analysis: ['URL analysis'],
          }
          const activityTypes: HistoryType[] = ['url_scan', 'website_reputation', 'domain_age', 'ssl_certificate', 'malicious_url_database', 'url_pattern_analysis']
          await Promise.all(activityTypes.map((scanType) => saveScanHistory({
            requestId: `${requestId}:${scanType}`,
            scanType,
            target: data.normalizedUrl,
            riskCategory: data.risk,
            confidenceLevel,
            finalReport: report,
            findings: { ...findings, indicators: scanType === 'url_scan' ? data.indicators : data.indicators.filter((item: Indicator) => (scanType === 'website_reputation' ? ['Website reputation', 'Trusted brand reputation'].includes(item.label) : activityLabels[scanType as keyof typeof activityLabels]?.includes(item.label))) },
          })))
      } catch {
        const fallback = { available: false, error: 'Gemma is temporarily unavailable. The scan results are still available.' }
        setExplanation(fallback)
        const report = `${data.note}\n\nRisk score: ${data.riskScore}/100 (higher means more risk).`
        const findings = { riskScore: data.riskScore, indicators: data.indicators }
        const activityTypes: HistoryType[] = ['url_scan', 'website_reputation', 'domain_age', 'ssl_certificate', 'malicious_url_database', 'url_pattern_analysis']
        await Promise.all(activityTypes.map((scanType) => saveScanHistory({ requestId: `${requestId}:${scanType}`, scanType, target: data.normalizedUrl, riskCategory: data.risk, confidenceLevel: 'Medium', finalReport: report, findings })))
      }
    } catch (scanError) {
    const message = scanError instanceof Error ? scanError.message : 'Unable to scan this URL.'
    setError(message)
    if (url.trim()) {
      const activityTypes: HistoryType[] = ['url_scan', 'website_reputation', 'domain_age', 'ssl_certificate', 'malicious_url_database', 'url_pattern_analysis']
      await Promise.all(activityTypes.map((scanType) => saveScanHistory({ requestId: `${requestId}:${scanType}`, scanType, target: url.trim(), riskCategory: 'Unknown', confidenceLevel: 'Low', finalReport: message, findings: { status: 'Unknown', error: message } })))
    }
  } finally { setLoading(false); setExplanationLoading(false) }
  }

  return (
    <main className="min-h-screen bg-[#fafafa] text-slate-950">
      <header className="mx-auto flex max-w-5xl items-center justify-between px-6 py-7">
        <Link href="/" className="flex items-center gap-2.5"><img src="https://hebbkx1anhila5yf.public.blob.vercel-storage.com/image-TMC6J8OtTrw06fQx00D797ADPNMbbv.png" alt="FindFake AI logo" className="h-12 w-12 rounded-lg object-cover" /><span className="text-2xl font-semibold tracking-tight sm:text-3xl">FindFake<span className="text-slate-400"> AI</span></span></Link>
        <nav className="flex items-center gap-2 text-xs font-medium sm:text-sm">
          <span className="hidden rounded-full border border-slate-200 px-3 py-1 text-slate-500 sm:inline-flex">Smart Enter URL</span>
          <Link href="/dashboard" className="rounded-full bg-slate-950 px-3 py-1.5 text-white transition hover:bg-slate-800">Dashboard</Link>
        </nav>
      </header>
      <section className="mx-auto max-w-3xl px-6 pb-16 pt-16 text-center sm:pt-24">
        <p className="mb-4 text-sm font-semibold uppercase tracking-[0.18em] text-slate-400">Check before you click</p>
        <h1 className="text-4xl font-semibold tracking-[-0.04em] sm:text-6xl">Is this website <span className="text-slate-400">real?</span></h1>
        <p className="mx-auto mt-5 max-w-xl text-base leading-7 text-slate-500">Scan a URL for common phishing patterns, suspicious domains, and deceptive link structures.</p>
        <form onSubmit={handleSubmit} className="mx-auto mt-10 flex max-w-2xl flex-col gap-3 sm:flex-row">
          <label className="sr-only" htmlFor="website-url">Website URL</label>
          <input id="website-url" value={url} onChange={(event) => setUrl(event.target.value)} placeholder="https://example.com" className="h-14 min-w-0 flex-1 rounded-xl border border-slate-200 bg-slate-50 px-5 text-sm outline-none transition focus:border-slate-500 focus:bg-white focus:ring-4 focus:ring-slate-100" />
          <button disabled={loading} className="flex h-14 items-center justify-center gap-2 rounded-xl bg-slate-950 px-7 text-sm font-semibold text-white transition hover:bg-slate-800 disabled:cursor-wait disabled:opacity-60"><Search size={17} />{loading ? 'Scanning…' : 'Enter URL'}</button>
        </form>
        {error && <p role="alert" className="mt-4 text-sm font-medium text-red-600">{error}</p>}
        {result && <Results result={result} explanation={explanation} loading={explanationLoading} />}
        <ComparisonPanel file={comparisonFile} report={comparison} loading={comparisonLoading} error={comparisonError} onFileChange={setComparisonFile} onSubmit={handleComparison} />
        <HistoryPanel records={history} filter={historyFilter} from={historyFrom} to={historyTo} loading={historyLoading} error={historyError} openId={openHistoryId} onFilterChange={setHistoryFilter} onFromChange={setHistoryFrom} onToChange={setHistoryTo} onToggle={setOpenHistoryId} onDelete={handleDeleteHistory} />
      </section>
    </main>
  )
}

function ComparisonPanel({ file, report, loading, error, onFileChange, onSubmit }: { file: File | null; report: OCRReport | null; loading: boolean; error: string; onFileChange: (file: File | null) => void; onSubmit: (event: FormEvent) => void }) {
  return <section className="mx-auto mt-10 max-w-2xl rounded-3xl bg-white p-1 text-left" aria-labelledby="comparison-heading">
    <div className="flex items-center gap-3"><span className="flex h-9 w-9 items-center justify-center rounded-lg bg-slate-950 text-white shadow-sm"><Upload size={17} /></span><div><p className="text-xs font-semibold uppercase tracking-widest text-slate-400">Visual website analysis</p><h2 id="comparison-heading" className="mt-1 text-xl font-semibold tracking-tight text-slate-900">Verify a website screenshot</h2></div></div>
    <p className="mt-2 text-sm leading-6 text-slate-500">Upload one screenshot. OCR extracts visible details and checks for cautious impersonation indicators without assuming an unfamiliar site is fake.</p>
    <form onSubmit={onSubmit} className="mt-5 grid gap-3">
      <label className="rounded-xl border border-dashed border-slate-300 bg-slate-50 p-4 text-sm font-medium text-slate-700"><span className="block">Upload Website Screenshot</span><input type="file" accept="image/png,image/jpeg,image/webp" onChange={(event) => onFileChange(event.target.files?.[0] || null)} className="mt-3 block w-full text-xs text-slate-500 file:mr-3 file:rounded-lg file:border-0 file:bg-slate-950 file:px-3 file:py-2 file:text-xs file:font-semibold file:text-white" /></label>
      <button type="submit" disabled={loading || !file} className="h-12 rounded-xl bg-slate-950 text-sm font-semibold text-white transition hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-50">{loading ? 'Analysing screenshot…' : 'Analyse screenshot'}</button>
    </form>
    {error && <p role="alert" className="mt-3 text-sm text-red-600">{error}</p>}
    {report && <div className="mt-5 rounded-2xl border border-slate-200 bg-white p-5 text-sm leading-6 text-slate-600"><div className="flex flex-wrap items-center justify-between gap-2"><p className="font-semibold text-slate-800">Screenshot analysis</p><span className="rounded-full bg-slate-100 px-3 py-1 text-xs font-semibold text-slate-700">{report.riskLevel}</span></div><p className="mt-2 text-xs text-slate-500">Confidence: {report.confidence}{report.identifiedBrand ? ` · Claimed brand: ${report.identifiedBrand}` : ''}{report.identifiedDomain ? ` · Domain: ${report.identifiedDomain}` : ''}</p>{report.highlights.length > 0 && <ul className="mt-3 list-disc space-y-1 pl-5">{report.highlights.map((highlight) => <li key={highlight}>{highlight}</li>)}</ul>}{report.suspiciousText.length > 0 && <div className="mt-4"><p className="font-semibold text-slate-800">Visible text</p><p className="mt-1 text-sm">{report.suspiciousText.join(' · ')}</p></div>}<p className="mt-4 border-t border-slate-100 pt-4">{report.note}</p>{report.limitations.length > 0 && <div className="mt-3"><p className="font-semibold text-slate-800">Limitations</p><ul className="list-disc pl-5">{report.limitations.map((item) => <li key={item}>{item}</li>)}</ul></div>}</div>}
  </section>
}

function HistoryPanel({ records, filter, from, to, loading, error, openId, onFilterChange, onFromChange, onToChange, onToggle, onDelete }: { records: HistoryRecord[]; filter: 'all' | HistoryType; from: string; to: string; loading: boolean; error: string; openId: string | null; onFilterChange: (value: 'all' | HistoryType) => void; onFromChange: (value: string) => void; onToChange: (value: string) => void; onToggle: (id: string | null) => void; onDelete: (id: string) => void }) {
  const labels: Record<'all' | HistoryType, string> = { all: 'All scans', url_scan: 'URL Scan', website_reputation: 'Website Reputation', domain_age: 'Domain Age', ssl_certificate: 'SSL Certificate', malicious_url_database: 'Malicious URL Database', url_pattern_analysis: 'URL Pattern Analysis', visual_comparison: 'Visual Comparison', ocr: 'OCR' }
  return <section className="mx-auto mt-10 max-w-2xl rounded-3xl bg-white p-1 text-left" aria-labelledby="history-heading">
    <div className="flex items-center justify-between gap-4"><div><p className="text-xs font-semibold uppercase tracking-widest text-slate-400">Scan History</p><h2 id="history-heading" className="mt-1 text-xl font-semibold tracking-tight text-slate-900">Previous reports</h2></div><FileText className="text-slate-300" size={22} /></div>
    <div className="mt-4 flex flex-wrap gap-2">{(Object.keys(labels) as Array<'all' | HistoryType>).map((key) => <button key={key} type="button" onClick={() => onFilterChange(key)} className={`rounded-full border px-3 py-1.5 text-xs font-medium transition ${filter === key ? 'border-slate-950 bg-slate-950 text-white' : 'border-slate-200 text-slate-500 hover:border-slate-400'}`}>{labels[key]}</button>)}</div>
    <div className="mt-3 flex flex-wrap gap-2">
      <label className="text-xs text-slate-500">From <input type="date" value={from} onChange={(event) => onFromChange(event.target.value)} className="ml-1 rounded-lg border border-slate-200 px-2 py-1.5 text-xs text-slate-700" /></label>
      <label className="text-xs text-slate-500">To <input type="date" value={to} onChange={(event) => onToChange(event.target.value)} className="ml-1 rounded-lg border border-slate-200 px-2 py-1.5 text-xs text-slate-700" /></label>
    </div>
    {error && <p role="alert" className="mt-4 text-sm text-amber-700">{error}</p>}
    {loading ? <p className="mt-5 text-sm text-slate-500">Loading saved reports…</p> : records.length === 0 ? <p className="mt-5 rounded-xl border border-dashed border-slate-200 p-5 text-sm text-slate-500">No saved reports in this filter.</p> : <div className="mt-5 divide-y divide-slate-100 rounded-2xl border border-slate-200 bg-white">{records.map((record) => <div key={record.id} className="p-4"><div className="flex items-start gap-3"><button type="button" onClick={() => onToggle(openId === record.id ? null : record.id)} className="min-w-0 flex-1 text-left"><p className="text-sm font-semibold text-slate-800">{labels[record.scanType]}</p><p className="mt-1 truncate text-xs text-slate-500">{record.target || 'Saved report'}</p><p className="mt-1 text-xs text-slate-400">{new Date(record.scanDate).toLocaleString()} · {record.riskCategory} · {record.confidenceLevel} confidence{typeof record.findings.riskScore === 'number' ? ` · Risk score ${record.findings.riskScore}/100` : ''}</p></button><button type="button" aria-label={`Delete ${labels[record.scanType]} report`} onClick={() => onDelete(record.id)} className="rounded-lg p-2 text-slate-400 hover:bg-red-50 hover:text-red-600"><Trash2 size={16} /></button></div>{openId === record.id && <div className="mt-4 border-t border-slate-100 pt-4 text-sm leading-6 text-slate-600"><p className="whitespace-pre-wrap">{record.finalReport}</p></div>}</div>)}</div>}
  </section>
}

function Results({ result, explanation, loading }: { result: Result; explanation: Explanation | null; loading: boolean }) {
  const concernClass = result.risk === 'High concern'
    ? 'bg-red-50 text-red-700'
    : result.risk === 'Medium concern'
      ? 'bg-amber-50 text-amber-700'
      : result.risk === 'Inconclusive'
        ? 'bg-slate-100 text-slate-700'
        : 'bg-emerald-50 text-emerald-700'

  return (
    <section aria-live="polite" className="mx-auto mt-12 max-w-2xl rounded-3xl bg-white p-1 text-left">
      <div className="rounded-2xl border border-slate-200 bg-slate-50 p-6 sm:p-8">
        <div className="flex items-center gap-3">
          <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-slate-950 text-white shadow-sm"><Sparkles size={17} /></span>
          <div><p className="text-xs font-semibold uppercase tracking-widest text-slate-400">AI Security Explanation</p><p className="mt-1 text-sm text-slate-500">A cautious summary of the scan evidence.</p></div>
        </div>
        {loading ? <p className="mt-6 text-sm text-slate-500">Gemma is preparing an explanation…</p> : explanation?.available && explanation.explanation ? <div className="mt-6 whitespace-pre-wrap text-sm leading-7 text-slate-600">{explanation.explanation}</div> : <p className="mt-6 text-sm leading-6 text-slate-500">{explanation?.error || 'AI explanation is unavailable. Your scan results are still valid and unchanged.'}</p>}
        <p className="mt-6 border-t border-slate-200 pt-4 text-xs leading-5 text-slate-400">AI-generated guidance is limited to the detected evidence above. It does not verify ownership or prove that a site is safe.</p>
      </div>

      <div className="mt-6 rounded-2xl border border-slate-200 bg-white p-6 shadow-[0_12px_40px_rgba(15,23,42,0.06)] sm:p-8">
        <div className="flex flex-col justify-between gap-4 border-b border-slate-100 pb-6 sm:flex-row sm:items-start"><div><p className="text-xs font-semibold uppercase tracking-widest text-slate-400">Scan summary</p><p className="mt-2 break-all text-sm text-slate-600">{result.normalizedUrl}</p></div><div className="flex items-center gap-2"><span className="rounded-full bg-slate-100 px-3 py-1.5 text-sm font-semibold text-slate-700">Risk score {result.riskScore}/100</span><span className={`w-fit rounded-full px-3 py-1.5 text-sm font-semibold ${concernClass}`}>{result.risk}</span></div></div>
        <div className="divide-y divide-slate-100">
          {result.indicators.map((item) => {
            const meta = statusMeta[item.status]
            const Icon = meta.icon
            return <details key={item.label} className="group py-5 first:pb-4"><summary className="flex cursor-pointer list-none items-center gap-3"><span className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-full ${meta.className}`}><Icon size={15} strokeWidth={2.5} /></span><span className="flex-1 text-sm font-semibold text-slate-800">{item.label}</span><span className={`hidden rounded-full px-2.5 py-1 text-xs font-medium sm:inline ${meta.className}`}>{meta.label}</span><ChevronDown size={16} className="text-slate-400 transition group-open:rotate-180" /></summary><div className="ml-10 mt-3 space-y-1 text-sm leading-6 text-slate-500"><p>{item.explanation}</p><p className="text-xs text-slate-400"><span className="font-semibold">Evidence:</span> {item.evidence}</p></div></details>
          })}
        </div>
        <p className="mt-2 border-t border-slate-100 pt-5 text-xs leading-5 text-slate-400">{result.note}</p>
      </div>
    </section>
  )
}
