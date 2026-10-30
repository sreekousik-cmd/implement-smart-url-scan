import { NextResponse } from 'next/server'

const MODEL = 'gemma-4-26b-a4b-it'
const MAX_BYTES = 5 * 1024 * 1024
const ALLOWED_TYPES = new Set(['image/png', 'image/jpeg', 'image/webp'])

type OCRReport = {
  riskLevel: 'Likely legitimate' | 'Suspicious' | 'High risk' | 'Inconclusive'
  confidence: string
  identifiedBrand: string
  identifiedDomain: string
  limitations: string[]
  suspiciousText: string[]
  officialText: string[]
  matchingText: string[]
  changedText: { suspicious: string; official: string; reason: string }[]
  missingText: { text: string; presentOn: 'suspicious' | 'official' }[]
  highlights: string[]
  note: string
}

function cleanReport(value: unknown): OCRReport {
  const candidate = Array.isArray(value) ? value[0] : value
  const source = candidate && typeof candidate === 'object' ? candidate as Record<string, unknown> : {}
  const strings = (input: unknown) => Array.isArray(input) ? input.filter((item): item is string => typeof item === 'string').slice(0, 40) : []
  const changed = Array.isArray(source.changedText) ? source.changedText.slice(0, 30).map((item) => {
    const row = item && typeof item === 'object' ? item as Record<string, unknown> : {}
    return { suspicious: String(row.suspicious || '').slice(0, 180), official: String(row.official || '').slice(0, 180), reason: String(row.reason || '').slice(0, 240) }
  }).filter((item) => item.suspicious || item.official) : []
  const missing = Array.isArray(source.missingText) ? source.missingText.slice(0, 30).map((item) => {
    const row = item && typeof item === 'object' ? item as Record<string, unknown> : {}
    return { text: String(row.text || '').slice(0, 180), presentOn: row.presentOn === 'official' ? 'official' as const : 'suspicious' as const }
  }).filter((item) => item.text) : []
  const riskLevels = new Set(['Likely legitimate', 'Suspicious', 'High risk', 'Inconclusive'])
  return {
    riskLevel: riskLevels.has(String(source.riskLevel)) ? String(source.riskLevel) as OCRReport['riskLevel'] : 'Inconclusive',
    confidence: typeof source.confidence === 'string' ? source.confidence.slice(0, 80) : 'Low',
    identifiedBrand: typeof source.identifiedBrand === 'string' ? source.identifiedBrand.slice(0, 160) : '',
    identifiedDomain: typeof source.identifiedDomain === 'string' ? source.identifiedDomain.slice(0, 240) : '',
    limitations: strings(source.limitations).slice(0, 10),
    suspiciousText: strings(source.suspiciousText), officialText: strings(source.officialText), matchingText: strings(source.matchingText),
    changedText: changed, missingText: missing, highlights: strings(source.highlights),
    note: typeof source.note === 'string' ? source.note.slice(0, 500) : 'OCR detects visible details; it does not verify ownership or prove that a site is safe.',
  }
}

export async function POST(request: Request) {
  const key = process.env.GOOGLE_AI_STUDIO_API_KEY
  if (!key) return NextResponse.json({ error: 'OCR service is not configured.' }, { status: 503 })

  const form = await request.formData()
  const screenshot = form.get('screenshot')
  const suspicious = form.get('suspicious')
  const official = form.get('official')
  const singleScreenshot = screenshot instanceof File ? screenshot : null
  if (!singleScreenshot && (!(suspicious instanceof File) || !(official instanceof File))) return NextResponse.json({ error: 'Upload a website screenshot.' }, { status: 400 })
  for (const file of singleScreenshot ? [singleScreenshot] : [suspicious as File, official as File]) {
    if (!ALLOWED_TYPES.has(file.type) || file.size > MAX_BYTES) return NextResponse.json({ error: 'Use PNG, JPEG, or WebP images up to 5 MB each.' }, { status: 400 })
  }

  const toData = async (file: File) => ({ mimeType: file.type, data: Buffer.from(await file.arrayBuffer()).toString('base64') })
  const images = await Promise.all((singleScreenshot ? [singleScreenshot] : [suspicious as File, official as File]).map(toData))
  const prompt = singleScreenshot
    ? `You are analysing one website screenshot cautiously. Extract only clearly visible text, website names, URLs, logos, product names, prices, and other details. Identify the claimed brand and domain only when visible or strongly supported. Assess suspicious branding, copied-looking layouts, misleading URLs, unrealistic discounts, and impersonation indicators without assuming unfamiliar means fake. Return ONLY valid JSON with this shape: {"riskLevel":"Likely legitimate|Suspicious|High risk|Inconclusive","confidence":"Low|Medium|High","identifiedBrand":"","identifiedDomain":"","limitations":[],"suspiciousText":[],"officialText":[],"matchingText":[],"changedText":[],"missingText":[],"highlights":[],"note":""}. A screenshot alone cannot verify ownership; use Inconclusive and ask for the website URL when it is insufficient. Do not fabricate OCR, brand matches, official references, or threat-intelligence results. Screenshot follows.`
    : `You are doing OCR and a cautious text comparison. Extract only clearly visible text from image 1 (suspicious) and image 2 (official). Compare brand names, headings, navigation, buttons, alerts, and messages. Return ONLY valid JSON with riskLevel, confidence, identifiedBrand, identifiedDomain, limitations, and this shape: {"suspiciousText":[],"officialText":[],"matchingText":[],"changedText":[{"suspicious":"","official":"","reason":""}],"missingText":[{"text":"","presentOn":"suspicious|official"}],"highlights":[],"note":""}. Do not infer hidden text or declare phishing. Keep arrays concise. Image 1 follows, then image 2.`
  const body = { contents: [{ parts: [{ text: prompt }, ...images.map((image) => ({ inlineData: image }))] }], generationConfig: { temperature: 0, maxOutputTokens: 1400, responseMimeType: 'application/json', thinkingConfig: { thinkingLevel: 'minimal' } } }

  try {
    const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${MODEL}:generateContent?key=${encodeURIComponent(key)}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(30000) })
    const payload = await response.json().catch(() => null)
    if (!response.ok) {
      const upstreamMessage = typeof payload?.error?.message === 'string' ? payload.error.message : `OCR provider returned HTTP ${response.status}.`
      console.error('[v0] OCR Gemini error', { status: response.status, message: upstreamMessage })
      return NextResponse.json({ error: upstreamMessage }, { status: 502 })
    }
    const parts = payload?.candidates?.[0]?.content?.parts
    const textParts = Array.isArray(parts)
      ? parts.filter((part: { text?: unknown; thought?: boolean }) => typeof part?.text === 'string' && !part.thought).map((part: { text: string }) => part.text)
      : []
    const text = textParts.at(-1) || (Array.isArray(parts) ? parts.find((part: { text?: unknown }) => typeof part?.text === 'string')?.text : undefined)
    if (!text) return NextResponse.json({ error: 'No readable text was detected.' }, { status: 422 })
    try {
      const normalized = text.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/i, '').trim()
      let parsed: unknown
      try {
        parsed = JSON.parse(normalized)
      } catch {
        const jsonStart = normalized.indexOf('{')
        const jsonEnd = normalized.lastIndexOf('}')
        const jsonText = jsonStart >= 0 && jsonEnd > jsonStart ? normalized.slice(jsonStart, jsonEnd + 1) : normalized
        parsed = JSON.parse(jsonText)
      }
      return NextResponse.json({ report: cleanReport(parsed) })
    } catch {
      console.error('[v0] OCR Gemini returned invalid JSON', { message: 'Model response was not valid structured OCR JSON' })
      return NextResponse.json({ report: cleanReport({ note: 'OCR could not reliably parse the returned text. Try clearer screenshots.' }), warning: 'OCR returned no reliable structured differences.' })
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown request error'
    const timedOut = message.toLowerCase().includes('abort') || message.toLowerCase().includes('timeout')
    console.error('[v0] OCR request failed', { message })
    return NextResponse.json({ error: timedOut ? 'OCR comparison timed out after 30 seconds.' : `OCR request failed: ${message}` }, { status: timedOut ? 504 : 502 })
  }
}
