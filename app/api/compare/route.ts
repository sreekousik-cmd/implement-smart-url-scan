import { NextResponse } from 'next/server'

const MODEL = 'gemma-4-26b-a4b-it'
const MAX_BYTES = 5 * 1024 * 1024
const ALLOWED_TYPES = new Set(['image/png', 'image/jpeg', 'image/webp'])

type OCRReport = {
  suspiciousText: string[]
  officialText: string[]
  matchingText: string[]
  changedText: { suspicious: string; official: string; reason: string }[]
  missingText: { text: string; presentOn: 'suspicious' | 'official' }[]
  highlights: string[]
  note: string
}

function cleanReport(value: unknown): OCRReport {
  const source = value && typeof value === 'object' ? value as Record<string, unknown> : {}
  const strings = (input: unknown) => Array.isArray(input) ? input.filter((item): item is string => typeof item === 'string').slice(0, 40) : []
  const changed = Array.isArray(source.changedText) ? source.changedText.slice(0, 30).map((item) => {
    const row = item && typeof item === 'object' ? item as Record<string, unknown> : {}
    return { suspicious: String(row.suspicious || '').slice(0, 180), official: String(row.official || '').slice(0, 180), reason: String(row.reason || '').slice(0, 240) }
  }).filter((item) => item.suspicious || item.official) : []
  const missing = Array.isArray(source.missingText) ? source.missingText.slice(0, 30).map((item) => {
    const row = item && typeof item === 'object' ? item as Record<string, unknown> : {}
    return { text: String(row.text || '').slice(0, 180), presentOn: row.presentOn === 'official' ? 'official' as const : 'suspicious' as const }
  }).filter((item) => item.text) : []
  return {
    suspiciousText: strings(source.suspiciousText), officialText: strings(source.officialText), matchingText: strings(source.matchingText),
    changedText: changed, missingText: missing, highlights: strings(source.highlights),
    note: typeof source.note === 'string' ? source.note.slice(0, 500) : 'OCR detects visible text differences; it does not prove that either site is fraudulent.',
  }
}

export async function POST(request: Request) {
  const key = process.env.GOOGLE_AI_STUDIO_API_KEY
  if (!key) return NextResponse.json({ error: 'OCR service is not configured.' }, { status: 503 })

  const form = await request.formData()
  const suspicious = form.get('suspicious')
  const official = form.get('official')
  if (!(suspicious instanceof File) || !(official instanceof File)) return NextResponse.json({ error: 'Upload both screenshots.' }, { status: 400 })
  for (const file of [suspicious, official]) {
    if (!ALLOWED_TYPES.has(file.type) || file.size > MAX_BYTES) return NextResponse.json({ error: 'Use PNG, JPEG, or WebP images up to 8 MB each.' }, { status: 400 })
  }

  const toData = async (file: File) => ({ mimeType: file.type, data: Buffer.from(await file.arrayBuffer()).toString('base64') })
  const [suspiciousImage, officialImage] = await Promise.all([toData(suspicious), toData(official)])
  const prompt = `You are doing OCR and a cautious text comparison. Extract only clearly visible text from image 1 (suspicious) and image 2 (official). Compare brand names, headings, navigation, buttons, alerts, and messages. Return ONLY valid JSON with this shape: {"suspiciousText":[],"officialText":[],"matchingText":[],"changedText":[{"suspicious":"","official":"","reason":""}],"missingText":[{"text":"","presentOn":"suspicious|official"}],"highlights":[],"note":""}. Do not infer hidden text or declare phishing. Keep arrays concise. Image 1 follows, then image 2.`
  const body = { contents: [{ parts: [{ text: prompt }, { inlineData: suspiciousImage }, { inlineData: officialImage }] }], generationConfig: { temperature: 0, maxOutputTokens: 400, responseMimeType: 'application/json' } }

  try {
    const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${MODEL}:generateContent?key=${encodeURIComponent(key)}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(30000) })
    const payload = await response.json().catch(() => null)
    if (!response.ok) {
      console.error('[v0] OCR Gemini error', { status: response.status, message: payload?.error?.message || 'Unknown upstream error' })
      return NextResponse.json({ error: 'OCR comparison is temporarily unavailable.' }, { status: 502 })
    }
    const text = payload?.candidates?.[0]?.content?.parts?.find((part: { text?: string }) => part.text)?.text
    if (!text) return NextResponse.json({ error: 'No readable text was detected.' }, { status: 422 })
    try {
      const normalized = text.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/i, '').trim()
      const jsonStart = normalized.indexOf('{')
      const jsonEnd = normalized.lastIndexOf('}')
      const jsonText = jsonStart >= 0 && jsonEnd > jsonStart ? normalized.slice(jsonStart, jsonEnd + 1) : normalized
      return NextResponse.json({ report: cleanReport(JSON.parse(jsonText)) })
    } catch {
      console.error('[v0] OCR Gemini returned invalid JSON', { preview: text.slice(0, 160) })
      return NextResponse.json({ report: cleanReport({ note: 'OCR could not reliably parse the returned text. Try clearer screenshots.' }), warning: 'OCR returned no reliable structured differences.' })
    }
  } catch (error) {
    console.error('[v0] OCR request failed', { message: error instanceof Error ? error.message : 'Unknown request error' })
    return NextResponse.json({ error: 'OCR comparison timed out. Try clearer screenshots.' }, { status: 504 })
  }
}
