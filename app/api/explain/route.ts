import { NextResponse } from 'next/server'

type Indicator = { label: string; status: string; explanation: string; evidence: string }
type ScanResult = { normalizedUrl: string; risk: string; indicators: Indicator[]; note: string }

const GEMMA_MODEL = 'gemma-4-26b-a4b-it'

function buildPrompt(result: ScanResult) {
  const findings = result.indicators.map((item) =>
    `- ${item.label}: status=${item.status}; explanation=${item.explanation}; evidence=${item.evidence}`,
  ).join('\n')

  return `You are a cautious website-safety educator. Explain this URL scan in plain language for a non-technical user.

Hard rules:
- Use only the supplied scan findings. Never invent checks, evidence, reputation data, ownership data, or page content.
- Clearly label supplied findings as detected evidence and anything else as an assumption or limitation.
- Never say the website is genuine, safe, or malicious as a verified fact. The scan is not proof of legitimacy.
- Explicitly mention checks marked unavailable and what that means.
- Do not include markdown tables. Keep the response under 350 words.

URL: ${result.normalizedUrl}
Overall scan result: ${result.risk}
Scanner note: ${result.note}
Findings:
${findings}

Use these short headings:
Why it may be suspicious
Detected evidence
What the indicators mean
What to be careful about
Recommended next steps`
}

export async function POST(request: Request) {
  const apiKey = process.env.GOOGLE_AI_STUDIO_API_KEY
  if (!apiKey) {
    return NextResponse.json({ available: false, error: 'Gemma is unavailable because GOOGLE_AI_STUDIO_API_KEY is not configured.' }, { status: 200 })
  }

  try {
    const body = await request.json()
    const result = body?.result as ScanResult | undefined
    if (!result?.normalizedUrl || !Array.isArray(result.indicators)) {
      return NextResponse.json({ available: false, error: 'Scan findings are required.' }, { status: 400 })
    }

    const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${GEMMA_MODEL}:generateContent?key=${encodeURIComponent(apiKey)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ contents: [{ parts: [{ text: buildPrompt(result) }] }] }),
      cache: 'no-store',
      signal: AbortSignal.timeout(15000),
    })

    if (!response.ok) {
      return NextResponse.json({ available: false, error: 'Gemma could not generate an explanation right now.' }, { status: 200 })
    }

    const data = await response.json()
    const explanation = data?.candidates?.[0]?.content?.parts?.map((part: { text?: string }) => part.text || '').join('').trim()
    if (!explanation) return NextResponse.json({ available: false, error: 'Gemma returned no explanation.' }, { status: 200 })
    return NextResponse.json({ available: true, explanation, model: GEMMA_MODEL })
  } catch {
    return NextResponse.json({ available: false, error: 'Gemma is temporarily unavailable. The scan results are still available.' }, { status: 200 })
  }
}
