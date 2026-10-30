import { NextResponse } from 'next/server'

type Indicator = { label: string; status: string; explanation: string; evidence: string }
type ScanResult = { normalizedUrl: string; risk: string; indicators: Indicator[]; note: string }

const GEMMA_MODEL = 'gemma-4-26b-a4b-it'

function buildPrompt(result: ScanResult) {
  const findings = result.indicators.map((item) => {
    const explanation = item.explanation.slice(0, 240)
    const evidence = item.evidence.slice(0, 180)
    return `- ${item.label}: status=${item.status}; explanation=${explanation}; evidence=${evidence}`
  }).join('\n')

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

    const payload = JSON.stringify({
      contents: [{ parts: [{ text: buildPrompt(result) }] }],
      generationConfig: { maxOutputTokens: 256 },
    })
    let lastError = 'Gemma request failed.'

    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${GEMMA_MODEL}:generateContent?key=${encodeURIComponent(apiKey)}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: payload,
          cache: 'no-store',
          signal: AbortSignal.timeout(15000),
        })

        if (response.ok) {
          const data = await response.json()
          const parts = data?.candidates?.[0]?.content?.parts as Array<{ text?: string; thought?: boolean }> | undefined
          const explanation = parts?.filter((part) => !part.thought && part.text).map((part) => part.text).join('').trim()
            || parts?.map((part) => part.text || '').join('').trim()
          if (!explanation) {
            lastError = 'Gemma returned no explanation.'
          } else {
            return NextResponse.json({ available: true, explanation, model: GEMMA_MODEL })
          }
        } else {
          const detail = (await response.text()).slice(0, 300)
          lastError = `Gemini API ${response.status}: ${detail || response.statusText}`
          if (response.status < 500 && response.status !== 429) break
        }
      } catch (error) {
        lastError = error instanceof Error ? error.message : 'Gemma request failed.'
      }
    }

    console.error('[FindFake AI] Gemma explanation failed:', { model: GEMMA_MODEL, error: lastError })
    return NextResponse.json({ available: false, error: 'Gemma is temporarily unavailable. The scan results are still available.' }, { status: 200 })
  } catch (error) {
    console.error('[FindFake AI] Explanation request failed:', error instanceof Error ? error.message : 'Unknown error')
    return NextResponse.json({ available: false, error: 'Gemma is temporarily unavailable. The scan results are still available.' }, { status: 200 })
  }
}
