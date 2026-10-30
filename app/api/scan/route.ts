import { NextResponse } from 'next/server'

const PRIVATE_HOST = /^(localhost|.*\.local|127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[0-1])\.|0\.)/i
const COMMON_BRANDS = ['google.com', 'paypal.com', 'microsoft.com', 'apple.com', 'amazon.com', 'facebook.com', 'instagram.com', 'netflix.com']

type Status = 'passed' | 'warning' | 'failed' | 'unavailable'

type Indicator = { label: string; status: Status; explanation: string; evidence: string }

function levenshtein(a: string, b: string) {
  const row = Array.from({ length: b.length + 1 }, (_, i) => i)
  for (let i = 1; i <= a.length; i++) {
    let previous = row[0]
    row[0] = i
    for (let j = 1; j <= b.length; j++) {
      const current = row[j]
      row[j] = Math.min(row[j] + 1, row[j - 1] + 1, previous + (a[i - 1] === b[j - 1] ? 0 : 1))
      previous = current
    }
  }
  return row[b.length]
}

function scanUrl(input: string) {
  const value = input.trim().replace(/\s+/g, '')
  if (!value || value.length > 2048) throw new Error('Enter a URL under 2,048 characters.')
  const candidate = /^https?:\/\//i.test(value) ? value : `https://${value}`
  let url: URL
  try { url = new URL(candidate) } catch { throw new Error('Enter a valid website URL.') }
  if (!['http:', 'https:'].includes(url.protocol) || !url.hostname) throw new Error('Only HTTP and HTTPS website URLs are supported.')
  const hostname = url.hostname.toLowerCase().replace(/\.$/, '')
  if (PRIVATE_HOST.test(hostname) || /^[0-9a-f:]+$/i.test(hostname) || /^\d+(\.\d+){3}$/.test(hostname)) throw new Error('Private, local, and IP-address destinations are not allowed.')

  const labels = hostname.split('.')
  const registrable = labels.slice(-2).join('.')
  const indicators: Indicator[] = []
  const unicode = /[^\x00-\x7F]/.test(hostname) || hostname.includes('xn--')
  const brandMatch = COMMON_BRANDS.find((brand) => {
    const base = brand.split('.')[0]
    const hostBase = registrable.split('.')[0]
    return hostBase !== base && levenshtein(hostBase, base) <= 2
  })
  const misleadingSubdomain = labels.length > 2 && COMMON_BRANDS.some((brand) => labels.slice(0, -2).join('.').toLowerCase().includes(brand.split('.')[0]))
  const suspiciousPath = url.pathname.length > 180 || url.search.length > 500 || url.href.length > 500
  const hasEncodedTricks = /%[0-9a-f]{2}/i.test(url.pathname + url.search) || /[\\@]/.test(url.pathname + url.search)

  indicators.push({ label: 'Domain spelling', status: brandMatch ? 'failed' : 'passed', explanation: brandMatch ? 'The domain closely resembles a well-known brand but is not the official domain.' : 'No close spelling match to common brands was found.', evidence: brandMatch ? `“${registrable}” is visually close to “${brandMatch}”.` : `Registered domain examined: ${registrable}.` })
  indicators.push({ label: 'Subdomain structure', status: misleadingSubdomain ? 'warning' : 'passed', explanation: misleadingSubdomain ? 'A brand-like term appears in a subdomain, which can make the real owner harder to see.' : 'No misleading brand-like subdomain was detected.', evidence: misleadingSubdomain ? `Full host: ${hostname}` : 'Host labels have a conventional structure.' })
  indicators.push({ label: 'Unicode characters', status: unicode ? 'warning' : 'passed', explanation: unicode ? 'Unicode or punycode can create look-alike characters in a domain name.' : 'The hostname uses standard ASCII characters.', evidence: unicode ? `Hostname: ${hostname}` : 'No non-ASCII hostname characters found.' })
  indicators.push({ label: 'URL structure', status: suspiciousPath || hasEncodedTricks ? 'warning' : 'passed', explanation: suspiciousPath || hasEncodedTricks ? 'The URL contains unusually long or encoded sections that deserve extra care.' : 'The URL length and encoding look ordinary.', evidence: `Length: ${url.href.length} characters${hasEncodedTricks ? '; encoded or escape characters present' : ''}.` })
  indicators.push({ label: 'Network destination', status: 'unavailable', explanation: 'Live reputation, content, and ownership checks were not performed.', evidence: 'No request was made to the submitted website.' })

  const failed = indicators.filter((item) => item.status === 'failed').length
  const warnings = indicators.filter((item) => item.status === 'warning').length
  const risk = failed > 0 ? 'High concern' : warnings > 0 ? 'Medium concern' : 'Inconclusive'
  return { normalizedUrl: url.toString(), risk, indicators, note: 'Pattern checks only. No suspicious pattern does not prove a website is safe; live reputation and ownership checks are unavailable.' }
}

export async function POST(request: Request) {
  try {
    const body = await request.json()
    if (typeof body?.url !== 'string') return NextResponse.json({ error: 'Enter a website URL.' }, { status: 400 })
    return NextResponse.json(scanUrl(body.url))
  } catch (error) {
    return NextResponse.json({ error: error instanceof Error ? error.message : 'Unable to scan this URL.' }, { status: 400 })
  }
}
