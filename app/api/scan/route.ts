import { lookup } from 'node:dns/promises'
import { isIP } from 'node:net'
import { connect as tlsConnect } from 'node:tls'
import { NextResponse } from 'next/server'
import { TRUSTED_BRAND_DOMAINS, TRUSTED_BRANDS } from '@/lib/trusted-brands'

const PRIVATE_HOST = /^(localhost|.*\.local|127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[0-1])\.|0\.)/i
const COMMON_BRANDS = TRUSTED_BRAND_DOMAINS
const CHECK_TIMEOUT_MS = 7000
const MULTI_LABEL_SUFFIXES = new Set(['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'co.jp', 'co.nz', 'co.za'])

type Status = 'passed' | 'warning' | 'failed' | 'unavailable'
type Indicator = { label: string; status: Status; explanation: string; evidence: string }
type ParsedUrl = { url: URL; hostname: string; registrable: string }

type RdapEvent = { eventAction?: string; eventDate?: string }
type Certificate = { valid_from?: string; valid_to?: string; issuer?: { O?: string; CN?: string }; subject?: { CN?: string } }

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

function withTimeout<T>(promise: Promise<T>, message: string) {
  return Promise.race([
    promise,
    new Promise<never>((_, reject) => setTimeout(() => reject(new Error(message)), CHECK_TIMEOUT_MS)),
  ])
}

function getRegistrableDomain(hostname: string) {
  const labels = hostname.split('.').filter(Boolean)
  if (labels.length <= 2) return labels.join('.')
  const suffix = labels.slice(-2).join('.')
  return MULTI_LABEL_SUFFIXES.has(suffix) ? labels.slice(-3).join('.') : suffix
}

function parseUrl(input: string): ParsedUrl {
  const value = input.trim().replace(/\s+/g, '')
  if (!value || value.length > 2048) throw new Error('Enter a URL under 2,048 characters.')
  const candidate = /^https?:\/\//i.test(value) ? value : `https://${value}`
  let url: URL
  try { url = new URL(candidate) } catch { throw new Error('Enter a valid website URL.') }
  if (!['http:', 'https:'].includes(url.protocol) || !url.hostname) throw new Error('Only HTTP and HTTPS website URLs are supported.')
  const hostname = url.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '')
  if (PRIVATE_HOST.test(hostname) || /^[0-9a-f:]+$/i.test(hostname) || /^\d+(\.\d+){3}$/.test(hostname)) throw new Error('Private, local, and IP-address destinations are not allowed.')
  return { url, hostname, registrable: getRegistrableDomain(hostname) }
}

function unavailable(label: string, explanation: string, evidence: string): Indicator {
  return { label, status: 'unavailable', explanation, evidence }
}

function rdapEndpoints(registrable: string) {
  const tld = registrable.split('.').pop()
  if (tld === 'com' || tld === 'net') return [`https://rdap.verisign.com/${tld}/v1/domain/${encodeURIComponent(registrable)}`]
  if (tld === 'org') return [`https://rdap.publicinterestregistry.org/rdap/org/domain/${encodeURIComponent(registrable)}`]
  return [`https://rdap.org/domain/${encodeURIComponent(registrable)}`]
}

async function checkDomainAge(registrable: string): Promise<Indicator> {
  try {
    let data: { events?: RdapEvent[] } | null = null
    let lastStatus = 'no response'
    for (const endpoint of rdapEndpoints(registrable)) {
      const response = await withTimeout(fetch(endpoint, { cache: 'no-store' }), 'RDAP timed out.')
      lastStatus = `HTTP ${response.status}`
      if (response.ok) {
        data = await response.json() as { events?: RdapEvent[] }
        break
      }
    }
    if (!data) return unavailable('Domain age', 'The registration service could not verify this domain.', `RDAP returned ${lastStatus} for ${registrable}.`)
    const registration = data.events?.find((event) => ['registration', 'registered'].includes(event.eventAction?.toLowerCase() || ''))?.eventDate
    if (!registration) return unavailable('Domain age', 'No registration date was provided by RDAP.', `RDAP returned no registration event for ${registrable}.`)
    const registrationTime = new Date(registration).getTime()
    const ageDays = Math.floor((Date.now() - registrationTime) / 86_400_000)
    if (!Number.isFinite(ageDays) || ageDays < 0) return unavailable('Domain age', 'The registration date could not be interpreted safely.', `RDAP registration date: ${registration}.`)
    const status: Status = ageDays < 7 ? 'failed' : ageDays < 30 ? 'warning' : 'passed'
    return { label: 'Domain age', status, explanation: ageDays < 30 ? 'Recently registered domains deserve additional caution because phishing sites are often short-lived.' : 'The RDAP registration date is not unusually recent.', evidence: `Registered ${ageDays} day${ageDays === 1 ? '' : 's'} ago (${new Date(registrationTime).toISOString().slice(0, 10)}).` }
  } catch (error) {
    console.error('[scan] RDAP check failed', { registrable, error: error instanceof Error ? error.message : 'unknown error' })
    return unavailable('Domain age', 'The registration service was unavailable.', error instanceof Error ? error.message : 'RDAP request failed.')
  }
}

function isPrivateAddress(address: string) {
  if (isIP(address) === 4) {
    const parts = address.split('.').map(Number)
    return parts[0] === 10 || parts[0] === 127 || parts[0] === 0 || (parts[0] === 169 && parts[1] === 254) || (parts[0] === 192 && parts[1] === 168) || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31)
  }
  const normalized = address.toLowerCase()
  return normalized === '::1' || normalized.startsWith('fc') || normalized.startsWith('fd') || normalized.startsWith('fe80:') || normalized.startsWith('::ffff:10.') || normalized.startsWith('::ffff:192.168.') || normalized.startsWith('::ffff:127.')
}

async function resolvePublicAddresses(hostname: string) {
  const results = await withTimeout(lookup(hostname, { all: true }), 'DNS lookup timed out.')
  const addresses = results.map((result) => result.address)
  if (!addresses.length || addresses.some(isPrivateAddress)) throw new Error('The hostname resolves to a private or restricted address.')
  return addresses
}

async function checkSsl(hostname: string, protocol: string): Promise<Indicator> {
  if (protocol !== 'https:') return unavailable('SSL certificate', 'The submitted URL does not use HTTPS, so a certificate could not be verified.', 'Use an HTTPS URL for certificate verification.')
  try {
    const [address] = await resolvePublicAddresses(hostname)
    const certificate = await withTimeout(new Promise<Certificate>((resolve, reject) => {
      const socket = tlsConnect({ host: address, servername: hostname, port: 443, rejectUnauthorized: true }, () => {
        const peer = socket.getPeerCertificate(true) as Certificate
        socket.end()
        resolve(peer)
      })
      socket.once('error', reject)
      socket.setTimeout(CHECK_TIMEOUT_MS, () => socket.destroy(new Error('TLS handshake timed out.')))
    }), 'TLS check timed out.')
    if (!certificate.valid_from || !certificate.valid_to) return unavailable('SSL certificate', 'The certificate did not expose complete validity dates.', 'Certificate details were incomplete.')
    const validFrom = new Date(certificate.valid_from)
    const expiry = new Date(certificate.valid_to)
    if (!Number.isFinite(validFrom.getTime()) || !Number.isFinite(expiry.getTime())) return unavailable('SSL certificate', 'The certificate dates could not be interpreted safely.', 'Certificate dates were invalid.')
    const now = Date.now()
    const daysRemaining = Math.floor((expiry.getTime() - now) / 86_400_000)
    const notYetValid = validFrom.getTime() > now
    if (daysRemaining < 0) return { label: 'SSL certificate', status: 'failed', explanation: 'The HTTPS certificate is expired. Do not continue to this website.', evidence: `Certificate for ${certificate.subject?.CN || hostname} expired on ${expiry.toISOString().slice(0, 10)}; issuer: ${certificate.issuer?.O || certificate.issuer?.CN || 'not provided'}.` }
    if (notYetValid) return { label: 'SSL certificate', status: 'failed', explanation: 'The HTTPS certificate is not valid yet.', evidence: `Certificate validity starts ${validFrom.toISOString().slice(0, 10)}; issuer: ${certificate.issuer?.O || certificate.issuer?.CN || 'not provided'}.` }
    const status: Status = daysRemaining < 14 ? 'warning' : 'passed'
    return { label: 'SSL certificate', status, explanation: status === 'passed' ? 'The HTTPS certificate was verified and is not close to expiry.' : 'The HTTPS certificate is close to expiry; do not treat HTTPS alone as proof of legitimacy.', evidence: `Certificate for ${certificate.subject?.CN || hostname} is valid through ${expiry.toISOString().slice(0, 10)} (${daysRemaining} days remaining); issuer: ${certificate.issuer?.O || certificate.issuer?.CN || 'not provided'}.` }
  } catch (error) {
    const code = error && typeof error === 'object' && 'code' in error ? String(error.code) : ''
    const message = error instanceof Error ? error.message : 'TLS verification failed.'
    console.error('[scan] SSL check failed', { hostname, code, error: message })
    if (code === 'CERT_HAS_EXPIRED') return { label: 'SSL certificate', status: 'failed', explanation: 'The HTTPS certificate is expired. Do not continue to this website.', evidence: 'TLS reported CERT_HAS_EXPIRED.' }
    if (code === 'ERR_TLS_CERT_ALTNAME_INVALID') return { label: 'SSL certificate', status: 'failed', explanation: 'The certificate does not match this hostname.', evidence: 'TLS reported a hostname mismatch.' }
    return unavailable('SSL certificate', 'The HTTPS certificate could not be verified from this environment.', message)
  }
}

async function checkUrlhaus(normalizedUrl: string): Promise<Indicator> {
  try {
    const body = new URLSearchParams({ url: normalizedUrl })
const urlhausHeaders: Record<string, string> = { 'Content-Type': 'application/x-www-form-urlencoded' }
  if (process.env.URLHAUS_AUTH_KEY) urlhausHeaders['Auth-Key'] = process.env.URLHAUS_AUTH_KEY
  const response = await withTimeout(fetch('https://urlhaus-api.abuse.ch/v1/url/', { method: 'POST', headers: urlhausHeaders, body, cache: 'no-store' }), 'URLhaus timed out.')
  if (!response.ok) return unavailable('Phishing detection', 'The malicious-URL database could not verify this URL.', `Provider URLhaus returned HTTP ${response.status}${process.env.URLHAUS_AUTH_KEY ? '.' : ' (no URLHAUS_AUTH_KEY is configured).'}`)
    const data = await response.json() as { query_status?: string; threat?: string; url_status?: string }
    if (data.query_status === 'no_results') return { label: 'Phishing detection', status: 'passed', explanation: 'The URL was not found in the checked malicious-URL database. This is not proof that it is safe.', evidence: 'URLhaus returned no matching record.' }
    if (data.query_status === 'ok') return { label: 'Phishing detection', status: 'failed', explanation: 'The URL appears in the checked malicious-URL database. Avoid entering credentials or payment details.', evidence: `URLhaus record: ${data.threat || 'threat listed'}; status ${data.url_status || 'unknown'}.` }
    return unavailable('Phishing detection', 'The malicious-URL database returned an inconclusive response.', `URLhaus status: ${data.query_status || 'unknown'}.`)
  } catch (error) {
    console.error('[scan] phishing database check failed', { error: error instanceof Error ? error.message : 'unknown error' })
    return unavailable('Phishing detection', 'The malicious-URL database was unavailable.', error instanceof Error ? error.message : 'URLhaus request failed.')
  }
}

async function checkReputation(normalizedUrl: string): Promise<Indicator> {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY
  if (!apiKey) return unavailable('Website reputation', 'No reputation provider is configured for this environment.', 'Google Safe Browsing verification is unavailable.')
  try {
    const response = await withTimeout(fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey)}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ client: { clientId: 'findfake-ai', clientVersion: '1.0' }, threatInfo: { threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'], platformTypes: ['ANY_PLATFORM'], threatEntryTypes: ['URL'], threatEntries: [{ url: normalizedUrl }] } }), cache: 'no-store' }), 'Reputation check timed out.')
    if (!response.ok) return unavailable('Website reputation', 'The reputation provider could not verify this URL.', `Safe Browsing returned HTTP ${response.status}.`)
    const data = await response.json() as { matches?: Array<{ threatType?: string }> }
    if (data.matches?.length) return { label: 'Website reputation', status: 'failed', explanation: 'The reputation provider reported a threat match. Do not treat the website as trustworthy.', evidence: `Reported threat types: ${data.matches.map((match) => match.threatType || 'unknown').join(', ')}.` }
    return { label: 'Website reputation', status: 'passed', explanation: 'The configured reputation provider found no threat match. This is not a guarantee of safety.', evidence: 'No Safe Browsing threat match was returned.' }
  } catch (error) {
    console.error('[scan] reputation check failed', { error: error instanceof Error ? error.message : 'unknown error' })
    return unavailable('Website reputation', 'The reputation provider was unavailable.', error instanceof Error ? error.message : 'Reputation request failed.')
  }
}

function matchesDomainBoundary(hostname: string, domain: string) {
  return hostname === domain || hostname.endsWith(`.${domain}`)
}

function checkTrustedBrand(hostname: string, registrable: string): Indicator {
  const approvedMatch = TRUSTED_BRANDS
    .flatMap((brand) => brand.approvedDomains.map((domain) => ({ brand, domain })))
    .filter(({ domain }) => matchesDomainBoundary(hostname, domain))
    .sort((left, right) => right.domain.length - left.domain.length)[0]

  if (approvedMatch) {
    const scope = hostname === approvedMatch.domain ? 'exact official-domain match' : `approved subdomain of ${approvedMatch.domain}`
    return {
      label: 'Trusted brand reputation',
      status: 'passed',
      explanation: `${approvedMatch.brand.name} is listed in the editable trusted-brand registry, but provider warnings still take precedence.`,
      evidence: `Verified ${approvedMatch.brand.name} ${scope}; primary domain: ${approvedMatch.brand.primaryDomain}.`,
    }
  }

  const lookalike = TRUSTED_BRANDS
    .flatMap((brand) => brand.approvedDomains.map((domain) => ({ brand, domain })))
    .map(({ brand, domain }) => ({ brand, domain, distance: levenshtein(registrable, domain) }))
    .filter(({ distance }) => distance > 0 && distance <= 2)
    .sort((left, right) => left.distance - right.distance)[0]

  if (lookalike) {
    return {
      label: 'Trusted brand reputation',
      status: 'warning',
      explanation: `This domain resembles ${lookalike.brand.name}, but it is not an approved official domain. Treat it as a possible impersonation attempt.`,
      evidence: `No official match for ${registrable}; closest registered brand domain: ${lookalike.domain} (edit distance ${lookalike.distance}).`,
    }
  }

  return {
    label: 'Trusted brand reputation',
    status: 'unavailable',
    explanation: 'Unknown — this domain is not in the trusted-brand registry. Live threat-intelligence checks remain authoritative.',
    evidence: `No approved brand domain matched ${hostname}; absence from the registry is not a threat finding.`,
  }
}

function analyzeUrl(parsed: ParsedUrl): Indicator {
  const { url, hostname, registrable } = parsed
  const labels = hostname.split('.')
  const brandMatch = COMMON_BRANDS.find((brand) => {
    const base = brand.split('.')[0]
    const hostBase = registrable.split('.')[0]
    return hostBase !== base && levenshtein(hostBase, base) <= 2
  })
  const misleadingSubdomain = labels.length > registrable.split('.').length && COMMON_BRANDS.some((brand) => labels.slice(0, -registrable.split('.').length).join('.').toLowerCase().includes(brand.split('.')[0]))
  const suspiciousWords = /(login|verify|account|secure|update|password|wallet|claim|bonus|free|billing)/i.test(`${hostname}${url.pathname}${url.search}`)
  const suspiciousPath = url.pathname.length > 180 || url.search.length > 500 || url.href.length > 500
  const hasEncodedTricks = /%[0-9a-f]{2}/i.test(url.pathname + url.search) || /[\\@]/.test(url.pathname + url.search)
  const unicode = /[^\x00-\x7F]/.test(hostname) || hostname.includes('xn--')
  const suspicious = brandMatch || misleadingSubdomain || suspiciousWords || suspiciousPath || hasEncodedTricks || unicode
  const evidence = [brandMatch && `close brand spelling to ${brandMatch}`, misleadingSubdomain && 'brand-like subdomain', suspiciousWords && 'sensitive or urgency words', suspiciousPath && 'unusually long path', hasEncodedTricks && 'encoded or escape characters', unicode && 'Unicode or punycode hostname'].filter(Boolean).join('; ')
  return { label: 'URL analysis', status: suspicious ? 'warning' : 'passed', explanation: suspicious ? 'The URL contains patterns that can appear in deceptive links. Review the exact domain before continuing.' : 'No common suspicious words, misspellings, symbols, or unusual domain patterns were detected.', evidence: evidence || `Analyzed ${url.href.length} URL characters and the ${registrable} registrable domain.` }
}

async function scanUrl(input: string) {
  const parsed = parseUrl(input)
  const indicators = await Promise.all([
    checkDomainAge(parsed.registrable),
    checkSsl(parsed.hostname, parsed.url.protocol),
    checkUrlhaus(parsed.url.toString()),
    analyzeUrl(parsed),
    checkTrustedBrand(parsed.hostname, parsed.registrable),
    checkReputation(parsed.url.toString()),
  ])
  const failed = indicators.filter((item) => item.status === 'failed').length
  const meaningfulWarnings = indicators.filter((item) => item.status === 'warning' && item.label !== 'SSL certificate').length
  const hasSslWarning = indicators.some((item) => item.label === 'SSL certificate' && item.status === 'warning')
  const unavailableCount = indicators.filter((item) => item.status === 'unavailable').length
  const risk = failed > 0 ? 'High concern' : meaningfulWarnings > 0 ? 'Medium concern' : hasSslWarning || unavailableCount > 0 ? 'Inconclusive' : 'Low concern'
  return { normalizedUrl: parsed.url.toString(), risk, indicators, note: 'These checks combine available registration, certificate, database, URL-pattern, and reputation evidence. A passed or unavailable check does not prove that a website is safe.' }
}

export async function POST(request: Request) {
  try {
    const body = await request.json()
    if (typeof body?.url !== 'string') return NextResponse.json({ error: 'Enter a website URL.' }, { status: 400 })
    return NextResponse.json(await scanUrl(body.url))
  } catch (error) {
    return NextResponse.json({ error: error instanceof Error ? error.message : 'Unable to scan this URL.' }, { status: 400 })
  }
}
