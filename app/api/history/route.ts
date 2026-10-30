import { and, desc, eq, gte, lte } from "drizzle-orm"
import { cookies } from "next/headers"
import { NextResponse } from "next/server"
import { randomUUID } from "node:crypto"
import { db } from "@/lib/db"
import { scanHistory } from "@/lib/db/schema"

const COOKIE_NAME = "findfake_visitor"
const allowedTypes = new Set(["url_scan", "website_reputation", "domain_age", "ssl_certificate", "malicious_url_database", "url_pattern_analysis", "visual_comparison", "ocr"])

async function getVisitorId() {
  const cookieStore = await cookies()
  const existing = cookieStore.get(COOKIE_NAME)?.value
  return { id: existing ?? randomUUID(), shouldSet: !existing }
}

function withVisitorCookie(response: NextResponse, visitorId: string, shouldSet: boolean) {
  if (shouldSet) {
    response.cookies.set(COOKIE_NAME, visitorId, {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 60 * 60 * 24 * 365,
      path: "/",
    })
  }
  return response
}

export async function GET(request: Request) {
  const { id: visitorId, shouldSet } = await getVisitorId()
  const params = new URL(request.url).searchParams
  const type = params.get("type")
  const from = params.get("from")
  const to = params.get("to")
  const filters = [eq(scanHistory.visitorId, visitorId)]
  if (type && allowedTypes.has(type)) filters.push(eq(scanHistory.scanType, type))
  if (from && !Number.isNaN(Date.parse(from))) filters.push(gte(scanHistory.scanDate, new Date(`${from}T00:00:00.000Z`)))
  if (to && !Number.isNaN(Date.parse(to))) filters.push(lte(scanHistory.scanDate, new Date(`${to}T23:59:59.999Z`)))

  try {
    const rows = await db
      .select()
      .from(scanHistory)
      .where(and(...filters))
      .orderBy(desc(scanHistory.scanDate))
      .limit(100)

    return withVisitorCookie(NextResponse.json({ records: rows }), visitorId, shouldSet)
  } catch (error) {
    console.error("[v0] History load failed", { message: error instanceof Error ? error.message : "Unknown database error" })
    return withVisitorCookie(NextResponse.json({ error: "Scan history is temporarily unavailable." }, { status: 503 }), visitorId, shouldSet)
  }
}

export async function POST(request: Request) {
  const { id: visitorId, shouldSet } = await getVisitorId()

  try {
    const body = await request.json()
    if (!allowedTypes.has(body.scanType) || typeof body.finalReport !== "string" || typeof body.riskCategory !== "string" || typeof body.confidenceLevel !== "string") {
      return NextResponse.json({ error: "Invalid history record" }, { status: 400 })
    }

    const requestId = typeof body.requestId === "string" ? body.requestId.slice(0, 120) : null
    const [record] = await db.insert(scanHistory).values({
      visitorId,
      requestId,
      scanType: body.scanType,
      target: typeof body.target === "string" ? body.target.slice(0, 2048) : null,
      riskCategory: body.riskCategory.slice(0, 80),
      confidenceLevel: body.confidenceLevel.slice(0, 80),
      finalReport: body.finalReport.slice(0, 20000),
      findings: body.findings && typeof body.findings === "object" ? body.findings : {},
    }).onConflictDoNothing().returning()
    const existing = record || (requestId ? (await db.select().from(scanHistory).where(and(eq(scanHistory.visitorId, visitorId), eq(scanHistory.scanType, body.scanType), eq(scanHistory.requestId, requestId))).limit(1))[0] : undefined)

    return withVisitorCookie(NextResponse.json({ record: existing }, { status: record ? 201 : 200 }), visitorId, shouldSet)
  } catch (error) {
    console.error("[v0] History save failed", { message: error instanceof Error ? error.message : "Unknown database error" })
    return withVisitorCookie(NextResponse.json({ error: "This report could not be saved to scan history." }, { status: 503 }), visitorId, shouldSet)
  }
}

export async function DELETE(request: Request) {
  const { id: visitorId } = await getVisitorId()
  const id = new URL(request.url).searchParams.get("id")
  if (!id) return NextResponse.json({ error: "Missing record id" }, { status: 400 })
  await db.delete(scanHistory).where(and(eq(scanHistory.id, id), eq(scanHistory.visitorId, visitorId)))
  return NextResponse.json({ ok: true })
}
