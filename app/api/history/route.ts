import { and, desc, eq } from "drizzle-orm"
import { cookies } from "next/headers"
import { NextResponse } from "next/server"
import { randomUUID } from "node:crypto"
import { db } from "@/lib/db"
import { scanHistory } from "@/lib/db/schema"

const COOKIE_NAME = "findfake_visitor"
const allowedTypes = new Set(["url_scan", "visual_comparison", "ocr"])

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
  const type = new URL(request.url).searchParams.get("type")
  const rows = await db
    .select()
    .from(scanHistory)
    .where(type && allowedTypes.has(type) ? and(eq(scanHistory.visitorId, visitorId), eq(scanHistory.scanType, type)) : eq(scanHistory.visitorId, visitorId))
    .orderBy(desc(scanHistory.scanDate))
    .limit(100)

  return withVisitorCookie(NextResponse.json({ records: rows }), visitorId, shouldSet)
}

export async function POST(request: Request) {
  const { id: visitorId, shouldSet } = await getVisitorId()
  const body = await request.json()
  if (!allowedTypes.has(body.scanType) || typeof body.finalReport !== "string" || typeof body.riskCategory !== "string" || typeof body.confidenceLevel !== "string") {
    return NextResponse.json({ error: "Invalid history record" }, { status: 400 })
  }

  const [record] = await db.insert(scanHistory).values({
    visitorId,
    scanType: body.scanType,
    target: typeof body.target === "string" ? body.target.slice(0, 2048) : null,
    riskCategory: body.riskCategory.slice(0, 80),
    confidenceLevel: body.confidenceLevel.slice(0, 80),
    finalReport: body.finalReport.slice(0, 20000),
    findings: body.findings && typeof body.findings === "object" ? body.findings : {},
  }).returning()

  return withVisitorCookie(NextResponse.json({ record }, { status: 201 }), visitorId, shouldSet)
}

export async function DELETE(request: Request) {
  const { id: visitorId } = await getVisitorId()
  const id = new URL(request.url).searchParams.get("id")
  if (!id) return NextResponse.json({ error: "Missing record id" }, { status: 400 })
  await db.delete(scanHistory).where(and(eq(scanHistory.id, id), eq(scanHistory.visitorId, visitorId)))
  return NextResponse.json({ ok: true })
}
