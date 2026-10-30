import { desc, eq } from "drizzle-orm"
import { cookies } from "next/headers"
import { NextResponse } from "next/server"
import { randomUUID } from "node:crypto"
import { db } from "@/lib/db"
import { scanHistory } from "@/lib/db/schema"

const COOKIE_NAME = "findfake_visitor"
const MAX_RECENT = 100

async function getVisitorId() {
  const cookieStore = await cookies()
  const existing = cookieStore.get(COOKIE_NAME)?.value
  return { id: existing ?? randomUUID(), shouldSet: !existing }
}

export async function GET() {
  const { id: visitorId, shouldSet } = await getVisitorId()

  try {
    const records = await db
      .select()
      .from(scanHistory)
      .where(eq(scanHistory.visitorId, visitorId))
      .orderBy(desc(scanHistory.scanDate))
      .limit(MAX_RECENT)

    const totals = {
      totalScans: records.filter((record) => record.scanType === "url_scan").length,
      visualComparisons: records.filter((record) => record.scanType === "visual_comparison").length,
      suspiciousDetected: records.filter((record) => /high|medium|suspicious/i.test(record.riskCategory)).length,
      highRisk: records.filter((record) => /high/i.test(record.riskCategory)).length,
    }

    const riskCounts = records.reduce<Record<string, number>>((counts, record) => {
      const key = record.riskCategory.toLowerCase().includes("high")
        ? "High"
        : record.riskCategory.toLowerCase().includes("medium")
          ? "Medium"
          : record.riskCategory.toLowerCase().includes("low")
            ? "Low"
            : "Inconclusive"
      counts[key] = (counts[key] ?? 0) + 1
      return counts
    }, { Low: 0, Medium: 0, High: 0, Inconclusive: 0 })

    const dailyCounts = records.reduce<Record<string, number>>((counts, record) => {
      const day = new Date(record.scanDate).toISOString().slice(0, 10)
      counts[day] = (counts[day] ?? 0) + 1
      return counts
    }, {})

    const response = NextResponse.json({
      totals,
      riskCounts,
      dailyCounts,
      recent: records.slice(0, 8),
    })

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
  } catch (error) {
    console.error("[dashboard] Failed to load dashboard data", error instanceof Error ? error.message : "Unknown database error")
    return NextResponse.json({ error: "Dashboard data is temporarily unavailable." }, { status: 503 })
  }
}
