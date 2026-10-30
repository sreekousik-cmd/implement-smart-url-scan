export type HistoryScanType = "url_scan" | "visual_comparison" | "ocr"

export type HistoryRecord = {
  id: string
  scanType: HistoryScanType
  scanDate: string
  target: string | null
  riskCategory: string
  confidenceLevel: string
  finalReport: string
  findings: Record<string, unknown>
}

export async function saveHistory(record: Omit<HistoryRecord, "id" | "scanDate">) {
  const response = await fetch("/api/history", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(record),
  })
  if (!response.ok) throw new Error("Unable to save scan history")
  return response.json() as Promise<{ record: HistoryRecord }>
}
