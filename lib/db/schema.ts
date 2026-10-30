import { jsonb, pgTable, text, timestamp, uuid } from "drizzle-orm/pg-core"

export const scanHistory = pgTable("scan_history", {
  id: uuid("id").defaultRandom().primaryKey(),
  visitorId: text("visitor_id").notNull(),
  scanType: text("scan_type").notNull(),
  scanDate: timestamp("scan_date", { withTimezone: true }).notNull().defaultNow(),
  target: text("target"),
  riskCategory: text("risk_category").notNull(),
  confidenceLevel: text("confidence_level").notNull(),
  finalReport: text("final_report").notNull(),
  findings: jsonb("findings").notNull().default({}),
})
