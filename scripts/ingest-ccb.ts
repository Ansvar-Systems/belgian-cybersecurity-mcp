/**
 * CCB Ingestion Crawler
 *
 * Scrapes the CCB (Centre for Cybersecurity Belgium) website and CERT.be
 * advisories to populate the SQLite database with real guidance documents,
 * security advisories, and framework metadata.
 *
 * Data sources:
 *   1. CERT.be / CCB security advisories — paginated listing at ccb.belgium.be/advisories
 *   2. CCB guidelines & regulation pages — NIS2, CRA, CySoA, CVD sub-pages
 *   3. Safeonweb@work resources — CyberFundamentals, policy templates, guides
 *   4. CCB news — cybersecurity strategy, threat reports, operational updates
 *
 * Content languages: English (primary crawl), with French and Dutch variants
 * linked where available.
 *
 * Usage:
 *   npx tsx scripts/ingest-ccb.ts                   # full crawl
 *   npx tsx scripts/ingest-ccb.ts --resume           # resume from last checkpoint
 *   npx tsx scripts/ingest-ccb.ts --dry-run          # log what would be inserted
 *   npx tsx scripts/ingest-ccb.ts --force             # drop and recreate DB first
 *   npx tsx scripts/ingest-ccb.ts --advisories-only   # only crawl advisories
 *   npx tsx scripts/ingest-ccb.ts --guidance-only     # only crawl guidance/resources
 */

import Database from "better-sqlite3";
import * as cheerio from "cheerio";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import { SCHEMA_SQL } from "../src/db.js";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const DB_PATH = process.env["CCB_DB_PATH"] ?? "data/ccb.db";
const PROGRESS_FILE = resolve(dirname(DB_PATH), "ingest-progress.json");

const CCB_BASE = "https://ccb.belgium.be";
const SAFEONWEB_BASE = "https://atwork.safeonweb.be";

const RATE_LIMIT_MS = 1500;
const MAX_RETRIES = 3;
const RETRY_BACKOFF_MS = 2000;
const USER_AGENT =
  "AnsvarCCBCrawler/1.0 (+https://ansvar.eu; compliance research)";

// CLI flags
const args = process.argv.slice(2);
const force = args.includes("--force");
const dryRun = args.includes("--dry-run");
const resume = args.includes("--resume");
const advisoriesOnly = args.includes("--advisories-only");
const guidanceOnly = args.includes("--guidance-only");

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface GuidanceRow {
  reference: string;
  title: string;
  title_en: string | null;
  date: string | null;
  type: string;
  series: string;
  summary: string;
  full_text: string;
  topics: string;
  status: string;
}

interface AdvisoryRow {
  reference: string;
  title: string;
  date: string | null;
  severity: string | null;
  affected_products: string | null;
  summary: string;
  full_text: string;
  cve_references: string | null;
}

interface FrameworkRow {
  id: string;
  name: string;
  name_en: string | null;
  description: string;
  document_count: number;
}

interface Progress {
  completed_advisory_slugs: string[];
  completed_guidance_urls: string[];
  completed_news_slugs: string[];
  advisory_pages_done: number;
  last_updated: string;
}

// ---------------------------------------------------------------------------
// Utility: rate-limited fetch with retry
// ---------------------------------------------------------------------------

let lastRequestTime = 0;
let totalRequests = 0;

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

async function rateLimitedFetch(
  url: string,
  opts?: RequestInit,
): Promise<Response> {
  const now = Date.now();
  const elapsed = now - lastRequestTime;
  if (elapsed < RATE_LIMIT_MS) {
    await sleep(RATE_LIMIT_MS - elapsed);
  }

  let lastError: Error | null = null;
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      lastRequestTime = Date.now();
      totalRequests++;
      const resp = await fetch(url, {
        headers: {
          "User-Agent": USER_AGENT,
          Accept:
            "text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8",
        },
        redirect: "follow",
        signal: AbortSignal.timeout(30_000),
        ...opts,
      });
      if (!resp.ok) {
        throw new Error(`HTTP ${resp.status} for ${url}`);
      }
      return resp;
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err));
      console.warn(
        `  [retry ${attempt}/${MAX_RETRIES}] ${url}: ${lastError.message}`,
      );
      if (attempt < MAX_RETRIES) {
        await sleep(RETRY_BACKOFF_MS * attempt);
      }
    }
  }
  throw lastError!;
}

async function fetchHtml(url: string): Promise<string> {
  const resp = await rateLimitedFetch(url);
  return resp.text();
}

// ---------------------------------------------------------------------------
// HTML parsing helpers (cheerio-based)
// ---------------------------------------------------------------------------

/**
 * Strip HTML tags and normalise whitespace to plain text.
 */
function htmlToText(html: string): string {
  const $ = cheerio.load(html);
  $("script, style, nav, footer, header").remove();
  return $.text().replace(/[ \t]+/g, " ").replace(/\n{3,}/g, "\n\n").trim();
}

/**
 * Parse a DD/MM/YYYY or DD.MM.YYYY date into ISO YYYY-MM-DD.
 */
function parseDate(raw: string): string | null {
  const m = raw.match(/(\d{1,2})[./](\d{1,2})[./](\d{4})/);
  if (!m) return null;
  const day = m[1]!.padStart(2, "0");
  const month = m[2]!.padStart(2, "0");
  const year = m[3]!;
  return `${year}-${month}-${day}`;
}

/**
 * Derive severity from CVSS score or title keywords.
 * CCB advisories do not carry an explicit severity label; we infer from
 * CVSS scores found in the body text and title urgency cues.
 */
function deriveSeverity(title: string, bodyText: string): string {
  // Look for CVSS scores in the text
  const cvssMatches = bodyText.match(/CVSS\s*[:=]?\s*([\d.]+)/gi);
  if (cvssMatches) {
    let maxScore = 0;
    for (const m of cvssMatches) {
      const score = parseFloat(m.replace(/CVSS\s*[:=]?\s*/i, ""));
      if (!isNaN(score) && score > maxScore) maxScore = score;
    }
    if (maxScore >= 9.0) return "critical";
    if (maxScore >= 7.0) return "high";
    if (maxScore >= 4.0) return "medium";
    if (maxScore > 0) return "low";
  }

  // Infer from title keywords
  const lower = title.toLowerCase();
  if (lower.includes("critical") || lower.includes("zero-day")) return "critical";
  if (lower.includes("high") || lower.includes("actively exploited")) return "high";
  if (lower.includes("medium") || lower.includes("moderate")) return "medium";
  if (lower.includes("low")) return "low";

  return "medium"; // default when no signal available
}

/**
 * Extract CVE references from text content.
 */
function extractCves(text: string): string | null {
  // Match CVE-YYYY-NNNNN patterns (including en-dash variants)
  const cves = new Set<string>();
  const re = /CVE[\u2010\u2011\u2012\u2013\u2014-]\d{4}[\u2010\u2011\u2012\u2013\u2014-]\d{4,}/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    // Normalise dashes to hyphens
    cves.add(m[0].replace(/[\u2010\u2011\u2012\u2013\u2014]/g, "-").toUpperCase());
  }
  return cves.size > 0 ? [...cves].sort().join(", ") : null;
}

/**
 * Generate a stable reference ID from an advisory slug.
 * Converts e.g. "warning-microsoft-patch-tuesday-march-2026" into "CERT.be-warning-microsoft-patch-tuesday-march-2026".
 */
function advisorySlugToReference(slug: string): string {
  return `CERT.be-${slug}`;
}

/**
 * Generate a stable reference ID from a guidance URL path.
 */
function guidanceUrlToReference(urlPath: string): string {
  const slug = urlPath
    .replace(/^\/+/, "")
    .replace(/\/+/g, "-")
    .replace(/[^a-zA-Z0-9_-]/g, "");
  return `CCB-${slug}`;
}

// ---------------------------------------------------------------------------
// Progress tracking
// ---------------------------------------------------------------------------

function loadProgress(): Progress {
  if (resume && existsSync(PROGRESS_FILE)) {
    try {
      const raw = readFileSync(PROGRESS_FILE, "utf-8");
      const p = JSON.parse(raw) as Progress;
      console.log(
        `Resuming from checkpoint (${p.last_updated}): ` +
          `${p.completed_advisory_slugs.length} advisories, ` +
          `${p.completed_guidance_urls.length} guidance docs, ` +
          `${p.completed_news_slugs.length} news articles, ` +
          `advisory pages done: ${p.advisory_pages_done}`,
      );
      return p;
    } catch {
      console.warn("Could not parse progress file, starting fresh");
    }
  }
  return {
    completed_advisory_slugs: [],
    completed_guidance_urls: [],
    completed_news_slugs: [],
    advisory_pages_done: 0,
    last_updated: new Date().toISOString(),
  };
}

function saveProgress(progress: Progress): void {
  progress.last_updated = new Date().toISOString();
  writeFileSync(PROGRESS_FILE, JSON.stringify(progress, null, 2));
}

// ---------------------------------------------------------------------------
// Advisory crawling
// ---------------------------------------------------------------------------

interface AdvisoryListItem {
  slug: string;
  title: string;
  date: string | null;
  url: string;
}

/**
 * Parse the advisory listing page and extract advisory card entries.
 */
function parseAdvisoryListPage(html: string): AdvisoryListItem[] {
  const $ = cheerio.load(html);
  const items: AdvisoryListItem[] = [];

  // Each advisory on the listing appears as a teaser/card with a link
  // The structure uses article or div teasers with an <a> linking to /advisories/SLUG
  $('a[href*="/advisories/"]').each((_i, el) => {
    const href = $(el).attr("href");
    if (!href || href === "/advisories" || href.includes("?")) return;

    const slug = href.replace(/.*\/advisories\//, "").replace(/\/$/, "");
    if (!slug || slug.includes("/")) return;

    const title = $(el).text().trim();
    if (!title || title.length < 10) return;

    // Try to find date near this element — look at parent/sibling text
    let date: string | null = null;
    const parentText = $(el).parent().parent().text();
    const dateMatch = parentText.match(/(\d{1,2})[./](\d{1,2})[./](\d{4})/);
    if (dateMatch) {
      date = parseDate(dateMatch[0]);
    }

    // Avoid duplicates within the same page
    if (!items.some((it) => it.slug === slug)) {
      items.push({
        slug,
        title,
        date,
        url: `${CCB_BASE}/advisories/${slug}`,
      });
    }
  });

  return items;
}

/**
 * Determine total number of advisory pages from the pagination.
 */
function parseAdvisoryPageCount(html: string): number {
  const $ = cheerio.load(html);
  let maxPage = 1;

  // Pagination uses ?page=N links. The "Last page" link has the highest number.
  $('a[href*="?page="]').each((_i, el) => {
    const href = $(el).attr("href") ?? "";
    const m = href.match(/[?&]page=(\d+)/);
    if (m) {
      const p = parseInt(m[1]!, 10) + 1; // page param is 0-indexed
      if (p > maxPage) maxPage = p;
    }
  });

  return maxPage;
}

/**
 * Fetch and parse a single advisory detail page.
 */
async function fetchAdvisoryDetail(
  item: AdvisoryListItem,
): Promise<AdvisoryRow | null> {
  try {
    const html = await fetchHtml(item.url);
    const $ = cheerio.load(html);

    // Remove navigation, header, footer cruft
    $("nav, header, footer, script, style, .breadcrumb").remove();

    // Extract the main content area
    const mainContent =
      $("main").html() ??
      $("article").html() ??
      $(".node__content").html() ??
      $('[role="main"]').html() ??
      "";

    const bodyText = htmlToText(mainContent);
    if (bodyText.length < 50) {
      console.warn(`  Skipping ${item.slug}: body too short (${bodyText.length} chars)`);
      return null;
    }

    // Title: prefer h1, fall back to listing title
    const title =
      $("h1").first().text().trim() || item.title;

    // Date: look for "Published : DD/MM/YYYY" pattern in page text
    let date = item.date;
    const publishedMatch = bodyText.match(
      /Published\s*:?\s*(\d{1,2}[./]\d{1,2}[./]\d{4})/i,
    );
    if (publishedMatch) {
      date = parseDate(publishedMatch[1]!) ?? date;
    }

    // Affected products: look for "Affected software" line
    let affectedProducts: string | null = null;
    const affectedMatch = bodyText.match(
      /Affected\s+(?:software|products?|systems?)\s*:?\s*[→\-:]?\s*(.+?)(?:\n|Published|Last update)/is,
    );
    if (affectedMatch) {
      affectedProducts = affectedMatch[1]!.trim().slice(0, 2000);
    }

    // CVEs
    const cveReferences = extractCves(bodyText);

    // Severity
    const severity = deriveSeverity(title, bodyText);

    // Summary: extract from the "Risks" section or first substantial paragraph
    let summary = "";
    const risksSection = bodyText.match(
      /(?:^|\n)\s*Risks?\s*\n([\s\S]*?)(?:\n\s*(?:Description|Recommended|Sources|References)\s*\n|$)/i,
    );
    if (risksSection) {
      summary = risksSection[1]!.trim().slice(0, 1000);
    } else {
      // First 500 chars of body as fallback
      summary = bodyText.slice(0, 500).trim();
    }

    return {
      reference: advisorySlugToReference(item.slug),
      title,
      date,
      severity,
      affected_products: affectedProducts,
      summary,
      full_text: bodyText,
      cve_references: cveReferences,
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`  Failed to fetch advisory ${item.slug}: ${msg}`);
    return null;
  }
}

/**
 * Crawl all advisory pages and insert into the database.
 */
async function crawlAdvisories(
  db: Database.Database,
  progress: Progress,
): Promise<number> {
  console.log("\n=== Crawling CCB/CERT.be Advisories ===\n");

  const insertStmt = db.prepare(
    `INSERT OR REPLACE INTO advisories
       (reference, title, date, severity, affected_products, summary, full_text, cve_references)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  );

  // Fetch first page to determine total pages
  const firstPageUrl = `${CCB_BASE}/advisories`;
  console.log(`Fetching advisory listing: ${firstPageUrl}`);
  const firstHtml = await fetchHtml(firstPageUrl);
  const totalPages = parseAdvisoryPageCount(firstHtml);
  console.log(`Found ${totalPages} advisory pages to crawl`);

  let inserted = 0;
  let skipped = 0;
  const startPage = resume ? progress.advisory_pages_done : 0;

  for (let page = startPage; page < totalPages; page++) {
    const pageUrl =
      page === 0 ? firstPageUrl : `${firstPageUrl}?page=${page}`;
    console.log(`\n--- Advisory page ${page + 1}/${totalPages} ---`);

    let listHtml: string;
    if (page === 0) {
      listHtml = firstHtml;
    } else {
      try {
        listHtml = await fetchHtml(pageUrl);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error(`Failed to fetch page ${page}: ${msg}. Continuing.`);
        continue;
      }
    }

    const items = parseAdvisoryListPage(listHtml);
    console.log(`  Found ${items.length} advisories on page ${page + 1}`);

    for (const item of items) {
      if (progress.completed_advisory_slugs.includes(item.slug)) {
        skipped++;
        continue;
      }

      const advisory = await fetchAdvisoryDetail(item);
      if (!advisory) {
        skipped++;
        continue;
      }

      if (dryRun) {
        console.log(
          `  [dry-run] Would insert: ${advisory.reference} — ${advisory.title.slice(0, 80)}`,
        );
      } else {
        insertStmt.run(
          advisory.reference,
          advisory.title,
          advisory.date,
          advisory.severity,
          advisory.affected_products,
          advisory.summary,
          advisory.full_text,
          advisory.cve_references,
        );
        console.log(
          `  Inserted: ${advisory.reference} (${advisory.severity ?? "?"}) — ${advisory.title.slice(0, 70)}`,
        );
      }

      inserted++;
      progress.completed_advisory_slugs.push(item.slug);

      // Save progress periodically (every 10 advisories)
      if (inserted % 10 === 0) {
        progress.advisory_pages_done = page;
        saveProgress(progress);
      }
    }

    progress.advisory_pages_done = page + 1;
    saveProgress(progress);
  }

  console.log(
    `\nAdvisories complete: ${inserted} inserted, ${skipped} skipped`,
  );
  return inserted;
}

// ---------------------------------------------------------------------------
// Guidance crawling — CCB regulation pages + Safeonweb@work resources
// ---------------------------------------------------------------------------

/**
 * Static list of known CCB guidance page URLs to crawl.
 * These are the structured content pages on ccb.belgium.be and
 * atwork.safeonweb.be that contain cybersecurity guidance, regulation
 * summaries, and technical resources.
 */
const GUIDANCE_SOURCES: Array<{
  url: string;
  type: string;
  series: string;
  topics: string[];
}> = [
  // --- CCB Regulation pages ---
  {
    url: `${CCB_BASE}/regulation/nis2`,
    type: "nis2_guide",
    series: "NIS2",
    topics: ["NIS2", "regulation", "compliance", "Belgium"],
  },
  {
    url: `${CCB_BASE}/regulation/cyber-solidarity-act`,
    type: "regulation_guide",
    series: "EU Regulation",
    topics: ["CySoA", "EU", "solidarity", "incident response"],
  },
  {
    url: `${CCB_BASE}/regulation/cra`,
    type: "regulation_guide",
    series: "EU Regulation",
    topics: ["CRA", "Cyber Resilience Act", "product security", "EU"],
  },
  {
    url: `${CCB_BASE}/regulation/cvdp`,
    type: "procedure",
    series: "CCB",
    topics: ["CVD", "vulnerability disclosure", "responsible disclosure"],
  },
  // --- CCB operational pages ---
  {
    url: `${CCB_BASE}/cert`,
    type: "organisational",
    series: "CERT.be",
    topics: ["CERT.be", "CSIRT", "incident response", "Belgium"],
  },
  {
    url: `${CCB_BASE}/cytris`,
    type: "organisational",
    series: "CCB",
    topics: ["CyTRIS", "threat intelligence", "information sharing"],
  },
  {
    url: `${CCB_BASE}/ncca`,
    type: "regulation_guide",
    series: "EU Regulation",
    topics: ["CSA", "Cybersecurity Act", "certification", "ENISA"],
  },
  {
    url: `${CCB_BASE}/vital-sectors`,
    type: "nis2_guide",
    series: "NIS2",
    topics: ["critical infrastructure", "vital sectors", "NIS2"],
  },
  // --- Safeonweb@work resources ---
  {
    url: `${SAFEONWEB_BASE}/tools-resources/cyberfundamentals-framework`,
    type: "framework_guide",
    series: "CyberFundamentals",
    topics: ["CyberFundamentals", "CyFun", "framework", "certification", "NIS2"],
  },
  {
    url: `${SAFEONWEB_BASE}/tools-resources/nis-2-quickstart-guide`,
    type: "nis2_guide",
    series: "NIS2",
    topics: ["NIS2", "quickstart", "compliance", "7 steps"],
  },
  {
    url: `${SAFEONWEB_BASE}/tools-resources/self-assessment`,
    type: "assessment_tool",
    series: "CyberFundamentals",
    topics: ["self-assessment", "maturity", "CyberFundamentals"],
  },
  {
    url: `${SAFEONWEB_BASE}/tools-resources/coordinated-vulnerability-disclosure-policy`,
    type: "procedure",
    series: "CCB",
    topics: ["CVD", "vulnerability disclosure", "policy"],
  },
  {
    url: `${SAFEONWEB_BASE}/tools-resources/policy-templates`,
    type: "policy_template",
    series: "CyberFundamentals",
    topics: ["policy", "templates", "security policy", "baseline"],
  },
  // --- Safeonweb@work threat-specific guides ---
  {
    url: `${SAFEONWEB_BASE}/tools-resources/ransomware`,
    type: "threat_guide",
    series: "Safeonweb",
    topics: ["ransomware", "malware", "incident response"],
  },
  {
    url: `${SAFEONWEB_BASE}/tools-resources/phishing-do-not-take-bait`,
    type: "threat_guide",
    series: "Safeonweb",
    topics: ["phishing", "social engineering", "awareness"],
  },
  {
    url: `${SAFEONWEB_BASE}/tools-resources/website-defacement`,
    type: "threat_guide",
    series: "Safeonweb",
    topics: ["defacement", "web security", "incident response"],
  },
  {
    url: `${SAFEONWEB_BASE}/tools-resources/fake-wire-transfer-scam`,
    type: "threat_guide",
    series: "Safeonweb",
    topics: ["BEC", "wire fraud", "social engineering"],
  },
  // --- Safeonweb@work best-practice guides ---
  {
    url: `${SAFEONWEB_BASE}/tools-resources/strong-password-protect-valuable-information`,
    type: "technical_guideline",
    series: "Safeonweb",
    topics: ["passwords", "authentication", "access control"],
  },
  {
    url: `${SAFEONWEB_BASE}/tools-resources/how-manage-updates`,
    type: "technical_guideline",
    series: "Safeonweb",
    topics: ["patching", "updates", "vulnerability management"],
  },
  {
    url: `${SAFEONWEB_BASE}/tools-resources/antivirus-software`,
    type: "technical_guideline",
    series: "Safeonweb",
    topics: ["antivirus", "endpoint protection", "malware"],
  },
  {
    url: `${SAFEONWEB_BASE}/tools-resources/protect-your-mobile-devices`,
    type: "technical_guideline",
    series: "Safeonweb",
    topics: ["mobile security", "BYOD", "device management"],
  },
  {
    url: `${SAFEONWEB_BASE}/tools-resources/separate-professional-and-personal-usage`,
    type: "technical_guideline",
    series: "Safeonweb",
    topics: ["BYOD", "separation", "data protection"],
  },
  {
    url: `${SAFEONWEB_BASE}/tools-resources/social-media-security`,
    type: "technical_guideline",
    series: "Safeonweb",
    topics: ["social media", "privacy", "awareness"],
  },
  {
    url: `${SAFEONWEB_BASE}/tools-resources/cyber-security-raise-your-peoples-awareness`,
    type: "awareness_guide",
    series: "Safeonweb",
    topics: ["awareness", "training", "human factor"],
  },
  {
    url: `${SAFEONWEB_BASE}/tools-resources/how-stay-vigilant-against-cyber-threats`,
    type: "awareness_guide",
    series: "Safeonweb",
    topics: ["threat awareness", "vigilance", "best practices"],
  },
  {
    url: `${SAFEONWEB_BASE}/tools-resources/quick-wins`,
    type: "technical_guideline",
    series: "Safeonweb",
    topics: ["quick wins", "baseline", "first steps"],
  },
  {
    url: `${SAFEONWEB_BASE}/tools-resources/cybersecurity-companies`,
    type: "awareness_guide",
    series: "Safeonweb",
    topics: ["SME", "companies", "cybersecurity basics"],
  },
  {
    url: `${SAFEONWEB_BASE}/tools-resources/cybersecurity-belgium`,
    type: "reference",
    series: "CCB",
    topics: ["Belgium", "ecosystem", "resources", "support"],
  },
  {
    url: `${SAFEONWEB_BASE}/tools-resources/cybersecurity-subsidies`,
    type: "reference",
    series: "CCB",
    topics: ["subsidies", "funding", "SME", "cyber voucher"],
  },
];

/**
 * Fetch and parse a single guidance page into a GuidanceRow.
 */
async function fetchGuidancePage(
  source: (typeof GUIDANCE_SOURCES)[number],
  progress: Progress,
): Promise<GuidanceRow | null> {
  if (progress.completed_guidance_urls.includes(source.url)) {
    return null; // already crawled
  }

  try {
    const html = await fetchHtml(source.url);
    const $ = cheerio.load(html);

    // Remove navigation cruft
    $("nav, header, footer, script, style, .breadcrumb, .menu").remove();

    const mainContent =
      $("main").html() ??
      $("article").html() ??
      $(".node__content").html() ??
      $('[role="main"]').html() ??
      $(".content").html() ??
      "";

    const bodyText = htmlToText(mainContent);
    if (bodyText.length < 30) {
      console.warn(`  Skipping ${source.url}: body too short (${bodyText.length} chars)`);
      return null;
    }

    const title = $("h1").first().text().trim() || $("title").text().trim();
    if (!title) {
      console.warn(`  Skipping ${source.url}: no title found`);
      return null;
    }

    // Date: look for publication date patterns
    let date: string | null = null;
    const dateMatch = bodyText.match(
      /(?:Published|Date|Updated|Publié|Gepubliceerd)\s*:?\s*(\d{1,2}[./]\d{1,2}[./]\d{4})/i,
    );
    if (dateMatch) {
      date = parseDate(dateMatch[1]!);
    }

    // Summary: first paragraph or first 500 chars
    const firstPara = $("main p, article p, .node__content p").first().text().trim();
    const summary = firstPara && firstPara.length > 30
      ? firstPara.slice(0, 1000)
      : bodyText.slice(0, 500);

    const reference = guidanceUrlToReference(new URL(source.url).pathname);

    return {
      reference,
      title,
      title_en: title, // crawled in English
      date,
      type: source.type,
      series: source.series,
      summary,
      full_text: bodyText,
      topics: JSON.stringify(source.topics),
      status: "current",
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`  Failed to fetch guidance ${source.url}: ${msg}`);
    return null;
  }
}

/**
 * Crawl all guidance sources and insert into the database.
 */
async function crawlGuidance(
  db: Database.Database,
  progress: Progress,
): Promise<number> {
  console.log("\n=== Crawling CCB Guidance & Resources ===\n");

  const insertStmt = db.prepare(
    `INSERT OR REPLACE INTO guidance
       (reference, title, title_en, date, type, series, summary, full_text, topics, status)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  );

  let inserted = 0;
  let skipped = 0;

  for (let i = 0; i < GUIDANCE_SOURCES.length; i++) {
    const source = GUIDANCE_SOURCES[i]!;
    console.log(
      `[${i + 1}/${GUIDANCE_SOURCES.length}] ${source.url}`,
    );

    const row = await fetchGuidancePage(source, progress);
    if (!row) {
      skipped++;
      continue;
    }

    if (dryRun) {
      console.log(
        `  [dry-run] Would insert: ${row.reference} — ${row.title.slice(0, 80)}`,
      );
    } else {
      insertStmt.run(
        row.reference,
        row.title,
        row.title_en,
        row.date,
        row.type,
        row.series,
        row.summary,
        row.full_text,
        row.topics,
        row.status,
      );
      console.log(`  Inserted: ${row.reference} — ${row.title.slice(0, 70)}`);
    }

    inserted++;
    progress.completed_guidance_urls.push(source.url);

    if (inserted % 5 === 0) {
      saveProgress(progress);
    }
  }

  saveProgress(progress);
  console.log(
    `\nGuidance complete: ${inserted} inserted, ${skipped} skipped`,
  );
  return inserted;
}

// ---------------------------------------------------------------------------
// News crawling — CCB news articles (cybersecurity strategy, reports)
// ---------------------------------------------------------------------------

interface NewsListItem {
  slug: string;
  title: string;
  date: string | null;
  url: string;
}

/**
 * Parse a CCB news listing page.
 */
function parseNewsListPage(html: string): NewsListItem[] {
  const $ = cheerio.load(html);
  const items: NewsListItem[] = [];

  $('a[href*="/news/"]').each((_i, el) => {
    const href = $(el).attr("href");
    if (!href || href === "/news" || href === "/news-events" || href.includes("?")) return;

    const slug = href.replace(/.*\/news\//, "").replace(/\/$/, "");
    if (!slug || slug.includes("/")) return;

    const title = $(el).text().trim();
    if (!title || title.length < 10) return;

    let date: string | null = null;
    const parentText = $(el).parent().parent().text();
    const dateMatch = parentText.match(/(\d{1,2})[./](\d{1,2})[./](\d{4})/);
    if (dateMatch) {
      date = parseDate(dateMatch[0]);
    }

    if (!items.some((it) => it.slug === slug)) {
      items.push({
        slug,
        title,
        date,
        url: `${CCB_BASE}/news/${slug}`,
      });
    }
  });

  return items;
}

/**
 * Determine total news pages from pagination.
 */
function parseNewsPageCount(html: string): number {
  const $ = cheerio.load(html);
  let maxPage = 1;

  $('a[href*="?page="]').each((_i, el) => {
    const href = $(el).attr("href") ?? "";
    const m = href.match(/[?&]page=(\d+)/);
    if (m) {
      const p = parseInt(m[1]!, 10) + 1;
      if (p > maxPage) maxPage = p;
    }
  });

  return maxPage;
}

/**
 * Fetch and parse a single news article as a guidance document.
 * CCB news articles often contain cybersecurity strategy updates,
 * threat reports, and operational guidance.
 */
async function fetchNewsArticle(
  item: NewsListItem,
): Promise<GuidanceRow | null> {
  try {
    const html = await fetchHtml(item.url);
    const $ = cheerio.load(html);

    $("nav, header, footer, script, style, .breadcrumb, .menu").remove();

    const mainContent =
      $("main").html() ??
      $("article").html() ??
      $(".node__content").html() ??
      "";

    const bodyText = htmlToText(mainContent);
    if (bodyText.length < 100) {
      return null;
    }

    const title = $("h1").first().text().trim() || item.title;

    let date = item.date;
    const publishedMatch = bodyText.match(
      /(?:Published|Date)\s*:?\s*(\d{1,2}[./]\d{1,2}[./]\d{4})/i,
    );
    if (publishedMatch) {
      date = parseDate(publishedMatch[1]!) ?? date;
    }

    const firstPara = $("main p, article p").first().text().trim();
    const summary = firstPara && firstPara.length > 30
      ? firstPara.slice(0, 1000)
      : bodyText.slice(0, 500);

    // Classify news articles by content
    const lower = bodyText.toLowerCase();
    let type = "news";
    const topics: string[] = ["Belgium", "CCB"];

    if (lower.includes("threat report") || lower.includes("quarterly")) {
      type = "threat_report";
      topics.push("threat report");
    } else if (lower.includes("strategy") || lower.includes("strategie")) {
      type = "strategy";
      topics.push("strategy");
    } else if (lower.includes("nis2") || lower.includes("nis 2")) {
      type = "nis2_guide";
      topics.push("NIS2");
    } else if (lower.includes("phishing") || lower.includes("ransomware")) {
      type = "threat_guide";
      topics.push("threats");
    } else if (lower.includes("awareness") || lower.includes("campaign")) {
      type = "awareness";
      topics.push("awareness");
    }

    return {
      reference: `CCB-news-${item.slug}`,
      title,
      title_en: title,
      date,
      type,
      series: "CCB News",
      summary,
      full_text: bodyText,
      topics: JSON.stringify(topics),
      status: "current",
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`  Failed to fetch news ${item.slug}: ${msg}`);
    return null;
  }
}

/**
 * Crawl CCB news pages and insert as guidance documents.
 */
async function crawlNews(
  db: Database.Database,
  progress: Progress,
): Promise<number> {
  console.log("\n=== Crawling CCB News (as guidance) ===\n");

  const insertStmt = db.prepare(
    `INSERT OR REPLACE INTO guidance
       (reference, title, title_en, date, type, series, summary, full_text, topics, status)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  );

  // Fetch first page
  const newsUrl = `${CCB_BASE}/news-events`;
  let firstHtml: string;
  try {
    firstHtml = await fetchHtml(newsUrl);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`Failed to fetch news listing: ${msg}`);
    return 0;
  }

  // The news-events page has "See all news" -> /news which is the paginated listing
  // Try the paginated listing instead
  const paginatedUrl = `${CCB_BASE}/news`;
  let paginatedHtml: string;
  try {
    paginatedHtml = await fetchHtml(paginatedUrl);
  } catch {
    // Fall back to news-events page
    paginatedHtml = firstHtml;
  }

  const totalPages = parseNewsPageCount(paginatedHtml);
  console.log(`Found ${totalPages} news pages to crawl`);

  let inserted = 0;
  let skipped = 0;

  for (let page = 0; page < totalPages; page++) {
    const pageUrl = page === 0 ? paginatedUrl : `${paginatedUrl}?page=${page}`;
    console.log(`\n--- News page ${page + 1}/${totalPages} ---`);

    let listHtml: string;
    if (page === 0) {
      listHtml = paginatedHtml;
    } else {
      try {
        listHtml = await fetchHtml(pageUrl);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error(`Failed to fetch news page ${page}: ${msg}. Continuing.`);
        continue;
      }
    }

    const items = parseNewsListPage(listHtml);
    console.log(`  Found ${items.length} news articles on page ${page + 1}`);

    for (const item of items) {
      if (progress.completed_news_slugs.includes(item.slug)) {
        skipped++;
        continue;
      }

      const row = await fetchNewsArticle(item);
      if (!row) {
        skipped++;
        continue;
      }

      if (dryRun) {
        console.log(
          `  [dry-run] Would insert: ${row.reference} — ${row.title.slice(0, 80)}`,
        );
      } else {
        insertStmt.run(
          row.reference,
          row.title,
          row.title_en,
          row.date,
          row.type,
          row.series,
          row.summary,
          row.full_text,
          row.topics,
          row.status,
        );
        console.log(
          `  Inserted: ${row.reference} — ${row.title.slice(0, 70)}`,
        );
      }

      inserted++;
      progress.completed_news_slugs.push(item.slug);

      if (inserted % 10 === 0) {
        saveProgress(progress);
      }
    }

    saveProgress(progress);
  }

  console.log(`\nNews complete: ${inserted} inserted, ${skipped} skipped`);
  return inserted;
}

// ---------------------------------------------------------------------------
// Framework metadata
// ---------------------------------------------------------------------------

function upsertFrameworks(db: Database.Database): void {
  console.log("\n=== Upserting Frameworks ===\n");

  const frameworks: FrameworkRow[] = [
    {
      id: "cyberfundamentals",
      name: "CyberFundamentals Framework (CyFun)",
      name_en: "CyberFundamentals Framework (CyFun)",
      description:
        "The CCB CyberFundamentals Framework is a set of concrete measures to protect data, " +
        "reduce the risk of common cyber-attacks, and increase cyber resilience. Built around " +
        "five core functions (Identify, Protect, Detect, Respond, Recover) with four assurance " +
        "levels: Small, Basic, Important, Essential. Aligned with NIST CSF, ISO 27001/27002, " +
        "IEC 62443, and CIS Controls. CyFun certification provides a presumption of NIS2 " +
        "conformity in Belgium. Verified/certified by BELAC-accredited conformity assessment bodies.",
      document_count: 0, // updated after crawl
    },
    {
      id: "nis2-be",
      name: "NIS2 Implementatie in België / Implémentation NIS2 en Belgique",
      name_en: "NIS2 Implementation in Belgium",
      description:
        "Implementation of NIS2 Directive (EU) 2022/2555 in Belgium via the Law of 26 April " +
        "2024. CCB is the national cybersecurity authority and supervisory body. Obligations " +
        "include: registration on Safeonweb@Work, cybersecurity risk-management measures " +
        "(Article 21), significant incident notification to CERT.be, management accountability, " +
        "and cooperation with authorities. Presumption of conformity through CyberFundamentals " +
        "or ISO 27001 certification.",
      document_count: 0,
    },
    {
      id: "cert-be",
      name: "CERT.be — Belgian National CSIRT",
      name_en: "CERT.be — Belgian National CSIRT",
      description:
        "CERT.be is the national Computer Security Incident Response Team of Belgium, operated " +
        "by the CCB. Analyses, contains, mitigates, and eradicates cyberattacks within Belgium. " +
        "Publishes security advisories with severity classification (Critical, High, Medium, Low). " +
        "Available in English, French, and Dutch. Contact: cert@cert.be or +32 2 501 05 60 (24/7). " +
        "NIS2 entities must report significant incidents to CERT.be (24h early warning, 72h notification).",
      document_count: 0,
    },
    {
      id: "ccb-safeguards",
      name: "CCB Cybersecurity Safeguards",
      name_en: "CCB Cybersecurity Safeguards",
      description:
        "The CCB Cybersecurity Safeguards define baseline security measures for Belgian " +
        "organisations. Two tiers: Essential (for all NIS2 entities) and Important (for NIS2 " +
        "essential entities). 12 domains covering governance, asset management, identity and " +
        "access management, network security, vulnerability management, cryptography, HR security, " +
        "supplier security, incident management, business continuity, physical security, and " +
        "compliance. Aligned with NIS2 Article 21 requirements and international standards " +
        "(ISO 27001, NIST CSF, CIS Controls).",
      document_count: 0,
    },
    {
      id: "ccb-directives",
      name: "CCB Directives / Richtlijnen / Directives",
      name_en: "CCB Directives",
      description:
        "Official directives issued by the Centre for Cybersecurity Belgium under the NIS2 " +
        "Law. CCB Directive 1/2024 covers public administration IT systems. CCB Directive " +
        "1/2025 applies to information systems of all organisations. Published in French and " +
        "Dutch. Legally binding for entities in scope of the Belgian NIS2 Act.",
      document_count: 0,
    },
    {
      id: "safeonweb-resources",
      name: "Safeonweb@work Resources",
      name_en: "Safeonweb@work Resources",
      description:
        "Safeonweb@work is the CCB platform providing cybersecurity tools and resources for " +
        "Belgian organisations. Includes the CyberFundamentals Framework, self-assessment tools, " +
        "policy templates, NIS2 quickstart guide, threat-specific guides (ransomware, phishing, " +
        "BEC fraud), and best-practice guides (passwords, patching, mobile security). All " +
        "resources are free and publicly available.",
      document_count: 0,
    },
  ];

  const insertStmt = db.prepare(
    "INSERT OR REPLACE INTO frameworks (id, name, name_en, description, document_count) VALUES (?, ?, ?, ?, ?)",
  );
  for (const f of frameworks) {
    insertStmt.run(f.id, f.name, f.name_en, f.description, f.document_count);
  }
  console.log(`Upserted ${frameworks.length} frameworks`);
}

/**
 * Update framework document_count based on actual data in the database.
 */
function updateFrameworkCounts(db: Database.Database): void {
  const advisoryCount = (
    db.prepare("SELECT COUNT(*) as n FROM advisories").get() as { n: number }
  ).n;
  const guidanceBySeriesStmt = db.prepare(
    "SELECT series, COUNT(*) as n FROM guidance GROUP BY series",
  );
  const seriesCounts = guidanceBySeriesStmt.all() as Array<{
    series: string;
    n: number;
  }>;

  const countMap = new Map<string, number>();
  for (const row of seriesCounts) {
    countMap.set(row.series, row.n);
  }

  const updateStmt = db.prepare(
    "UPDATE frameworks SET document_count = ? WHERE id = ?",
  );

  updateStmt.run(advisoryCount, "cert-be");
  updateStmt.run(countMap.get("CyberFundamentals") ?? 0, "cyberfundamentals");
  updateStmt.run(countMap.get("NIS2") ?? 0, "nis2-be");
  updateStmt.run(countMap.get("Safeguards") ?? 0, "ccb-safeguards");

  // Sum all Safeonweb series entries
  let safeonwebTotal = 0;
  for (const [series, n] of countMap) {
    if (series === "Safeonweb" || series === "CCB News") {
      safeonwebTotal += n;
    }
  }
  updateStmt.run(safeonwebTotal, "safeonweb-resources");

  // CCB Directives count from "EU Regulation" + "CCB" guidance
  const directiveCount =
    (countMap.get("EU Regulation") ?? 0) +
    (countMap.get("CCB") ?? 0);
  updateStmt.run(directiveCount, "ccb-directives");

  console.log("Updated framework document counts");
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  console.log("CCB Ingestion Crawler");
  console.log("=====================");
  console.log(`Database: ${DB_PATH}`);
  console.log(`Flags: ${[
    force && "--force",
    dryRun && "--dry-run",
    resume && "--resume",
    advisoriesOnly && "--advisories-only",
    guidanceOnly && "--guidance-only",
  ].filter(Boolean).join(", ") || "(none)"}`);
  console.log();

  // Database setup
  const dir = dirname(DB_PATH);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  if (force && existsSync(DB_PATH)) {
    unlinkSync(DB_PATH);
    console.log(`Deleted existing database: ${DB_PATH}`);
  }

  const db = new Database(DB_PATH);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  db.exec(SCHEMA_SQL);
  if (dryRun) {
    console.log("[dry-run] Database schema initialised (no writes will occur)\n");
  }

  const progress = loadProgress();

  // Upsert framework metadata (always, regardless of flags)
  if (!dryRun) {
    upsertFrameworks(db);
  }

  let totalAdvisories = 0;
  let totalGuidance = 0;
  let totalNews = 0;

  // Crawl advisories
  if (!guidanceOnly) {
    totalAdvisories = await crawlAdvisories(db, progress);
  }

  // Crawl guidance pages
  if (!advisoriesOnly) {
    totalGuidance = await crawlGuidance(db, progress);
  }

  // Crawl news (as additional guidance)
  if (!advisoriesOnly) {
    totalNews = await crawlNews(db, progress);
  }

  // Update framework counts
  if (!dryRun) {
    updateFrameworkCounts(db);
  }

  // Final summary
  const gc = (db.prepare("SELECT COUNT(*) as n FROM guidance").get() as { n: number }).n;
  const ac = (db.prepare("SELECT COUNT(*) as n FROM advisories").get() as { n: number }).n;
  const fc = (db.prepare("SELECT COUNT(*) as n FROM frameworks").get() as { n: number }).n;

  console.log("\n=====================");
  console.log("Ingestion complete");
  console.log("=====================");
  console.log(`This run: ${totalAdvisories} advisories, ${totalGuidance} guidance, ${totalNews} news`);
  console.log(`Database totals: ${ac} advisories, ${gc} guidance, ${fc} frameworks`);
  console.log(`HTTP requests made: ${totalRequests}`);
  if (!dryRun) {
    saveProgress(progress);
    console.log(`Progress saved to: ${PROGRESS_FILE}`);
  }
  console.log(`Database at: ${DB_PATH}`);

  db.close();
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
