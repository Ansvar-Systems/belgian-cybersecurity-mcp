#!/usr/bin/env node

/**
 * Belgian Cybersecurity MCP — stdio entry point.
 *
 * Provides MCP tools for querying CCB (Centre for Cybersecurity Belgium)
 * guidelines, technical reports, security advisories, and NIS2 implementation
 * frameworks for Belgium.
 *
 * Tool prefix: be_cyber_
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { searchGuidance, getGuidance, searchAdvisories, getAdvisory, listFrameworks } from "./db.js";
import { buildCitation } from './citation.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

let pkgVersion = "0.1.0";
try {
  const pkg = JSON.parse(readFileSync(join(__dirname, "..", "package.json"), "utf8")) as { version: string };
  pkgVersion = pkg.version;
} catch { /* fallback */ }

const SERVER_NAME = "belgian-cybersecurity-mcp";

const TOOLS = [
  {
    name: "be_cyber_search_guidance",
    description: "Full-text search across CCB (Centre for Cybersecurity Belgium) guidelines and technical reports. Covers the Belgian Cybersecurity Strategy, NIS2 implementation guidance, CCB good practice guides, and essential security measures (Safeguards). Returns matching documents with reference, title, series, and summary.",
    inputSchema: {
      type: "object" as const,
      properties: {
        query: { type: "string", description: "Search query in English (e.g., 'encryption TLS', 'NIS2 essential services', 'incident reporting')" },
        type: { type: "string", enum: ["technical_guideline", "nis2_guide", "technical_report", "recommendation"], description: "Filter by document type. Optional." },
        series: { type: "string", enum: ["CCB", "NIS2", "Safeguards"], description: "Filter by series. Optional." },
        status: { type: "string", enum: ["current", "superseded", "draft"], description: "Filter by document status. Optional." },
        limit: { type: "number", description: "Maximum number of results to return. Defaults to 20." },
      },
      required: ["query"],
    },
  },
  {
    name: "be_cyber_get_guidance",
    description: "Get a specific CCB guidance document by reference (e.g., 'CCB-CS-2023-01', 'CCB-Safeguards-v2').",
    inputSchema: { type: "object" as const, properties: { reference: { type: "string", description: "CCB document reference" } }, required: ["reference"] },
  },
  {
    name: "be_cyber_search_advisories",
    description: "Search CCB security advisories and alerts (CERT.be). Returns advisories with severity, affected products, and CVE references where available.",
    inputSchema: {
      type: "object" as const,
      properties: {
        query: { type: "string", description: "Search query (e.g., 'critical vulnerability', 'ransomware', 'phishing campaign')" },
        severity: { type: "string", enum: ["critical", "high", "medium", "low"], description: "Filter by severity level. Optional." },
        limit: { type: "number", description: "Maximum number of results to return. Defaults to 20." },
      },
      required: ["query"],
    },
  },
  {
    name: "be_cyber_get_advisory",
    description: "Get a specific CCB/CERT.be security advisory by reference (e.g., 'CERT.be-AV-2024-0001').",
    inputSchema: { type: "object" as const, properties: { reference: { type: "string", description: "CCB advisory reference" } }, required: ["reference"] },
  },
  {
    name: "be_cyber_list_frameworks",
    description: "List all CCB frameworks and standard series covered in this MCP, including Belgian Cybersecurity Strategy, NIS2 implementation, and CCB Safeguards.",
    inputSchema: { type: "object" as const, properties: {}, required: [] },
  },
  {
    name: "be_cyber_about",
    description: "Return metadata about this MCP server: version, data source, coverage, and tool list.",
    inputSchema: { type: "object" as const, properties: {}, required: [] },
  },
];

const SearchGuidanceArgs = z.object({
  query: z.string().min(1),
  type: z.enum(["technical_guideline", "nis2_guide", "technical_report", "recommendation"]).optional(),
  series: z.enum(["CCB", "NIS2", "Safeguards"]).optional(),
  status: z.enum(["current", "superseded", "draft"]).optional(),
  limit: z.number().int().positive().max(100).optional(),
});
const GetGuidanceArgs = z.object({ reference: z.string().min(1) });
const SearchAdvisoriesArgs = z.object({
  query: z.string().min(1),
  severity: z.enum(["critical", "high", "medium", "low"]).optional(),
  limit: z.number().int().positive().max(100).optional(),
});
const GetAdvisoryArgs = z.object({ reference: z.string().min(1) });

function textContent(data: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }] };
}
function errorContent(message: string) {
  return { content: [{ type: "text" as const, text: message }], isError: true as const };
}

const server = new Server({ name: SERVER_NAME, version: pkgVersion }, { capabilities: { tools: {} } });

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args = {} } = request.params;
  try {
    switch (name) {
      case "be_cyber_search_guidance": {
        const parsed = SearchGuidanceArgs.parse(args);
        const results = searchGuidance({ query: parsed.query, type: parsed.type, series: parsed.series, status: parsed.status, limit: parsed.limit });
        return textContent({ results, count: results.length });
      }
      case "be_cyber_get_guidance": {
        const parsed = GetGuidanceArgs.parse(args);
        const doc = getGuidance(parsed.reference);
        if (!doc) return errorContent(`Guidance document not found: ${parsed.reference}`);
        return textContent({
          ...(typeof doc === 'object' ? doc : { data: doc }),
          _citation: buildCitation(
            doc.reference || parsed.reference,
            doc.title || doc.name || parsed.reference,
            'be_cyber_get_guidance',
            { reference: parsed.reference },
            doc.url || doc.source_url || null,
          ),
        });
      }
      case "be_cyber_search_advisories": {
        const parsed = SearchAdvisoriesArgs.parse(args);
        const results = searchAdvisories({ query: parsed.query, severity: parsed.severity, limit: parsed.limit });
        return textContent({ results, count: results.length });
      }
      case "be_cyber_get_advisory": {
        const parsed = GetAdvisoryArgs.parse(args);
        const advisory = getAdvisory(parsed.reference);
        if (!advisory) return errorContent(`Advisory not found: ${parsed.reference}`);
        return textContent({
          ...(typeof advisory === 'object' ? advisory : { data: advisory }),
          _citation: buildCitation(
            advisory.reference || parsed.reference,
            advisory.title || advisory.subject || parsed.reference,
            'be_cyber_get_advisory',
            { reference: parsed.reference },
            advisory.url || advisory.source_url || null,
          ),
        });
      }
      case "be_cyber_list_frameworks": {
        const frameworks = listFrameworks();
        return textContent({ frameworks, count: frameworks.length });
      }
      case "be_cyber_about":
        return textContent({
          name: SERVER_NAME, version: pkgVersion,
          description: "CCB (Centre for Cybersecurity Belgium) MCP server. Provides access to Belgian Cybersecurity Strategy, NIS2 implementation guides, CCB good practice guides, essential security measures (Safeguards), and CERT.be security advisories.",
          data_source: "CCB (https://ccb.belgium.be/) and CERT.be (https://www.cert.be/)",
          coverage: { guidance: "Belgian Cybersecurity Strategy, NIS2 implementation, CCB good practice guides, Safeguards (essential security measures)", advisories: "CERT.be security advisories and alerts", frameworks: "CCB guidance series, NIS2, Safeguards" },
          tools: TOOLS.map((t) => ({ name: t.name, description: t.description })),
        });
      default:
        return errorContent(`Unknown tool: ${name}`);
    }
  } catch (err) {
    return errorContent(`Error executing ${name}: ${err instanceof Error ? err.message : String(err)}`);
  }
});

async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  process.stderr.write(`${SERVER_NAME} v${pkgVersion} running on stdio\n`);
}

main().catch((err) => {
  process.stderr.write(`Fatal error: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
