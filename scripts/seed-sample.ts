/**
 * Seed the CCB database with sample guidance documents, advisories, and frameworks.
 *
 * Usage:
 *   npx tsx scripts/seed-sample.ts
 *   npx tsx scripts/seed-sample.ts --force
 */

import Database from "better-sqlite3";
import { existsSync, mkdirSync, unlinkSync } from "node:fs";
import { dirname } from "node:path";
import { SCHEMA_SQL } from "../src/db.js";

const DB_PATH = process.env["CCB_DB_PATH"] ?? "data/ccb.db";
const force = process.argv.includes("--force");

const dir = dirname(DB_PATH);
if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
if (force && existsSync(DB_PATH)) { unlinkSync(DB_PATH); console.log(`Deleted ${DB_PATH}`); }

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(SCHEMA_SQL);
console.log(`Database initialised at ${DB_PATH}`);

interface FrameworkRow { id: string; name: string; name_en: string; description: string; document_count: number; }

const frameworks: FrameworkRow[] = [
  { id: "ccb-safeguards", name: "CCB Cybersecurity Safeguards", name_en: "CCB Cybersecurity Safeguards", description: "The CCB (Centre for Cybersecurity Belgium) Cybersecurity Safeguards define baseline security measures for Belgian organisations. Two tiers: Essential (88 measures, SME-friendly) and Important (all measures, for NIS2 entities). Covers governance, asset management, network security, incident response, supply chain, and recovery.", document_count: 88 },
  { id: "nis2-be", name: "NIS2 Implementatie in België / Implémentation NIS2 en Belgique", name_en: "NIS2 Implementation in Belgium", description: "Implementation of NIS2 Directive (EU) 2022/2555 in Belgium via the NIS2 Act (transposition law 2023). CCB is the Belgian national cybersecurity authority. Essential entities: energy, transport, banking, financial market infrastructure, health, drinking water, digital infrastructure, ICT service management, public administration, space. Important entities: postal, waste management, chemicals, food, manufacturing, digital providers, research.", document_count: 25 },
  { id: "cert-be", name: "CERT.be Advisories", name_en: "CERT.be Security Advisories", description: "CERT.be is the national CSIRT of Belgium, operated by the CCB. Publishes security advisories for organisations in Belgium. Classifies threats by severity: Critical, High, Medium, Low. Available in English, French, and Dutch.", document_count: 600 },
];

const insertFramework = db.prepare("INSERT OR IGNORE INTO frameworks (id, name, name_en, description, document_count) VALUES (?, ?, ?, ?, ?)");
for (const f of frameworks) insertFramework.run(f.id, f.name, f.name_en, f.description, f.document_count);
console.log(`Inserted ${frameworks.length} frameworks`);

interface GuidanceRow { reference: string; title: string; title_en: string | null; date: string; type: string; series: string; summary: string; full_text: string; topics: string; status: string; }

const guidance: GuidanceRow[] = [
  {
    reference: "CCB-Safeguards-v2",
    title: "CCB Cybersecurity Safeguards v2.0 — Essential and Important Measures",
    title_en: "CCB Cybersecurity Safeguards v2.0 — Essential and Important Measures",
    date: "2023-10-01",
    type: "nis2_guide",
    series: "Safeguards",
    summary: "The CCB Cybersecurity Safeguards v2.0 define the baseline security measures for Belgian organisations subject to NIS2. Two tiers: Essential (88 measures for all NIS2 entities) and Important (additional measures for essential entities). Aligned with NIS2 Article 21 requirements and international standards (ISO 27001, NIST CSF, CIS Controls).",
    full_text: "CCB Cybersecurity Safeguards v2.0. Structure: 12 domains mirroring NIS2 Article 21 requirements. Domain 1 - Governance: information security policy; roles and responsibilities; risk management process; Board-level accountability. Domain 2 - Asset Management: inventory of systems; classification; lifecycle management. Domain 3 - Identity and Access Management: MFA for all remote access and privileged accounts; least privilege; access reviews; PAM solution for critical systems. Domain 4 - Network Security: network segmentation; firewall with default-deny; encrypted communications (TLS 1.2+ minimum); VPN for remote access; DMZ for public-facing services. Domain 5 - Vulnerability Management: asset patching within 30 days (critical: 7 days); vulnerability scanning; patch management process. Domain 6 - Cryptography: AES-256 for data at rest; TLS 1.2+ for data in transit; strong key management. Domain 7 - Human Resources Security: background checks; security awareness training (annual minimum); phishing simulations. Domain 8 - Supplier Security: supplier risk assessment; contractual security requirements; monitoring. Domain 9 - Incident Management: incident response plan; reporting to CCB/CERT.be for significant incidents; post-incident review. Domain 10 - Business Continuity: backup strategy (3-2-1 rule); tested recovery procedures; RTO/RPO defined. Domain 11 - Physical Security: access controls; CCTV; clean desk policy. Domain 12 - Compliance: legal requirements inventory; audit programme.",
    topics: JSON.stringify(["NIS2", "Safeguards", "compliance", "baseline"]),
    status: "current",
  },
  {
    reference: "CCB-CS-2023-01",
    title: "Belgian Cybersecurity Strategy 2.0 — 2023-2026",
    title_en: "Belgian Cybersecurity Strategy 2.0 — 2023-2026",
    date: "2023-02-01",
    type: "technical_guideline",
    series: "CCB",
    summary: "Belgian national cybersecurity strategy for 2023-2026. Defines 5 strategic objectives: cyber resilience, secure digital economy, Belgian critical infrastructure protection, international cooperation, and cyber skills development. Sets targets for NIS2 implementation and CCB capacity expansion.",
    full_text: "Belgian Cybersecurity Strategy 2.0 (2023-2026). Strategic Objective 1 - Cyber Resilience: implement CCB Safeguards across all NIS2 entities; mandatory security audits for essential entities; CCB Cyber Fundamentals certification scheme. Strategic Objective 2 - Secure Digital Economy: SME cybersecurity support programme; Belgian Cyber Voucher scheme; sector-specific guidance. Strategic Objective 3 - Critical Infrastructure Protection: enhanced NIS2 supervision; mandatory incident reporting; coordinated vulnerability disclosure (CVD) policy. Strategic Objective 4 - International Cooperation: active participation in ENISA, EU-CyCLONe, NATO CCDCOE; bilateral agreements; joint exercises (Cyber Europe). Strategic Objective 5 - Cyber Skills: cybersecurity education at all levels; CyberFundamentals certification; public sector hiring targets. Key milestones: NIS2 transposition (2023); CCB supervision ramp-up (2024); full implementation (2026). Budget: EUR 100 million additional investment over 4 years.",
    topics: JSON.stringify(["strategy", "NIS2", "resilience", "Belgium"]),
    status: "current",
  },
  {
    reference: "CCB-NIS2-Reporting-2023",
    title: "NIS2 Incident Reporting Guidelines for Belgium",
    title_en: "NIS2 Incident Reporting Guidelines for Belgium",
    date: "2023-10-17",
    type: "nis2_guide",
    series: "NIS2",
    summary: "CCB guidance on incident reporting obligations under the Belgian NIS2 Act. Defines what constitutes a significant incident, reporting timelines, and notification process to CERT.be and CCB. Covers both essential and important entities.",
    full_text: "CCB NIS2 Incident Reporting Guidelines Belgium. Significant incident definition: incident with significant impact on provision of services; considers: number of users affected; duration; geographic spread; financial impact; criticality of affected services. Reporting timelines (Art. 23 NIS2): Early warning to CERT.be: within 24 hours of becoming aware; Incident notification: within 72 hours (update if facts changed); Intermediate report: upon request of CCB or CERT.be; Final report: within 1 month of incident notification. Reporting channel: CERT.be reporting portal (https://ccb.belgium.be/report); telephone: +32 2 501 05 60 (24/7 for critical). Information required: incident description and timeline; affected services/systems; estimated impact; cause (if known); mitigation measures taken. Cross-border incidents: CCB coordinates with other MS CSOPs if the incident has cross-border impact. Sanctions for non-reporting: administrative fines up to EUR 10 million or 2% global turnover (essential entities). Confidentiality: incident reports treated as confidential by CCB and CERT.be.",
    topics: JSON.stringify(["NIS2", "incident reporting", "CERT.be", "compliance"]),
    status: "current",
  },
  {
    reference: "CCB-TechGuide-TLS-2023",
    title: "CCB Technical Guide: TLS Configuration Best Practices",
    title_en: "CCB Technical Guide: TLS Configuration Best Practices",
    date: "2023-05-15",
    type: "technical_guideline",
    series: "CCB",
    summary: "CCB technical guide for secure TLS configuration for Belgian organisations. Covers TLS version requirements, cipher suite selection, certificate management, and HSTS deployment. Aligned with CCB Safeguards Domain 4 (Network Security) and NIS2 Article 21(2)(h) cryptography requirements.",
    full_text: "CCB TLS Configuration Best Practices. TLS Versions: TLS 1.3 recommended (mandatory for high-sensitivity services); TLS 1.2 acceptable with strong cipher suites; TLS 1.1 and 1.0 deprecated and prohibited; SSL 3.0 and earlier prohibited. TLS 1.3 cipher suites (all acceptable): TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, TLS_AES_128_GCM_SHA256. TLS 1.2 cipher suites (acceptable): ECDHE-ECDSA-AES256-GCM-SHA384, ECDHE-RSA-AES256-GCM-SHA384, ECDHE-ECDSA-CHACHA20-POLY1305; RC4, 3DES, NULL, EXPORT cipher suites prohibited. Certificates: RSA minimum 2048-bit (3072+ recommended); EC curves: P-256, P-384, P-521; SHA-256+ for signatures; CN or SAN must match hostname; maximum validity 398 days (public CA) or 2 years (private CA). HSTS: max-age minimum 6 months; include subdomains recommended; preload optional. OCSP Stapling: recommended. Certificate Transparency (CT): required for public-facing services. mTLS: required for API-to-API communication in NIS2 essential entities. nginx reference config: ssl_protocols TLSv1.2 TLSv1.3; ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384.",
    topics: JSON.stringify(["TLS", "encryption", "network security", "configuration"]),
    status: "current",
  },
  {
    reference: "CCB-Supply-Chain-2023",
    title: "CCB Guidance on ICT Supply Chain Security",
    title_en: "CCB Guidance on ICT Supply Chain Security",
    date: "2023-08-01",
    type: "nis2_guide",
    series: "NIS2",
    summary: "CCB guidance on implementing ICT supply chain security requirements under NIS2 Article 21(2)(d). Covers supplier risk assessment, contractual security requirements, software supply chain integrity, and third-party incident notification. Applies to all NIS2 entities in Belgium.",
    full_text: "CCB ICT Supply Chain Security Guidance. Legal basis: NIS2 Art. 21(2)(d) — security in supply chain including security-related aspects concerning the relationships between each entity and its direct suppliers or service providers. Supplier Risk Assessment: classify suppliers by criticality (critical, important, standard); assess security posture (questionnaire, audit right, certifications); specific criteria for cloud and SaaS providers. Contractual Security Requirements: minimum security clauses for critical suppliers: right to audit; incident notification within 24h; patch commitment; data processing agreements; exit provisions; SLAs for security patches. Software Supply Chain: Software Bill of Materials (SBOM) requirement for critical software; code signing; vulnerability disclosure process from vendors; avoid single-source dependencies for critical functions. Third-party Incident: supplier must notify within 24h of incident affecting your systems; CCB may extend reporting obligations to cover supply chain incidents. Monitoring: annual supplier security review; continuous monitoring for critical suppliers; penetration testing of supplier-provided systems.",
    topics: JSON.stringify(["supply chain", "NIS2", "third-party risk", "procurement"]),
    status: "current",
  },
  {
    reference: "CCB-CyberFundamentals-2023",
    title: "CCB CyberFundamentals Framework — Assessment and Certification",
    title_en: "CCB CyberFundamentals Framework — Assessment and Certification",
    date: "2023-11-01",
    type: "recommendation",
    series: "CCB",
    summary: "The CCB CyberFundamentals Framework is a voluntary certification scheme for Belgian organisations demonstrating cybersecurity maturity. Four assurance levels: Basic (self-assessment), Essential (third-party verified, suitable for NIS2 important entities), Important (third-party verified, audit), and Advanced (NIS2 essential entity level). Based on CCB Safeguards.",
    full_text: "CCB CyberFundamentals Framework. Assurance Levels: Basic — self-assessment against 88 safeguards; suitable for SMEs and voluntary use; no third-party verification. Essential — verified by accredited assessor; covers all 88 essential safeguards; suitable for NIS2 important entities; renewal every 3 years. Important — full audit by accredited assessor; covers essential + important safeguards; suitable for NIS2 essential entities with lower risk; renewal every 2 years. Advanced — most rigorous; full audit + penetration test; for NIS2 essential entities with high risk; renewal every 2 years. Certification body: CCB-accredited assessors (list on CCB website). Benefits: demonstrates NIS2 compliance; CCB accepts certification as evidence of Article 21 implementation; insurability; public sector procurement preference. Process: register on CCB portal; self-assessment or appoint assessor; gap analysis; implementation; assessment; certification. Cost: assessor fees vary; CCB Cyber Voucher (SME subsidy) available for up to 50% of cost.",
    topics: JSON.stringify(["certification", "NIS2", "maturity", "Belgium"]),
    status: "current",
  },
];

const insertGuidance = db.prepare(`INSERT OR IGNORE INTO guidance (reference, title, title_en, date, type, series, summary, full_text, topics, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
for (const g of guidance) insertGuidance.run(g.reference, g.title, g.title_en, g.date, g.type, g.series, g.summary, g.full_text, g.topics, g.status);
console.log(`Inserted ${guidance.length} guidance documents`);

interface AdvisoryRow { reference: string; title: string; date: string; severity: string; affected_products: string; summary: string; full_text: string; cve_references: string | null; }

const advisories: AdvisoryRow[] = [
  {
    reference: "CERT.be-AV-2024-0012",
    title: "Critical vulnerability in Ivanti Connect Secure — Active exploitation confirmed",
    date: "2024-01-12",
    severity: "critical",
    affected_products: "Ivanti Connect Secure (all versions before 9.1R18.3, 22.3R3.2, 22.4R2.4, 22.5R1.3, 22.5R2.4, 22.6R1.3); Ivanti Policy Secure",
    summary: "CERT.be confirms active exploitation of CVE-2023-46805 and CVE-2024-21887 in Ivanti Connect Secure and Policy Secure. Combined, these allow unauthenticated remote code execution. Nation-state APT actors are deploying persistent webshells. Belgian organisations using Ivanti must patch immediately or disconnect.",
    full_text: "CERT.be-AV-2024-0012 Ivanti Connect Secure. CVE-2023-46805 (CVSS 8.2): authentication bypass in web component. CVE-2024-21887 (CVSS 9.1): command injection for authenticated admins. Combined: unauthenticated RCE. Nation-state APT (likely China-nexus) deploying custom webshells; persistence survives factory reset via update process manipulation. IoC: traffic to /api/v1/totp/user-backup-code/; unexpected processes; modified config files. Patches: Ivanti released patches 22 January 2024. Mitigation: apply patches immediately; run Ivanti Integrity Checker Tool; monitor for IoC; for NIS2 essential entities — report to CERT.be if exploitation confirmed. CERT.be contact: cert@cert.be or +32 2 501 05 60.",
    cve_references: "CVE-2023-46805, CVE-2024-21887",
  },
  {
    reference: "CERT.be-AV-2023-0089",
    title: "Belgian organisations targeted by ransomware group BlackBasta — Active campaign",
    date: "2023-10-05",
    severity: "high",
    affected_products: "Windows environments without MFA; organisations with internet-exposed RDP; VMware ESXi servers",
    summary: "CERT.be warns of an active BlackBasta ransomware campaign targeting Belgian organisations, including local government, healthcare, and manufacturing. Initial access via phishing and RDP brute-force. Double extortion (encryption + data leak). Several Belgian victims confirmed.",
    full_text: "CERT.be-AV-2023-0089 BlackBasta Ransomware Belgium. BlackBasta: highly active ransomware group since 2022; double extortion; affiliates use multiple initial access methods; RaaS model. Initial access vectors observed in Belgian incidents: phishing with QBot/IcedID malware (35%); RDP brute-force without MFA (40%); exploitation of public-facing vulnerabilities (25%). Post-compromise: QBot for initial payload; credential harvesting (Mimikatz); lateral movement (SMB, WMI, PsExec); domain admin compromise; data exfiltration to cloud storage; ESXi encryption for maximum impact. Belgian sectors targeted: local government (Gemeenten/Communes), healthcare (Ziekenhuizen/Hôpitaux), manufacturing, logistics. Mitigation: disable internet RDP; MFA on VPN and cloud services; offline backups; EDR deployment; network segmentation. NIS2 reporting: significant incidents must be reported to CERT.be within 24h early warning. CERT.be: cert@cert.be; +32 2 501 05 60 (24/7).",
    cve_references: null,
  },
  {
    reference: "CERT.be-AV-2024-0031",
    title: "Microsoft Outlook zero-click vulnerability — Patch immediately",
    date: "2024-02-14",
    severity: "critical",
    affected_products: "Microsoft Outlook 2016; Microsoft Outlook 2019; Microsoft 365 Apps for Enterprise; Microsoft Office LTSC 2021",
    summary: "CERT.be urges immediate patching for CVE-2024-21413 (CVSS 9.8), a critical Microsoft Outlook vulnerability allowing remote code execution without user interaction. The preview pane is sufficient for exploitation. Targeted by threat actors shortly after public disclosure.",
    full_text: "CERT.be-AV-2024-0031 Microsoft Outlook CVE-2024-21413. CVE-2024-21413 (CVSS 9.8 CRITICAL): Remote Code Execution in Microsoft Outlook. Vulnerability in Outlook's handling of specific file paths allows bypassing Office Protected View. Exploitation requires no user interaction beyond receiving an email — preview pane exploitation confirmed. Attacker gains NTLM credential leakage and potential code execution. Affected: Outlook 2016, Outlook 2019, Microsoft 365 Apps, Office LTSC 2021. Fixed in February 2024 Patch Tuesday. Mitigation: apply February 2024 security updates immediately; as temporary workaround, disable Outlook Preview Pane (View > Reading Pane > Off); block SMB traffic at perimeter to prevent NTLM relay. For Belgian NIS2 essential entities: if exploitation confirmed or suspected, report to CERT.be within 24h early warning. CERT.be: cert@cert.be.",
    cve_references: "CVE-2024-21413",
  },
];

const insertAdvisory = db.prepare(`INSERT OR IGNORE INTO advisories (reference, title, date, severity, affected_products, summary, full_text, cve_references) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`);
for (const a of advisories) insertAdvisory.run(a.reference, a.title, a.date, a.severity, a.affected_products, a.summary, a.full_text, a.cve_references);
console.log(`Inserted ${advisories.length} advisories`);

const gc = (db.prepare("SELECT COUNT(*) as n FROM guidance").get() as { n: number }).n;
const ac = (db.prepare("SELECT COUNT(*) as n FROM advisories").get() as { n: number }).n;
const fc = (db.prepare("SELECT COUNT(*) as n FROM frameworks").get() as { n: number }).n;
console.log(`\nDatabase summary:\n  Guidance: ${gc}\n  Advisories: ${ac}\n  Frameworks: ${fc}\n\nSeed complete.`);
