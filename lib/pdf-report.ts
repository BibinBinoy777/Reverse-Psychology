import { jsPDF } from 'jspdf';
import { AnalysisReport, EvidenceCategory, EvidenceRecord } from './analyzers';

export interface PdfExportOptions {
  reportTitle: string;
  authorName: string;
  caseId: string;
  analystNotes: string;
  includeTargetHeader: boolean;
  includeEvidenceLedger: boolean;
  includeReconstructedCode: boolean;
  includeAiSummary: boolean;
  aiSummaryText?: string | null;
  includedCategories: Record<EvidenceCategory, boolean>;
}

const CATEGORY_COLORS: Record<
  EvidenceCategory,
  { text: [number, number, number]; bg: [number, number, number]; label: string }
> = {
  observed: {
    text: [49, 46, 129], // Deep Indigo (#312E81)
    bg: [238, 242, 255], // Soft Indigo Tint (#EEF2FF)
    label: 'OBSERVED FACT',
  },
  derived: {
    text: [6, 95, 70], // Deep Emerald (#065F46)
    bg: [236, 253, 245], // Soft Emerald Tint (#ECFDF5)
    label: 'DERIVED STRUCTURE',
  },
  inferred: {
    text: [146, 64, 14], // Deep Amber (#92400E)
    bg: [255, 251, 235], // Soft Amber Tint (#FFFBEB)
    label: 'INFERRED INTENT',
  },
  unknown: {
    text: [153, 27, 27], // Deep Crimson (#991B1B)
    bg: [254, 242, 242], // Soft Rose Tint (#FEF2F2)
    label: 'EXPLICIT UNKNOWN',
  },
};

/**
 * Generates and downloads a formal, print-ready High-Contrast Light PDF report
 * preserving Reverse Psychology's four-tier Epistemic Evidence Ledger provenance.
 */
export function generateEvidencePdfReport(
  report: AnalysisReport,
  options: PdfExportOptions
): string {
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4',
  });

  const pageWidth = doc.internal.pageSize.getWidth(); // 210mm
  const pageHeight = doc.internal.pageSize.getHeight(); // 297mm
  const marginX = 16;
  const contentWidth = pageWidth - marginX * 2; // 178mm
  const bottomLimit = pageHeight - 20;

  let y = 18;

  const ensureSpace = (neededMm: number) => {
    if (y + neededMm > bottomLimit) {
      doc.addPage();
      y = 18;
      // Subtle running header on continuation pages
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(8);
      doc.setTextColor(100, 116, 139);
      doc.text(
        `Reverse Psychology · ${options.caseId} · ${report.targetName}`,
        marginX,
        12
      );
      doc.setDrawColor(226, 232, 240);
      doc.setLineWidth(0.25);
      doc.line(marginX, 14, pageWidth - marginX, 14);
      y = 20;
    }
  };

  // =========================================================================
  // 1. DOCUMENT BANNER & ATTRIBUTION HEADER
  // =========================================================================
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8.5);
  doc.setTextColor(67, 56, 202); // Indigo-700
  doc.text('REVERSE PSYCHOLOGY · EPISTEMIC EVIDENCE LEDGER REPORT', marginX, y);
  y += 6;

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(17);
  doc.setTextColor(15, 23, 42); // Slate-900
  const titleLines = doc.splitTextToSize(
    options.reportTitle.trim() || `Evidence Report: ${report.targetName}`,
    contentWidth
  );
  doc.text(titleLines, marginX, y);
  y += titleLines.length * 6.8 + 1;

  // Unboxed metadata line with typographic separators
  const generatedDate = new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
  const attributionLine = [
    `Case ID: ${options.caseId || 'RP-UNASSIGNED'}`,
    `Analyst: ${options.authorName || 'Lead Reverse Engineer'}`,
    `Generated: ${generatedDate}`,
  ].join('   ·   ');

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.setTextColor(71, 85, 105); // Slate-600
  doc.text(attributionLine, marginX, y);
  y += 5;

  // Top structural rule
  doc.setDrawColor(15, 23, 42);
  doc.setLineWidth(0.5);
  doc.line(marginX, y, pageWidth - marginX, y);
  y += 6;

  // Optional Analyst Notes
  if (options.analystNotes.trim()) {
    const noteLines = doc.splitTextToSize(options.analystNotes.trim(), contentWidth - 8);
    const boxH = noteLines.length * 4.5 + 11;
    ensureSpace(boxH + 4);
    doc.setFillColor(248, 250, 252);
    doc.setDrawColor(203, 213, 225);
    doc.setLineWidth(0.25);
    doc.rect(marginX, y, contentWidth, boxH, 'FD');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8.5);
    doc.setTextColor(30, 41, 59);
    doc.text('Analyst Scope & Assessment Notes', marginX + 4, y + 5);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(9);
    doc.setTextColor(51, 65, 85);
    doc.text(noteLines, marginX + 4, y + 10);
    y += boxH + 6;
  }

  // Optional AI Interrogation Executive Summary
  if (options.includeAiSummary && options.aiSummaryText?.trim()) {
    const sumLines = doc.splitTextToSize(options.aiSummaryText.trim(), contentWidth - 8);
    const boxH = sumLines.length * 4.5 + 11;
    ensureSpace(boxH + 4);
    doc.setFillColor(238, 242, 255);
    doc.setDrawColor(199, 210, 254);
    doc.setLineWidth(0.25);
    doc.rect(marginX, y, contentWidth, boxH, 'FD');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8.5);
    doc.setTextColor(49, 46, 129);
    doc.text('Executive Summary (AI Interrogation Synthesis)', marginX + 4, y + 5);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(9);
    doc.setTextColor(30, 41, 59);
    doc.text(sumLines, marginX + 4, y + 10);
    y += boxH + 6;
  }

  // =========================================================================
  // 2. TARGET METADATA & SHA-256 SUMMARY HEADER
  // =========================================================================
  if (options.includeTargetHeader) {
    ensureSpace(54);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(15, 23, 42);
    doc.text('01. Target Artifact Identity & Cryptographic Provenance', marginX, y);
    y += 4;

    // Outer container box
    const metaBoxHeight = 36;
    doc.setFillColor(248, 250, 252);
    doc.setDrawColor(203, 213, 225);
    doc.setLineWidth(0.3);
    doc.rect(marginX, y, contentWidth, metaBoxHeight, 'FD');

    // Row 1: Target Name, Format, Architecture
    const col1 = marginX + 4;
    const col2 = marginX + 64;
    const col3 = marginX + 122;

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(100, 116, 139);
    doc.text('TARGET ARTIFACT', col1, y + 5.5);
    doc.text('CONTAINER FORMAT', col2, y + 5.5);
    doc.text('ARCHITECTURE / ABI', col3, y + 5.5);

    doc.setFont('courier', 'bold');
    doc.setFontSize(9);
    doc.setTextColor(15, 23, 42);
    doc.text(report.targetName.slice(0, 28), col1, y + 10);
    doc.text(report.format, col2, y + 10);
    doc.setFont('helvetica', 'bold');
    doc.text(report.architecture.slice(0, 30), col3, y + 10);

    // Row 2: Entry Point, Size & Entropy, Provider
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(100, 116, 139);
    doc.text('ENTRY POINT / ROOT', col1, y + 16.5);
    doc.text('SIZE & SHANNON ENTROPY', col2, y + 16.5);
    doc.text('ANALYSIS ENGINE', col3, y + 16.5);

    doc.setFont('courier', 'bold');
    doc.setFontSize(9);
    doc.setTextColor(15, 23, 42);
    doc.text(report.entryPoint, col1, y + 21);
    doc.text(`${report.sizeBytes} B · ${report.entropy} bits/B`, col2, y + 21);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.text(report.providerUsed.slice(0, 34), col3, y + 21);

    // Divider inside metadata box
    doc.setDrawColor(226, 232, 240);
    doc.line(marginX + 4, y + 24.5, pageWidth - marginX - 4, y + 24.5);

    // Row 3: Full SHA-256 Digest
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7.5);
    doc.setTextColor(71, 85, 105);
    doc.text('SHA-256 DIGEST:', col1, y + 31);

    doc.setFont('courier', 'bold');
    doc.setFontSize(8.5);
    doc.setTextColor(15, 23, 42);
    doc.text(report.sha256, col1 + 26, y + 31);

    y += metaBoxHeight + 4;

    // Security Mitigations & Boundary Controls sub-strip
    if (report.mitigations.length > 0) {
      ensureSpace(16);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8.5);
      doc.setTextColor(51, 65, 85);
      doc.text('Observed Boundary Mitigations & Controls:', marginX, y + 3);
      y += 6;

      report.mitigations.forEach((m) => {
        ensureSpace(6);
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(8.5);
        doc.setTextColor(15, 23, 42);
        doc.text(`• ${m.label}: ${m.status}`, marginX + 2, y);

        doc.setFont('helvetica', 'normal');
        doc.setTextColor(71, 85, 105);
        doc.text(` — ${m.detail}`, marginX + 2 + doc.getTextWidth(`• ${m.label}: ${m.status}`), y);
        y += 4.8;
      });
      y += 3;
    }
  }

  // =========================================================================
  // 3. EPISTEMIC EVIDENCE LEDGER
  // =========================================================================
  if (options.includeEvidenceLedger) {
    const selectedRecords: EvidenceRecord[] = report.evidenceLedger.filter(
      (rec) => options.includedCategories[rec.category]
    );

    ensureSpace(22);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(15, 23, 42);
    doc.text(
      `02. Epistemic Evidence Ledger (${selectedRecords.length} Provenance Records)`,
      marginX,
      y
    );
    y += 4.5;

    // Category tally bar
    const counts = {
      observed: selectedRecords.filter((r) => r.category === 'observed').length,
      derived: selectedRecords.filter((r) => r.category === 'derived').length,
      inferred: selectedRecords.filter((r) => r.category === 'inferred').length,
      unknown: selectedRecords.filter((r) => r.category === 'unknown').length,
    };
    doc.setFont('courier', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(71, 85, 105);
    doc.text(
      `Observed: ${counts.observed}   ·   Derived: ${counts.derived}   ·   Inferred: ${counts.inferred}   ·   Unknowns: ${counts.unknown}`,
      marginX,
      y
    );
    y += 5;

    if (selectedRecords.length === 0) {
      doc.setFont('helvetica', 'italic');
      doc.setFontSize(9);
      doc.setTextColor(100, 116, 139);
      doc.text('No evidence records match the selected category filters.', marginX, y);
      y += 8;
    } else {
      selectedRecords.forEach((item, index) => {
        const style = CATEGORY_COLORS[item.category];
        const statementLines = doc.splitTextToSize(item.statement, contentWidth - 8);
        const snippetLines = item.snippet
          ? doc.splitTextToSize(item.snippet, contentWidth - 12)
          : [];

        const snippetBoxH =
          snippetLines.length > 0 ? Math.min(snippetLines.length, 10) * 3.8 + 5 : 0;
        const cardH = 14 + statementLines.length * 4.3 + (snippetBoxH > 0 ? snippetBoxH + 3 : 0);

        ensureSpace(cardH + 4);

        // Card container
        doc.setFillColor(255, 255, 255);
        doc.setDrawColor(203, 213, 225);
        doc.setLineWidth(0.28);
        doc.rect(marginX, y, contentWidth, cardH, 'FD');

        // Header strip inside card
        doc.setFillColor(style.bg[0], style.bg[1], style.bg[2]);
        doc.rect(marginX + 0.3, y + 0.3, contentWidth - 0.6, 6.5, 'F');

        doc.setFont('courier', 'bold');
        doc.setFontSize(7.5);
        doc.setTextColor(style.text[0], style.text[1], style.text[2]);
        const headerLeft = `#${(index + 1).toString().padStart(2, '0')} · ${style.label} · ${item.provenance}`;
        doc.text(headerLeft.slice(0, 82), marginX + 3.5, y + 4.6);

        doc.setFont('courier', 'normal');
        doc.setFontSize(7.5);
        doc.setTextColor(71, 85, 105);
        doc.text(`via ${item.toolUsed}`, pageWidth - marginX - 3.5, y + 4.6, {
          align: 'right',
        });

        // Evidence Title
        let innerY = y + 11.5;
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(9.5);
        doc.setTextColor(15, 23, 42);
        doc.text(item.title, marginX + 4, innerY);
        innerY += 4.5;

        // Evidence Statement
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(8.8);
        doc.setTextColor(51, 65, 85);
        doc.text(statementLines, marginX + 4, innerY);
        innerY += statementLines.length * 4.3;

        // Optional Monospace Byte / AST Snippet
        if (snippetLines.length > 0) {
          const cappedSnippet = snippetLines.slice(0, 10);
          doc.setFillColor(248, 250, 252);
          doc.setDrawColor(226, 232, 240);
          doc.setLineWidth(0.2);
          doc.rect(marginX + 4, innerY, contentWidth - 8, snippetBoxH, 'FD');

          doc.setFont('courier', 'normal');
          doc.setFontSize(7.5);
          doc.setTextColor(30, 41, 59);
          doc.text(cappedSnippet, marginX + 6, innerY + 3.8);
        }

        y += cardH + 3.5;
      });
    }
    y += 3;
  }

  // =========================================================================
  // 4. RECONSTRUCTED SOURCE CODE & VERIFICATION NOTES
  // =========================================================================
  if (options.includeReconstructedCode && report.reconstructedSource.code) {
    ensureSpace(36);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(15, 23, 42);
    doc.text('03. Reconstructed Implementation & Conformance Verification', marginX, y);
    y += 4.5;

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9);
    doc.setTextColor(51, 65, 85);
    doc.text(
      `${report.reconstructedSource.title} (${report.reconstructedSource.language})`,
      marginX,
      y
    );
    y += 4.5;

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8.5);
    doc.setTextColor(6, 95, 70);
    const verLines = doc.splitTextToSize(
      `Verification: ${report.reconstructedSource.verificationNote}`,
      contentWidth
    );
    doc.text(verLines, marginX, y);
    y += verLines.length * 4.2 + 2;

    // Paginate code lines cleanly
    const rawCodeLines = report.reconstructedSource.code.split(/\r?\n/);
    const wrappedCodeLines: string[] = [];
    rawCodeLines.forEach((line, idx) => {
      const numbered = `${(idx + 1).toString().padStart(2, '0')} | ${line}`;
      const split = doc.splitTextToSize(numbered, contentWidth - 8);
      wrappedCodeLines.push(...split);
    });

    const lineHeight = 3.9;
    let cursor = 0;
    while (cursor < wrappedCodeLines.length) {
      ensureSpace(18);
      const availableMm = bottomLimit - y - 6;
      const maxLinesThisPage = Math.max(1, Math.floor(availableMm / lineHeight));
      const chunk = wrappedCodeLines.slice(cursor, cursor + maxLinesThisPage);
      const boxH = chunk.length * lineHeight + 6;

      doc.setFillColor(248, 250, 252);
      doc.setDrawColor(203, 213, 225);
      doc.setLineWidth(0.25);
      doc.rect(marginX, y, contentWidth, boxH, 'FD');

      doc.setFont('courier', 'normal');
      doc.setFontSize(7.8);
      doc.setTextColor(15, 23, 42);
      doc.text(chunk, marginX + 4, y + 4.5);

      y += boxH + 4;
      cursor += chunk.length;
    }
  }

  // =========================================================================
  // 5. RUNNING PAGE FOOTERS (PAGE X OF Y)
  // =========================================================================
  const totalPages = doc.getNumberOfPages();
  for (let p = 1; p <= totalPages; p++) {
    doc.setPage(p);
    doc.setDrawColor(203, 213, 225);
    doc.setLineWidth(0.25);
    doc.line(marginX, pageHeight - 13, pageWidth - marginX, pageHeight - 13);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.8);
    doc.setTextColor(100, 116, 139);
    doc.text(
      `Reverse Psychology · Formal Evidence Ledger · SHA-256: ${report.sha256.slice(0, 16)}...`,
      marginX,
      pageHeight - 8.5
    );
    doc.text(`Page ${p} of ${totalPages}`, pageWidth - marginX, pageHeight - 8.5, {
      align: 'right',
    });
  }

  const safeSlug = report.targetName
    .replace(/[^a-zA-Z0-9._-]/g, '-')
    .replace(/\.+/g, '.');
  const filename = `${safeSlug}-evidence-report.pdf`;
  doc.save(filename);
  return filename;
}
