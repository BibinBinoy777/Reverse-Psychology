'use client';

import React, { useState, useEffect, useRef, useMemo } from 'react';
import {
  Upload,
  Search,
  Copy,
  Check,
  Download,
  Sparkles,
  RefreshCw,
  FileText,
  X,
  GitCompare,
  Columns2,
  AlignJustify,
  PlusCircle,
  ArrowUpRight,
  ChevronDown,
  ChevronRight,
} from 'lucide-react';
import {
  analyzeArtifact,
  AnalysisReport,
  EvidenceCategory,
  EvidenceRecord,
  SymbolKind,
} from '@/lib/analyzers';
import { SAMPLE_ARTIFACT_PRESETS } from '@/lib/sample-targets';
import { generateEvidencePdfReport } from '@/lib/pdf-report';
import { buildBinaryDiffReport, BinaryDiffReport } from '@/lib/diff-engine';

type WorkbenchTab =
  | 'disassembly'
  | 'decompiler'
  | 'sections'
  | 'hexdump'
  | 'strings';

type DiffSubView = 'instructions' | 'pseudocode' | 'control-flow';
type DiffLayoutMode = 'split' | 'unified';

export default function ReversePsychologyApp() {
  const [selectedPresetId, setSelectedPresetId] = useState<string>('dx-ball-elf');
  const [report, setReport] = useState<AnalysisReport | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [activeWorkbenchTab, setActiveWorkbenchTab] = useState<WorkbenchTab>('disassembly');
  const [insnSearch, setInsnSearch] = useState<string>('');
  const [evidenceFilter, setEvidenceFilter] = useState<'all' | EvidenceCategory>('all');

  // Symbol Explorer Sidebar & One-Click Disassembly Navigation State
  const [symbolSearchQuery, setSymbolSearchQuery] = useState<string>('');
  const [symbolCategoryFilter, setSymbolCategoryFilter] = useState<'all' | SymbolKind>('all');
  const [selectedSymbolAddress, setSelectedSymbolAddress] = useState<string | null>(null);
  const [selectedSymbolLabel, setSelectedSymbolLabel] = useState<string | null>(null);
  const [collapsedLibraries, setCollapsedLibraries] = useState<Record<string, boolean>>({});
  const disassemblyContainerRef = useRef<HTMLDivElement | null>(null);

  // Visual Diffing Engine State
  const [comparisonSource, setComparisonSource] = useState<string>('paired-patch');
  const [comparisonReport, setComparisonReport] = useState<AnalysisReport | null>(null);
  const [diffSubView, setDiffSubView] = useState<DiffSubView>('instructions');
  const [diffLayoutMode, setDiffLayoutMode] = useState<DiffLayoutMode>('split');
  const [showChangesOnly, setShowChangesOnly] = useState<boolean>(false);
  const [syncScrollEnabled, setSyncScrollEnabled] = useState<boolean>(true);
  const [diffRecordedBanner, setDiffRecordedBanner] = useState<boolean>(false);

  const leftSplitRef = useRef<HTMLDivElement | null>(null);
  const rightSplitRef = useRef<HTMLDivElement | null>(null);
  const isSyncingScrollRef = useRef<boolean>(false);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const comparisonFileInputRef = useRef<HTMLInputElement | null>(null);

  // AI Investigation state
  const [analystQuestion, setAnalystQuestion] = useState<string>(
    SAMPLE_ARTIFACT_PRESETS[0]!.defaultQuestion
  );
  const [isInterrogating, setIsInterrogating] = useState<boolean>(false);
  const [aiSummary, setAiSummary] = useState<string | null>(null);
  const [aiError, setAiError] = useState<string | null>(null);

  // PDF Export Quick Configure Modal state
  const [isPdfModalOpen, setIsPdfModalOpen] = useState<boolean>(false);
  const [pdfReportTitle, setPdfReportTitle] = useState<string>('');
  const [pdfAuthorName, setPdfAuthorName] = useState<string>('Lead Reverse Engineer');
  const [pdfCaseId, setPdfCaseId] = useState<string>('');
  const [pdfAnalystNotes, setPdfAnalystNotes] = useState<string>('');
  const [pdfIncludeTargetHeader, setPdfIncludeTargetHeader] = useState<boolean>(true);
  const [pdfIncludeEvidenceLedger, setPdfIncludeEvidenceLedger] = useState<boolean>(true);
  const [pdfIncludeReconstructedCode, setPdfIncludeReconstructedCode] = useState<boolean>(true);
  const [pdfIncludeAiSummary, setPdfIncludeAiSummary] = useState<boolean>(true);
  const [pdfCategories, setPdfCategories] = useState<Record<EvidenceCategory, boolean>>({
    observed: true,
    derived: true,
    inferred: true,
    unknown: true,
  });
  const [pdfExportDownloadedFile, setPdfExportDownloadedFile] = useState<string | null>(null);

  // Copy feedback
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Load initial preset analysis + paired patched v2 comparison
  useEffect(() => {
    const preset =
      SAMPLE_ARTIFACT_PRESETS.find((p) => p.id === selectedPresetId) ??
      SAMPLE_ARTIFACT_PRESETS[0]!;
    setAnalystQuestion(preset.defaultQuestion);
    setAiSummary(null);
    setAiError(null);
    setDiffRecordedBanner(false);
    setIsAnalyzing(true);
    const bytes = preset.buildBytes();
    const patchedBytes = preset.buildPatchedBytes();
    Promise.all([
      analyzeArtifact(preset.fileName, bytes),
      analyzeArtifact(preset.patchedFileName, patchedBytes),
    ])
      .then(([baseRes, patchedRes]) => {
        setReport(baseRes);
        setComparisonSource('paired-patch');
        setComparisonReport(patchedRes);
        const firstFn = baseRes.symbols.find((s) => s.kind === 'function') ?? baseRes.symbols[0];
        setSelectedSymbolAddress(firstFn?.address ?? baseRes.entryPoint);
        setSelectedSymbolLabel(firstFn?.name ?? 'Entry Point');
      })
      .finally(() => {
        setIsAnalyzing(false);
      });
  }, [selectedPresetId]);

  // Handle comparison source selection change
  const handleComparisonSourceChange = async (nextSource: string) => {
    setComparisonSource(nextSource);
    setDiffRecordedBanner(false);
    const activePreset =
      SAMPLE_ARTIFACT_PRESETS.find((p) => p.id === selectedPresetId) ??
      SAMPLE_ARTIFACT_PRESETS[0]!;

    if (nextSource === 'paired-patch') {
      const patched = await analyzeArtifact(
        activePreset.patchedFileName,
        activePreset.buildPatchedBytes()
      );
      setComparisonReport(patched);
      return;
    }

    const otherPreset = SAMPLE_ARTIFACT_PRESETS.find((p) => p.id === nextSource);
    if (otherPreset) {
      const otherReport = await analyzeArtifact(
        otherPreset.fileName,
        otherPreset.buildBytes()
      );
      setComparisonReport(otherReport);
    }
  };

  // Handle custom comparison (Version B) file upload
  const handleComparisonFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setDiffRecordedBanner(false);
    const arrayBuffer = await file.arrayBuffer();
    const bytes = new Uint8Array(arrayBuffer);
    const result = await analyzeArtifact(file.name, bytes);
    setComparisonSource('custom-upload');
    setComparisonReport(result);
  };

  // Synchronized scroll handler for Side-by-Side Split Diff panes
  const handleSplitScroll = (source: 'left' | 'right') => {
    if (!syncScrollEnabled || isSyncingScrollRef.current) return;
    const leftEl = leftSplitRef.current;
    const rightEl = rightSplitRef.current;
    if (!leftEl || !rightEl) return;

    isSyncingScrollRef.current = true;
    if (source === 'left') {
      rightEl.scrollTop = leftEl.scrollTop;
    } else {
      leftEl.scrollTop = rightEl.scrollTop;
    }
    requestAnimationFrame(() => {
      isSyncingScrollRef.current = false;
    });
  };

  // Compute live BinaryDiffReport between Baseline (report) and Comparison (comparisonReport)
  const diffReport: BinaryDiffReport | null = useMemo(() => {
    if (!report || !comparisonReport) return null;
    return buildBinaryDiffReport(report, comparisonReport);
  }, [report, comparisonReport]);

  const filteredDiffInstructions = useMemo(() => {
    if (!diffReport) return [];
    if (!showChangesOnly) return diffReport.instructionRows;
    return diffReport.instructionRows.filter((r) => r.kind !== 'unchanged');
  }, [diffReport, showChangesOnly]);

  const filteredDiffPseudocode = useMemo(() => {
    if (!diffReport) return [];
    if (!showChangesOnly) return diffReport.pseudocodeRows;
    return diffReport.pseudocodeRows.filter((r) => r.kind !== 'unchanged');
  }, [diffReport, showChangesOnly]);

  const filteredControlFlowDeltas = useMemo(() => {
    if (!diffReport) return [];
    if (!showChangesOnly) return diffReport.controlFlowDeltas;
    return diffReport.controlFlowDeltas.filter((d) => d.changeType !== 'unchanged');
  }, [diffReport, showChangesOnly]);

  // Commit Visual Diff findings to Epistemic Evidence Ledger
  const handleRecordDiffInLedger = () => {
    if (!report || !comparisonReport || !diffReport) return;
    const mutatedHighlights = diffReport.instructionRows
      .filter((r) => r.kind !== 'unchanged')
      .slice(0, 6)
      .map((r) => `[${r.kind.toUpperCase()}] ${r.deltaSummary ?? ''}`)
      .join('\n');

    const newEvidence: EvidenceRecord = {
      id: `ev-diff-${Date.now()}`,
      category: 'derived',
      title: `Binary & CFG Diff: ${report.targetName} vs ${comparisonReport.targetName}`,
      statement: `Compared baseline (${report.sha256.slice(0, 12)}...) against ${comparisonReport.targetName} (${comparisonReport.sha256.slice(0, 12)}...). Identified ${diffReport.metrics.modifiedInsns} modified instructions, ${diffReport.metrics.addedInsns} added instructions, ${diffReport.metrics.removedInsns} removed instructions, and ${diffReport.metrics.branchMutations} control-flow block deltas (${diffReport.metrics.similarityPercent}% structural similarity).`,
      provenance: `diff(${report.entryPoint} <-> ${comparisonReport.entryPoint})`,
      confidence: 'structural',
      toolUsed: 'rp_visual_diff_engine',
      snippet: mutatedHighlights || 'Identical instruction stream.',
    };

    setReport((prev) =>
      prev
        ? {
            ...prev,
            evidenceLedger: [newEvidence, ...prev.evidenceLedger],
          }
        : prev
    );
    setDiffRecordedBanner(true);
  };

  // Handle custom file upload (Baseline Version A)
  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setIsAnalyzing(true);
    setAiSummary(null);
    setAiError(null);
    try {
      const arrayBuffer = await file.arrayBuffer();
      const bytes = new Uint8Array(arrayBuffer);
      const result = await analyzeArtifact(file.name, bytes);
      setReport(result);
      const firstFn = result.symbols.find((s) => s.kind === 'function') ?? result.symbols[0];
      setSelectedSymbolAddress(firstFn?.address ?? result.entryPoint);
      setSelectedSymbolLabel(firstFn?.name ?? 'Entry Point');
      setAnalystQuestion(
        `Inspect ${file.name} (${result.format}), explain its primary entry logic, and provide a clean code reconstruction with evidence provenance.`
      );
    } finally {
      setIsAnalyzing(false);
    }
  };

  // Open Quick Configure Modal for PDF Report
  const handleOpenPdfModal = () => {
    if (!report) return;
    setPdfReportTitle(`Reverse Psychology Evidence Report — ${report.targetName}`);
    setPdfCaseId(`RP-${report.sha256.slice(0, 8).toUpperCase()}`);
    setPdfExportDownloadedFile(null);
    if (evidenceFilter === 'all') {
      setPdfCategories({
        observed: true,
        derived: true,
        inferred: true,
        unknown: true,
      });
    } else {
      setPdfCategories({
        observed: evidenceFilter === 'observed',
        derived: evidenceFilter === 'derived',
        inferred: evidenceFilter === 'inferred',
        unknown: evidenceFilter === 'unknown',
      });
    }
    setIsPdfModalOpen(true);
  };

  const handleGeneratePdf = () => {
    if (!report) return;
    const savedName = generateEvidencePdfReport(report, {
      reportTitle: pdfReportTitle,
      authorName: pdfAuthorName,
      caseId: pdfCaseId,
      analystNotes: pdfAnalystNotes,
      includeTargetHeader: pdfIncludeTargetHeader,
      includeEvidenceLedger: pdfIncludeEvidenceLedger,
      includeReconstructedCode: pdfIncludeReconstructedCode,
      includeAiSummary: pdfIncludeAiSummary,
      aiSummaryText: aiSummary,
      includedCategories: pdfCategories,
    });
    setPdfExportDownloadedFile(savedName);
  };

  // Trigger Gemini Evidence-Backed Interrogation
  const handleRunInvestigation = async () => {
    if (!report || !analystQuestion.trim()) return;
    setIsInterrogating(true);
    setAiError(null);
    try {
      const response = await fetch('/api/investigate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          question: analystQuestion,
          targetName: report.targetName,
          format: report.format,
          architecture: report.architecture,
          entryPoint: report.entryPoint,
          sha256: report.sha256,
          instructions: report.instructions,
          decompiledPseudocode: report.decompiledPseudocode,
          strings: report.strings,
          sections: report.sections,
        }),
      });
      const data = await response.json();
      if (!response.ok || data.error) {
        throw new Error(data.error || 'Failed to run interrogation');
      }

      setAiSummary(data.executiveSummary);

      const newRecords: EvidenceRecord[] = [];
      (data.observedFacts ?? []).forEach(
        (item: { title: string; statement: string; provenance: string }, i: number) => {
          newRecords.push({
            id: `ai-obs-${Date.now()}-${i}`,
            category: 'observed',
            title: item.title,
            statement: item.statement,
            provenance: item.provenance,
            confidence: 'exact',
            toolUsed: 'rp_interrogate (observed)',
          });
        }
      );
      (data.derivedAnalysis ?? []).forEach(
        (item: { title: string; statement: string; provenance: string }, i: number) => {
          newRecords.push({
            id: `ai-der-${Date.now()}-${i}`,
            category: 'derived',
            title: item.title,
            statement: item.statement,
            provenance: item.provenance,
            confidence: 'structural',
            toolUsed: 'rp_interrogate (derived)',
          });
        }
      );
      (data.inferredIntent ?? []).forEach(
        (item: { title: string; statement: string; provenance: string }, i: number) => {
          newRecords.push({
            id: `ai-inf-${Date.now()}-${i}`,
            category: 'inferred',
            title: item.title,
            statement: item.statement,
            provenance: item.provenance,
            confidence: 'heuristic',
            toolUsed: 'rp_interrogate (inferred)',
          });
        }
      );
      (data.unknownsAndLimits ?? []).forEach(
        (item: { title: string; statement: string; provenance: string }, i: number) => {
          newRecords.push({
            id: `ai-unk-${Date.now()}-${i}`,
            category: 'unknown',
            title: item.title,
            statement: item.statement,
            provenance: item.provenance,
            confidence: 'unresolved',
            toolUsed: 'rp_interrogate (unknown)',
          });
        }
      );

      setReport((prev) =>
        prev
          ? {
              ...prev,
              reconstructedSource: data.reconstructedCode
                ? {
                    language: data.reconstructedLanguage || prev.reconstructedSource.language,
                    title: 'AI-Synthesized & Evidence-Backed Reconstruction',
                    code: data.reconstructedCode,
                    verificationNote:
                      'Grounded in extracted Evidence Ledger provenance and static disassembly.',
                  }
                : prev.reconstructedSource,
              evidenceLedger: [...newRecords, ...prev.evidenceLedger],
            }
          : prev
      );
    } catch (err: unknown) {
      setAiError(
        err instanceof Error ? err.message : 'Unable to complete AI investigation.'
      );
    } finally {
      setIsInterrogating(false);
    }
  };

  const handleCopy = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1800);
  };

  const handleDownloadJson = (filename: string, data: unknown) => {
    const blob = new Blob([JSON.stringify(data, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Filtered instructions
  const filteredInstructions = useMemo(() => {
    if (!report) return [];
    if (!insnSearch.trim()) return report.instructions;
    const q = insnSearch.toLowerCase();
    return report.instructions.filter(
      (ins) =>
        ins.address.toLowerCase().includes(q) ||
        ins.mnemonic.toLowerCase().includes(q) ||
        ins.operands.toLowerCase().includes(q) ||
        (ins.comment && ins.comment.toLowerCase().includes(q))
    );
  }, [report, insnSearch]);

  // Filtered symbols & dynamic libraries for Symbol Explorer Sidebar
  const filteredSymbols = useMemo(() => {
    if (!report) return [];
    const q = symbolSearchQuery.trim().toLowerCase();
    return report.symbols.filter((sym) => {
      const matchesCat =
        symbolCategoryFilter === 'all' || sym.kind === symbolCategoryFilter;
      if (!matchesCat) return false;
      if (!q) return true;
      return (
        sym.name.toLowerCase().includes(q) ||
        (sym.demangledName && sym.demangledName.toLowerCase().includes(q)) ||
        sym.address.toLowerCase().includes(q) ||
        sym.section.toLowerCase().includes(q) ||
        (sym.library && sym.library.toLowerCase().includes(q)) ||
        (sym.signature && sym.signature.toLowerCase().includes(q))
      );
    });
  }, [report, symbolSearchQuery, symbolCategoryFilter]);

  const filteredFunctionSymbols = useMemo(
    () => filteredSymbols.filter((s) => s.kind === 'function'),
    [filteredSymbols]
  );

  const filteredExportSymbols = useMemo(
    () => filteredSymbols.filter((s) => s.kind === 'export'),
    [filteredSymbols]
  );

  const filteredDynamicLibraries = useMemo(() => {
    if (!report) return [];
    if (symbolCategoryFilter !== 'all' && symbolCategoryFilter !== 'import') {
      return [];
    }
    const q = symbolSearchQuery.trim().toLowerCase();
    if (!q) return report.dynamicLibraries;
    return report.dynamicLibraries
      .map((lib) => {
        const libMatches =
          lib.name.toLowerCase().includes(q) ||
          lib.version.toLowerCase().includes(q);
        const matchingImports = lib.importedSymbols.filter(
          (imp) =>
            imp.name.toLowerCase().includes(q) ||
            imp.address.toLowerCase().includes(q) ||
            imp.slotType.toLowerCase().includes(q)
        );
        if (libMatches) return lib;
        if (matchingImports.length > 0) {
          return { ...lib, importedSymbols: matchingImports };
        }
        return null;
      })
      .filter((lib): lib is NonNullable<typeof lib> => lib !== null);
  }, [report, symbolSearchQuery, symbolCategoryFilter]);

  // One-click navigation from Symbol Explorer Sidebar to Disassembly address
  const handleNavigateToSymbolAddress = (address: string, symbolName: string) => {
    setActiveWorkbenchTab('disassembly');
    if (insnSearch.trim() && !address.toLowerCase().includes(insnSearch.trim().toLowerCase())) {
      setInsnSearch('');
    }
    setSelectedSymbolAddress(address);
    setSelectedSymbolLabel(symbolName);

    requestAnimationFrame(() => {
      const container = disassemblyContainerRef.current;
      if (!container) return;
      const targetRow = container.querySelector<HTMLElement>(
        `[data-insn-address="${address}"]`
      );
      if (targetRow) {
        targetRow.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    });
  };

  const toggleLibraryCollapse = (libName: string) => {
    setCollapsedLibraries((prev) => ({
      ...prev,
      [libName]: !prev[libName],
    }));
  };

  // Filtered evidence ledger
  const filteredEvidence = useMemo(() => {
    if (!report) return [];
    if (evidenceFilter === 'all') return report.evidenceLedger;
    return report.evidenceLedger.filter((e) => e.category === evidenceFilter);
  }, [report, evidenceFilter]);

  // Selected Evidence count for PDF modal preview
  const pdfSelectedEvidenceCount = useMemo(() => {
    if (!report || !pdfIncludeEvidenceLedger) return 0;
    return report.evidenceLedger.filter((e) => pdfCategories[e.category]).length;
  }, [report, pdfIncludeEvidenceLedger, pdfCategories]);

  const pdfSelectedSectionCount = useMemo(() => {
    let count = 0;
    if (pdfIncludeTargetHeader) count++;
    if (pdfIncludeEvidenceLedger) count++;
    if (pdfIncludeReconstructedCode) count++;
    if (pdfIncludeAiSummary && aiSummary) count++;
    return count;
  }, [
    pdfIncludeTargetHeader,
    pdfIncludeEvidenceLedger,
    pdfIncludeReconstructedCode,
    pdfIncludeAiSummary,
    aiSummary,
  ]);

  const activePresetMeta =
    SAMPLE_ARTIFACT_PRESETS.find((p) => p.id === selectedPresetId) ??
    SAMPLE_ARTIFACT_PRESETS[0]!;

  return (
    <div className="min-h-screen bg-[#0B0F17] text-slate-100 flex flex-col">
      {/* Hidden file input for Baseline (Version A) upload */}
      <input
        ref={fileInputRef}
        type="file"
        onChange={handleFileUpload}
        className="hidden"
        accept=".elf,.exe,.dll,.so,.dylib,.com,.wasm,.evm,.js,.mjs,.cjs,.har,.json,.bin,.dat"
      />
      {/* Hidden file input for Comparison (Version B) upload */}
      <input
        ref={comparisonFileInputRef}
        type="file"
        onChange={handleComparisonFileUpload}
        className="hidden"
        accept=".elf,.exe,.dll,.so,.dylib,.com,.wasm,.evm,.js,.mjs,.cjs,.har,.json,.bin,.dat"
      />

      {/* Strict 3-Zone Top Bar Contract */}
      <header className="sticky top-0 z-30 flex items-center justify-between gap-8 px-6 py-3.5 bg-[#0B0F17]/95 backdrop-blur border-b border-slate-800/80">
        {/* Zone 1: Single text element wordmark */}
        <a
          href="#workbench"
          className="text-lg font-bold tracking-tight text-white whitespace-nowrap shrink-0 font-display"
        >
          Reverse Psychology
        </a>

        {/* Zone 2: Concise single-line navigation links */}
        <nav className="hidden md:flex items-center gap-6 text-sm font-medium text-slate-400">
          <a
            href="#workbench"
            className="hover:text-white hover:underline underline-offset-4 transition-colors whitespace-nowrap shrink-0"
          >
            Workbench
          </a>
          <a
            href="#visual-diff-studio"
            className="hover:text-white hover:underline underline-offset-4 transition-colors whitespace-nowrap shrink-0"
          >
            Visual Diff
          </a>
          <a
            href="#evidence-ledger"
            className="hover:text-white hover:underline underline-offset-4 transition-colors whitespace-nowrap shrink-0"
          >
            Evidence Ledger
          </a>
        </nav>

        {/* Zone 3: 1 primary action */}
        <div className="flex items-center shrink-0">
          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            className="px-4 py-2 text-xs font-semibold text-white bg-indigo-600 rounded-lg hover:bg-indigo-500 transition-colors whitespace-nowrap shrink-0 flex items-center gap-2 cursor-pointer"
          >
            <Upload className="w-3.5 h-3.5" />
            <span>Upload Artifact</span>
          </button>
        </div>
      </header>

      <main className="flex-1 max-w-[1400px] w-full mx-auto px-6 py-8 space-y-12">
        {/* Section 01: Core Reverse Engineering Workbench */}
        <section id="workbench" className="space-y-5 scroll-mt-16">
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
            <div className="space-y-0.5">
              <div className="text-xs text-slate-400">
                01. Binary, Bytecode, Bundle &amp; Capture Inspector
              </div>
              <h1 className="text-2xl font-bold text-white font-display">
                Analysis Workbench
              </h1>
            </div>

            {/* Interactive Preset Switcher */}
            <div className="flex flex-wrap items-center gap-1.5 p-1 bg-[#111827] border border-slate-800 rounded-lg">
              {SAMPLE_ARTIFACT_PRESETS.map((preset) => {
                const active = selectedPresetId === preset.id;
                return (
                  <button
                    key={preset.id}
                    type="button"
                    onClick={() => setSelectedPresetId(preset.id)}
                    className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                      active
                        ? 'bg-indigo-600 text-white'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                    }`}
                  >
                    {preset.fileName}
                  </button>
                );
              })}
            </div>
          </div>

          {isAnalyzing || !report ? (
            <div className="bg-[#111827] border border-slate-800 rounded-xl p-12 text-center space-y-3">
              <RefreshCw className="w-6 h-6 text-indigo-400 animate-spin mx-auto" />
              <div className="text-sm text-slate-300">
                Parsing headers, decoding instructions, and assembling Evidence Ledger...
              </div>
            </div>
          ) : (
            <div className="space-y-5">
              {/* Target Telemetry Strip */}
              <div className="bg-[#111827] border border-slate-800 rounded-xl px-5 py-4 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                <div className="space-y-1 min-w-0">
                  <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400 font-mono tabular-nums">
                    <span className="text-indigo-300 font-semibold">{report.targetName}</span>
                    <span aria-hidden="true">·</span>
                    <span>{report.format}</span>
                    <span aria-hidden="true">·</span>
                    <span>{report.architecture}</span>
                    <span aria-hidden="true">·</span>
                    <span>{report.sizeBytes} bytes</span>
                    <span aria-hidden="true">·</span>
                    <span>Entropy: {report.entropy} bits/byte</span>
                    <span aria-hidden="true">·</span>
                    <span>Entry: {report.entryPoint}</span>
                  </div>
                  <div className="text-xs text-slate-400 font-mono truncate tabular-nums">
                    SHA-256: <span className="text-slate-300">{report.sha256}</span>
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-2.5 shrink-0">
                  <a
                    href="#visual-diff-studio"
                    className="px-3.5 py-1.5 text-xs font-semibold text-slate-200 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0"
                  >
                    <GitCompare className="w-3.5 h-3.5 text-indigo-400" />
                    <span>Visual Diff</span>
                  </a>
                  <button
                    type="button"
                    onClick={handleOpenPdfModal}
                    className="px-3.5 py-1.5 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-500 rounded-lg transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    <FileText className="w-3.5 h-3.5" />
                    <span>Export PDF Report</span>
                  </button>
                  <button
                    type="button"
                    onClick={() =>
                      handleDownloadJson(`${report.targetName}.rp-snapshot.json`, report)
                    }
                    className="px-3 py-1.5 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>JSON</span>
                  </button>
                </div>
              </div>

              {/* 3-Column IDE Grid: Symbol Explorer (3 cols) + Disassembly/Inspector (5 cols) + AI Interrogation & Code (4 cols) */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
                {/* Left 3 Columns: Searchable Symbol Explorer Sidebar */}
                <aside
                  aria-label="Symbol Explorer Sidebar"
                  className="lg:col-span-3 bg-[#111827] border border-slate-800 rounded-xl overflow-hidden flex flex-col"
                >
                  <div className="p-3.5 border-b border-slate-800 bg-[#0E1420] space-y-3">
                    <div className="flex items-center justify-between gap-2">
                      <h2 className="text-xs font-semibold text-white font-display">
                        Symbol &amp; Library Explorer
                      </h2>
                      <span className="text-xs text-slate-400 font-mono tabular-nums">
                        {report.symbols.length} syms · {report.dynamicLibraries.length} libs
                      </span>
                    </div>

                    {/* Live Symbol Search Input */}
                    <div className="relative">
                      <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
                      <input
                        type="text"
                        value={symbolSearchQuery}
                        onChange={(e) => setSymbolSearchQuery(e.target.value)}
                        placeholder="Search functions, exports, libs, 0x..."
                        className="w-full pl-8 pr-7 py-1.5 text-xs bg-[#0B0F17] border border-slate-800 rounded-md text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-indigo-500"
                      />
                      {symbolSearchQuery && (
                        <button
                          type="button"
                          onClick={() => setSymbolSearchQuery('')}
                          className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-400 hover:text-white cursor-pointer"
                          title="Clear symbol search"
                        >
                          <X className="w-3.5 h-3.5" />
                        </button>
                      )}
                    </div>

                    {/* Interactive Symbol Category Filter Tabs */}
                    <div className="grid grid-cols-4 gap-1 p-1 bg-[#0B0F17] border border-slate-800/80 rounded-lg">
                      {(
                        [
                          { id: 'all', label: 'All' },
                          { id: 'function', label: 'Funcs' },
                          { id: 'export', label: 'Exports' },
                          { id: 'import', label: 'Libs' },
                        ] as { id: 'all' | SymbolKind; label: string }[]
                      ).map((tab) => (
                        <button
                          key={tab.id}
                          type="button"
                          onClick={() => setSymbolCategoryFilter(tab.id)}
                          className={`py-1 px-1.5 text-[11px] font-medium rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                            symbolCategoryFilter === tab.id
                              ? 'bg-indigo-600 text-white'
                              : 'text-slate-400 hover:text-slate-200'
                          }`}
                        >
                          {tab.label}
                        </button>
                      ))}
                    </div>
                  </div>

                  {/* Scrollable Symbol Groups */}
                  <div className="p-3 max-h-[540px] overflow-y-auto space-y-5 divide-y divide-slate-800/70">
                    {/* Group 1: Functions */}
                    {(symbolCategoryFilter === 'all' || symbolCategoryFilter === 'function') && (
                      <div className="space-y-2">
                        <div className="flex items-center justify-between text-[11px] text-slate-400 font-mono tabular-nums px-1">
                          <span className="font-semibold text-slate-300 font-sans">
                            Functions
                          </span>
                          <span>{filteredFunctionSymbols.length}</span>
                        </div>

                        {filteredFunctionSymbols.length === 0 ? (
                          <div className="text-xs text-slate-500 px-1 py-2">
                            No matching functions found.
                          </div>
                        ) : (
                          <div className="space-y-1">
                            {filteredFunctionSymbols.map((fn) => {
                              const isSelected =
                                selectedSymbolAddress === fn.address &&
                                selectedSymbolLabel === fn.name;
                              return (
                                <button
                                  key={fn.id}
                                  type="button"
                                  onClick={() =>
                                    handleNavigateToSymbolAddress(fn.address, fn.name)
                                  }
                                  className={`w-full text-left p-2 rounded-lg border transition-colors cursor-pointer group ${
                                    isSelected
                                      ? 'bg-indigo-950/50 border-indigo-500/70 text-white'
                                      : 'bg-[#0B0F17]/70 border-slate-800/70 hover:bg-slate-800/60 hover:border-slate-700 text-slate-200'
                                  }`}
                                >
                                  <div className="flex items-center justify-between gap-2">
                                    <span className="font-mono text-xs font-semibold text-indigo-300 group-hover:text-indigo-200 truncate">
                                      {fn.name}
                                    </span>
                                    <span className="font-mono text-[11px] text-slate-400 group-hover:text-white shrink-0 tabular-nums flex items-center gap-0.5">
                                      <span>{fn.address}</span>
                                      <ArrowUpRight className="w-3 h-3 opacity-70" />
                                    </span>
                                  </div>
                                  {fn.signature && (
                                    <div className="text-[11px] text-slate-400 font-mono truncate mt-0.5">
                                      {fn.signature}
                                    </div>
                                  )}
                                  <div className="flex items-center gap-1.5 text-[11px] text-slate-500 mt-1 font-mono tabular-nums">
                                    <span>{fn.section}</span>
                                    <span aria-hidden="true">·</span>
                                    <span>{fn.binding}</span>
                                    {fn.sizeBytes !== undefined && (
                                      <>
                                        <span aria-hidden="true">·</span>
                                        <span>{fn.sizeBytes} B</span>
                                      </>
                                    )}
                                  </div>
                                </button>
                              );
                            })}
                          </div>
                        )}
                      </div>
                    )}

                    {/* Group 2: Exported Symbols */}
                    {(symbolCategoryFilter === 'all' || symbolCategoryFilter === 'export') && (
                      <div className="space-y-2 pt-4 first:pt-0">
                        <div className="flex items-center justify-between text-[11px] text-slate-400 font-mono tabular-nums px-1">
                          <span className="font-semibold text-slate-300 font-sans">
                            Exported Symbols
                          </span>
                          <span>{filteredExportSymbols.length}</span>
                        </div>

                        {filteredExportSymbols.length === 0 ? (
                          <div className="text-xs text-slate-500 px-1 py-2">
                            No matching exported symbols.
                          </div>
                        ) : (
                          <div className="space-y-1">
                            {filteredExportSymbols.map((exp) => {
                              const isSelected =
                                selectedSymbolAddress === exp.address &&
                                selectedSymbolLabel === exp.name;
                              return (
                                <button
                                  key={exp.id}
                                  type="button"
                                  onClick={() =>
                                    handleNavigateToSymbolAddress(exp.address, exp.name)
                                  }
                                  className={`w-full text-left p-2 rounded-lg border transition-colors cursor-pointer group ${
                                    isSelected
                                      ? 'bg-emerald-950/40 border-emerald-500/70 text-white'
                                      : 'bg-[#0B0F17]/70 border-slate-800/70 hover:bg-slate-800/60 hover:border-slate-700 text-slate-200'
                                  }`}
                                >
                                  <div className="flex items-center justify-between gap-2">
                                    <span className="font-mono text-xs font-semibold text-emerald-300 truncate">
                                      {exp.name}
                                    </span>
                                    <span className="font-mono text-[11px] text-slate-400 group-hover:text-white shrink-0 tabular-nums flex items-center gap-0.5">
                                      <span>{exp.address}</span>
                                      <ArrowUpRight className="w-3 h-3 opacity-70" />
                                    </span>
                                  </div>
                                  <div className="flex items-center gap-1.5 text-[11px] text-slate-500 mt-1 font-mono tabular-nums truncate">
                                    <span>{exp.section}</span>
                                    <span aria-hidden="true">·</span>
                                    <span>{exp.binding}</span>
                                    {exp.signature && (
                                      <>
                                        <span aria-hidden="true">·</span>
                                        <span className="truncate">{exp.signature}</span>
                                      </>
                                    )}
                                  </div>
                                </button>
                              );
                            })}
                          </div>
                        )}
                      </div>
                    )}

                    {/* Group 3: Imported Dynamic Libraries */}
                    {(symbolCategoryFilter === 'all' || symbolCategoryFilter === 'import') && (
                      <div className="space-y-2 pt-4 first:pt-0">
                        <div className="flex items-center justify-between text-[11px] text-slate-400 font-mono tabular-nums px-1">
                          <span className="font-semibold text-slate-300 font-sans">
                            Imported Dynamic Libraries
                          </span>
                          <span>{filteredDynamicLibraries.length}</span>
                        </div>

                        {filteredDynamicLibraries.length === 0 ? (
                          <div className="text-xs text-slate-500 px-1 py-2">
                            No matching dynamic libraries or imports.
                          </div>
                        ) : (
                          <div className="space-y-2">
                            {filteredDynamicLibraries.map((lib) => {
                              const isCollapsed = !!collapsedLibraries[lib.name];
                              return (
                                <div
                                  key={lib.name}
                                  className="bg-[#0B0F17]/80 border border-slate-800/80 rounded-lg overflow-hidden"
                                >
                                  <button
                                    type="button"
                                    onClick={() => toggleLibraryCollapse(lib.name)}
                                    className="w-full px-2.5 py-2 flex items-center justify-between gap-2 text-left hover:bg-slate-800/40 transition-colors cursor-pointer"
                                  >
                                    <div className="min-w-0">
                                      <div className="font-mono text-xs font-semibold text-amber-300 truncate">
                                        {lib.name}
                                      </div>
                                      <div className="text-[11px] text-slate-500 font-mono tabular-nums">
                                        {lib.version} · {lib.importedSymbols.length} imports
                                      </div>
                                    </div>
                                    {isCollapsed ? (
                                      <ChevronRight className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                                    ) : (
                                      <ChevronDown className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                                    )}
                                  </button>

                                  {!isCollapsed && (
                                    <div className="border-t border-slate-800/70 divide-y divide-slate-800/40">
                                      {lib.importedSymbols.map((imp, idx) => {
                                        const isSelected =
                                          selectedSymbolAddress === imp.address &&
                                          selectedSymbolLabel === imp.name;
                                        return (
                                          <button
                                            key={`${lib.name}-${idx}`}
                                            type="button"
                                            onClick={() =>
                                              handleNavigateToSymbolAddress(
                                                imp.address,
                                                imp.name
                                              )
                                            }
                                            className={`w-full px-2.5 py-1.5 text-left transition-colors cursor-pointer flex items-center justify-between gap-2 group ${
                                              isSelected
                                                ? 'bg-amber-950/40 text-white'
                                                : 'hover:bg-slate-800/50 text-slate-300'
                                            }`}
                                          >
                                            <div className="min-w-0">
                                              <div className="font-mono text-xs text-slate-200 group-hover:text-amber-200 truncate">
                                                {imp.name}
                                              </div>
                                              <div className="text-[10px] text-slate-500 font-mono truncate">
                                                {imp.slotType}
                                              </div>
                                            </div>
                                            <span className="font-mono text-[11px] text-slate-400 group-hover:text-white shrink-0 tabular-nums flex items-center gap-0.5">
                                              <span>{imp.address}</span>
                                              <ArrowUpRight className="w-3 h-3 opacity-70" />
                                            </span>
                                          </button>
                                        );
                                      })}
                                    </div>
                                  )}
                                </div>
                              );
                            })}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </aside>

                {/* Center 5 Columns: Low-level Inspection Views */}
                <div className="lg:col-span-5 bg-[#111827] border border-slate-800 rounded-xl overflow-hidden flex flex-col">
                  <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 border-b border-slate-800 bg-[#0E1420]">
                    <div className="flex flex-wrap items-center gap-1">
                      {(
                        [
                          { id: 'disassembly', label: 'Disassembly' },
                          { id: 'decompiler', label: 'Decompiler' },
                          { id: 'sections', label: 'Sections & IPC' },
                          { id: 'hexdump', label: 'Hex Dump' },
                          { id: 'strings', label: `Strings (${report.strings.length})` },
                        ] as { id: WorkbenchTab; label: string }[]
                      ).map((tab) => (
                        <button
                          key={tab.id}
                          type="button"
                          onClick={() => setActiveWorkbenchTab(tab.id)}
                          className={`px-2.5 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                            activeWorkbenchTab === tab.id
                              ? 'bg-slate-800 text-white'
                              : 'text-slate-400 hover:text-slate-200'
                          }`}
                        >
                          {tab.label}
                        </button>
                      ))}
                    </div>

                    {activeWorkbenchTab === 'disassembly' && (
                      <div className="relative">
                        <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
                        <input
                          type="text"
                          value={insnSearch}
                          onChange={(e) => setInsnSearch(e.target.value)}
                          placeholder="Filter address / mnemonic..."
                          className="pl-8 pr-3 py-1 text-xs bg-[#0B0F17] border border-slate-800 rounded-md text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-indigo-500 w-44"
                        />
                      </div>
                    )}
                  </div>

                  {/* Active Symbol Navigation Indicator Strip */}
                  {activeWorkbenchTab === 'disassembly' && selectedSymbolAddress && (
                    <div className="px-4 py-2 bg-[#0B0F17] border-b border-slate-800/80 flex items-center justify-between gap-2 text-xs font-mono tabular-nums">
                      <div className="flex items-center gap-2 min-w-0">
                        <span className="text-slate-400 font-sans">Focused Symbol:</span>
                        <span className="text-indigo-300 font-semibold truncate">
                          {selectedSymbolLabel ?? 'Address Target'}
                        </span>
                        <span className="text-slate-600">·</span>
                        <span className="text-emerald-300">{selectedSymbolAddress}</span>
                      </div>
                      <button
                        type="button"
                        onClick={() => {
                          setSelectedSymbolAddress(null);
                          setSelectedSymbolLabel(null);
                        }}
                        className="text-slate-400 hover:text-white font-sans text-[11px] whitespace-nowrap shrink-0 cursor-pointer"
                      >
                        Clear Focus
                      </button>
                    </div>
                  )}

                  {/* Tab Content Area */}
                  <div
                    ref={disassemblyContainerRef}
                    className="p-4 max-h-[540px] overflow-y-auto"
                  >
                    {activeWorkbenchTab === 'disassembly' && (
                      <div className="overflow-x-auto">
                        <table className="w-full text-left border-collapse font-mono text-xs tabular-nums">
                          <thead>
                            <tr className="border-b border-slate-800 text-slate-400">
                              <th className="py-2 pr-3 font-medium">Address</th>
                              <th className="py-2 px-3 font-medium">Offset</th>
                              <th className="py-2 px-3 font-medium">Bytes</th>
                              <th className="py-2 px-3 font-medium">Mnemonic</th>
                              <th className="py-2 px-3 font-medium">Operands</th>
                              <th className="py-2 pl-3 font-medium">Provenance Note</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-800/50">
                            {filteredInstructions.map((ins, i) => {
                              const isTargetAddress = selectedSymbolAddress === ins.address;
                              const matchingSymbols = report.symbols.filter(
                                (s) => s.address === ins.address
                              );
                              return (
                                <tr
                                  key={i}
                                  data-insn-address={ins.address}
                                  onClick={() => {
                                    setSelectedSymbolAddress(ins.address);
                                    setSelectedSymbolLabel(
                                      matchingSymbols[0]?.name ?? `insn @ ${ins.address}`
                                    );
                                  }}
                                  className={`transition-colors cursor-pointer ${
                                    isTargetAddress
                                      ? 'bg-indigo-950/60 ring-1 ring-inset ring-indigo-500/60'
                                      : 'hover:bg-slate-800/40'
                                  }`}
                                >
                                  <td className="py-2 pr-3 text-indigo-300 whitespace-nowrap">
                                    <div className="flex items-center gap-1.5">
                                      <span>{ins.address}</span>
                                      {isTargetAddress && (
                                        <span className="text-[10px] text-emerald-300 font-semibold">
                                          &larr;
                                        </span>
                                      )}
                                    </div>
                                  </td>
                                  <td className="py-2 px-3 text-slate-500 whitespace-nowrap">
                                    {ins.fileOffset}
                                  </td>
                                  <td className="py-2 px-3 text-slate-400 whitespace-nowrap">
                                    {ins.bytesHex}
                                  </td>
                                  <td
                                    className={`py-2 px-3 font-semibold whitespace-nowrap ${
                                      ins.category === 'branch' || ins.category === 'call'
                                        ? 'text-amber-300'
                                        : ins.category === 'return'
                                        ? 'text-rose-300'
                                        : ins.category === 'prologue'
                                        ? 'text-emerald-300'
                                        : 'text-slate-100'
                                    }`}
                                  >
                                    {ins.mnemonic}
                                  </td>
                                  <td className="py-2 px-3 text-slate-200 whitespace-nowrap">
                                    {ins.operands}
                                  </td>
                                  <td className="py-2 pl-3 text-slate-400 font-sans text-xs">
                                    <div className="flex flex-wrap items-center gap-1.5">
                                      {matchingSymbols.length > 0 && (
                                        <span className="font-mono text-[11px] text-indigo-300 font-medium">
                                          [{matchingSymbols.map((s) => s.name).join(', ')}]
                                        </span>
                                      )}
                                      <span>{ins.comment ?? ''}</span>
                                    </div>
                                  </td>
                                </tr>
                              );
                            })}
                          </tbody>
                        </table>
                      </div>
                    )}

                    {activeWorkbenchTab === 'decompiler' && (
                      <div className="space-y-3">
                        <div className="flex items-center justify-between text-xs text-slate-400">
                          <span>Provider: {report.providerUsed}</span>
                          <button
                            type="button"
                            onClick={() =>
                              handleCopy('decompiler-code', report.decompiledPseudocode)
                            }
                            className="text-slate-300 hover:text-white flex items-center gap-1 cursor-pointer"
                          >
                            {copiedId === 'decompiler-code' ? (
                              <Check className="w-3.5 h-3.5 text-emerald-400" />
                            ) : (
                              <Copy className="w-3.5 h-3.5" />
                            )}
                            <span>Copy Output</span>
                          </button>
                        </div>
                        <pre className="p-4 bg-[#0B0F17] border border-slate-800 rounded-lg text-xs font-mono text-slate-200 overflow-x-auto leading-relaxed">
                          {report.decompiledPseudocode}
                        </pre>
                      </div>
                    )}

                    {activeWorkbenchTab === 'sections' && (
                      <div className="space-y-6">
                        <div className="overflow-x-auto">
                          <table className="w-full text-left border-collapse text-xs font-mono tabular-nums">
                            <thead>
                              <tr className="border-b border-slate-800 text-slate-400">
                                <th className="py-2 pr-3">Name / Unit</th>
                                <th className="py-2 px-3">Address / Route</th>
                                <th className="py-2 px-3">Offset</th>
                                <th className="py-2 px-3 text-right">Size (B)</th>
                                <th className="py-2 px-3">Mode</th>
                                <th className="py-2 pl-3 font-sans">Description</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-800/50">
                              {report.sections.map((sec, i) => (
                                <tr key={i} className="hover:bg-slate-800/40">
                                  <td className="py-2.5 pr-3 text-indigo-300 font-semibold">
                                    {sec.name}
                                  </td>
                                  <td className="py-2.5 px-3 text-slate-300">
                                    {sec.virtualAddress}
                                  </td>
                                  <td className="py-2.5 px-3 text-slate-400">
                                    {sec.fileOffset}
                                  </td>
                                  <td className="py-2.5 px-3 text-right text-slate-200">
                                    {sec.sizeBytes}
                                  </td>
                                  <td className="py-2.5 px-3 text-emerald-300">
                                    {sec.permissions}
                                  </td>
                                  <td className="py-2.5 pl-3 text-slate-400 font-sans">
                                    {sec.kind}
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>

                        {report.jsAnalysis && (
                          <div className="space-y-3 border-t border-slate-800 pt-4">
                            <h3 className="text-xs font-semibold text-white">
                              Recovered Electron Preload &amp; IPC Channel Boundaries
                            </h3>
                            <div className="space-y-2">
                              {report.jsAnalysis.modules.map((mod) => (
                                <div
                                  key={mod.id}
                                  className="p-3 bg-[#0B0F17] border border-slate-800 rounded-lg space-y-2 text-xs"
                                >
                                  <div className="flex items-center justify-between text-slate-300 font-mono">
                                    <span className="text-indigo-300 font-semibold">
                                      {mod.name}
                                    </span>
                                    <span>
                                      Role: {mod.role} · {mod.sizeBytes} B
                                    </span>
                                  </div>
                                  {mod.ipcChannels.length > 0 && (
                                    <div className="space-y-1 font-mono text-xs text-slate-400">
                                      {mod.ipcChannels.map((ch, idx) => (
                                        <div key={idx} className="flex items-center gap-2">
                                          <span className="text-emerald-300">
                                            [{ch.direction}]
                                          </span>
                                          <span className="text-white">{ch.channel}</span>
                                          <span>· line {ch.line}</span>
                                        </div>
                                      ))}
                                    </div>
                                  )}
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    )}

                    {activeWorkbenchTab === 'hexdump' && (
                      <div className="space-y-1 font-mono text-xs tabular-nums overflow-x-auto">
                        {report.hexDumpLines.map((row, idx) => (
                          <div
                            key={idx}
                            className="flex items-center gap-4 py-0.5 hover:bg-slate-800/40 px-2 rounded"
                          >
                            <span className="text-indigo-400 shrink-0">{row.offset}</span>
                            <span className="text-slate-300 tracking-wider shrink-0">
                              {row.hexBytes.slice(0, 8).join(' ')}
                              {'  '}
                              {row.hexBytes.slice(8, 16).join(' ')}
                            </span>
                            <span className="text-emerald-300/90 border-l border-slate-800 pl-3 whitespace-pre">
                              {row.ascii}
                            </span>
                          </div>
                        ))}
                      </div>
                    )}

                    {activeWorkbenchTab === 'strings' && (
                      <div className="overflow-x-auto">
                        <table className="w-full text-left border-collapse text-xs font-mono tabular-nums">
                          <thead>
                            <tr className="border-b border-slate-800 text-slate-400">
                              <th className="py-2 pr-3">File Offset</th>
                              <th className="py-2 px-3 text-right">Length</th>
                              <th className="py-2 px-3">Section</th>
                              <th className="py-2 pl-3">Extracted Literal</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-800/50">
                            {report.strings.map((s, idx) => (
                              <tr key={idx} className="hover:bg-slate-800/40">
                                <td className="py-2 pr-3 text-indigo-300">{s.offset}</td>
                                <td className="py-2 px-3 text-right text-slate-400">
                                  {s.length}
                                </td>
                                <td className="py-2 px-3 text-slate-500">{s.sectionHint}</td>
                                <td className="py-2 pl-3 text-slate-200 break-all">
                                  {s.value}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>
                </div>

                {/* Right 4 Columns: AI Intent Interrogation & Clean Reconstructed Code */}
                <div className="lg:col-span-4 space-y-5">
                  {/* AI Interrogation Card */}
                  <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 space-y-4">
                    <div className="space-y-0.5">
                      <div className="text-xs text-indigo-400 font-mono">
                        Evidence-Backed Investigation
                      </div>
                      <h2 className="text-base font-semibold text-white font-display">
                        Interrogate Target Intent
                      </h2>
                    </div>

                    <div className="space-y-3">
                      <textarea
                        rows={3}
                        value={analystQuestion}
                        onChange={(e) => setAnalystQuestion(e.target.value)}
                        placeholder="Ask how a feature works, trace an IPC channel, or reconstruct source code..."
                        className="w-full p-3 text-xs bg-[#0B0F17] border border-slate-800 rounded-lg text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-indigo-500 leading-relaxed"
                      />

                      <div className="flex items-center justify-between gap-3">
                        <span className="text-xs text-slate-400">
                          Appends findings to Evidence Ledger
                        </span>
                        <button
                          type="button"
                          onClick={handleRunInvestigation}
                          disabled={isInterrogating}
                          className="px-4 py-2 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 rounded-lg transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer"
                        >
                          {isInterrogating ? (
                            <>
                              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                              <span>Interrogating...</span>
                            </>
                          ) : (
                            <>
                              <Sparkles className="w-3.5 h-3.5" />
                              <span>Run Investigation</span>
                            </>
                          )}
                        </button>
                      </div>
                    </div>

                    {aiError && (
                      <div className="p-3 bg-rose-950/40 border border-rose-800/70 rounded-lg text-xs text-rose-200">
                        {aiError}
                      </div>
                    )}

                    {aiSummary && (
                      <div className="p-3.5 bg-[#0B0F17] border border-slate-800 rounded-lg space-y-1.5">
                        <div className="text-xs font-semibold text-indigo-300">
                          Investigation Findings
                        </div>
                        <p className="text-xs text-slate-300 leading-relaxed">{aiSummary}</p>
                      </div>
                    )}
                  </div>

                  {/* Clean Reconstructed Feature Code */}
                  <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 space-y-3">
                    <div className="flex items-center justify-between gap-2">
                      <div>
                        <div className="text-xs text-emerald-400 font-mono">
                          {report.reconstructedSource.language}
                        </div>
                        <h3 className="text-sm font-semibold text-white font-display">
                          {report.reconstructedSource.title}
                        </h3>
                      </div>
                      <button
                        type="button"
                        onClick={() =>
                          handleCopy('reconstructed-src', report.reconstructedSource.code)
                        }
                        className="px-2.5 py-1 text-xs text-slate-300 hover:text-white bg-slate-800 rounded-md flex items-center gap-1 shrink-0 cursor-pointer"
                      >
                        {copiedId === 'reconstructed-src' ? (
                          <Check className="w-3.5 h-3.5 text-emerald-400" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                        <span>Copy</span>
                      </button>
                    </div>

                    <pre className="p-3.5 bg-[#0B0F17] border border-slate-800 rounded-lg text-xs font-mono text-slate-200 overflow-x-auto leading-relaxed max-h-[280px]">
                      {report.reconstructedSource.code}
                    </pre>

                    <div className="text-xs text-slate-400">
                      {report.reconstructedSource.verificationNote}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </section>

        {/* Section 02: Visual Binary, Decompiler & Control-Flow Diffing Studio */}
        <section
          id="visual-diff-studio"
          className="space-y-5 scroll-mt-16 border-t border-slate-800/80 pt-10"
        >
          <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-4">
            <div className="space-y-0.5">
              <div className="text-xs text-slate-400">
                02. Opcode, Decompiler Pseudocode &amp; Control-Flow Delta Engine
              </div>
              <h2 className="text-2xl font-bold text-white font-display">
                Visual Binary &amp; Decompiler Diffing Studio
              </h2>
            </div>

            {/* Comparison Target Selection & Upload Controls */}
            <div className="flex flex-wrap items-center gap-2.5">
              <label className="flex items-center gap-2 text-xs text-slate-400">
                <span>Compare Against (Version B):</span>
                <select
                  value={comparisonSource}
                  onChange={(e) => handleComparisonSourceChange(e.target.value)}
                  className="px-3 py-1.5 bg-[#111827] border border-slate-800 rounded-lg text-slate-200 font-mono text-xs focus:outline-none focus:border-indigo-500"
                >
                  <option value="paired-patch">
                    Paired Revision: {activePresetMeta.patchedFileName}
                  </option>
                  {SAMPLE_ARTIFACT_PRESETS.map((p) => (
                    <option key={p.id} value={p.id}>
                      Preset: {p.fileName}
                    </option>
                  ))}
                  {comparisonSource === 'custom-upload' && comparisonReport && (
                    <option value="custom-upload">
                      Uploaded: {comparisonReport.targetName}
                    </option>
                  )}
                </select>
              </label>

              <button
                type="button"
                onClick={() => comparisonFileInputRef.current?.click()}
                className="px-3 py-1.5 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer"
              >
                <Upload className="w-3.5 h-3.5" />
                <span>Upload Comparison File (v2)</span>
              </button>

              <button
                type="button"
                onClick={handleRecordDiffInLedger}
                disabled={!diffReport}
                className="px-3.5 py-1.5 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 rounded-lg transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer"
              >
                <PlusCircle className="w-3.5 h-3.5" />
                <span>Record Diff in Evidence Ledger</span>
              </button>
            </div>
          </div>

          {diffRecordedBanner && (
            <div className="p-3 bg-emerald-950/40 border border-emerald-800/70 rounded-lg text-xs text-emerald-200 flex items-center justify-between">
              <span>
                Recorded binary and control-flow diff provenance into the{' '}
                <strong>Epistemic Evidence Ledger</strong>.
              </span>
              <Check className="w-4 h-4 text-emerald-400 shrink-0" />
            </div>
          )}

          {diffReport && report && comparisonReport && (
            <div className="bg-[#111827] border border-slate-800 rounded-xl overflow-hidden">
              {/* Diff Summary & Controls Header Bar */}
              <div className="p-4 border-b border-slate-800 space-y-3 bg-[#0E1420]">
                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                  <div className="space-y-1">
                    <div className="flex flex-wrap items-center gap-2 text-xs font-mono tabular-nums">
                      <span className="text-slate-300 font-semibold">
                        Baseline (A): {report.targetName}
                      </span>
                      <span className="text-slate-600">·</span>
                      <span className="text-indigo-300 font-semibold">
                        Comparison (B): {comparisonReport.targetName}
                      </span>
                      <span className="text-slate-600">·</span>
                      <span className="text-slate-400">
                        Similarity: {diffReport.metrics.similarityPercent}%
                      </span>
                      <span className="text-slate-600">·</span>
                      <span className="text-amber-300">
                        ~{diffReport.metrics.modifiedInsns} Modified
                      </span>
                      <span className="text-slate-600">·</span>
                      <span className="text-emerald-300">
                        +{diffReport.metrics.addedInsns} Added
                      </span>
                      <span className="text-slate-600">·</span>
                      <span className="text-rose-300">
                        -{diffReport.metrics.removedInsns} Removed
                      </span>
                      <span className="text-slate-600">·</span>
                      <span className="text-indigo-300">
                        {diffReport.metrics.branchMutations} CFG Block Deltas
                      </span>
                    </div>

                    {comparisonSource === 'paired-patch' && (
                      <p className="text-xs text-slate-400">
                        {activePresetMeta.patchDescription}
                      </p>
                    )}
                  </div>

                  {/* Sub-View + Layout Mode Segmented Controls */}
                  <div className="flex flex-wrap items-center gap-2 shrink-0">
                    <div className="flex items-center gap-1 p-1 bg-[#0B0F17] border border-slate-800 rounded-lg">
                      {(
                        [
                          { id: 'instructions', label: 'Instruction Diff' },
                          { id: 'pseudocode', label: 'Pseudocode Diff' },
                          {
                            id: 'control-flow',
                            label: `CFG Deltas (${diffReport.controlFlowDeltas.length})`,
                          },
                        ] as { id: DiffSubView; label: string }[]
                      ).map((tab) => (
                        <button
                          key={tab.id}
                          type="button"
                          onClick={() => setDiffSubView(tab.id)}
                          className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                            diffSubView === tab.id
                              ? 'bg-indigo-600 text-white'
                              : 'text-slate-400 hover:text-slate-200'
                          }`}
                        >
                          {tab.label}
                        </button>
                      ))}
                    </div>

                    {diffSubView !== 'control-flow' && (
                      <div className="flex items-center gap-1 p-1 bg-[#0B0F17] border border-slate-800 rounded-lg">
                        <button
                          type="button"
                          onClick={() => setDiffLayoutMode('split')}
                          className={`px-2.5 py-1.5 text-xs font-medium rounded-md transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer ${
                            diffLayoutMode === 'split'
                              ? 'bg-slate-800 text-white'
                              : 'text-slate-400 hover:text-slate-200'
                          }`}
                        >
                          <Columns2 className="w-3.5 h-3.5" />
                          <span>Side-by-Side</span>
                        </button>
                        <button
                          type="button"
                          onClick={() => setDiffLayoutMode('unified')}
                          className={`px-2.5 py-1.5 text-xs font-medium rounded-md transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer ${
                            diffLayoutMode === 'unified'
                              ? 'bg-slate-800 text-white'
                              : 'text-slate-400 hover:text-slate-200'
                          }`}
                        >
                          <AlignJustify className="w-3.5 h-3.5" />
                          <span>Inline</span>
                        </button>
                      </div>
                    )}

                    <button
                      type="button"
                      onClick={() => setShowChangesOnly((prev) => !prev)}
                      className={`px-3 py-1.5 text-xs font-medium rounded-lg border transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                        showChangesOnly
                          ? 'bg-amber-950/50 border-amber-700 text-amber-200'
                          : 'bg-[#0B0F17] border-slate-800 text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      {showChangesOnly ? 'Changes Only' : 'Show All'}
                    </button>

                    {diffLayoutMode === 'split' && diffSubView !== 'control-flow' && (
                      <button
                        type="button"
                        onClick={() => setSyncScrollEnabled((prev) => !prev)}
                        className={`px-3 py-1.5 text-xs font-medium rounded-lg border transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                          syncScrollEnabled
                            ? 'bg-indigo-950/50 border-indigo-700 text-indigo-200'
                            : 'bg-[#0B0F17] border-slate-800 text-slate-400 hover:text-slate-200'
                        }`}
                      >
                        Sync Scroll: {syncScrollEnabled ? 'On' : 'Off'}
                      </button>
                    )}
                  </div>
                </div>
              </div>

              {/* SUB-VIEW 1: INSTRUCTION-LEVEL OPCODE & OPERAND DIFFING */}
              {diffSubView === 'instructions' && (
                <div>
                  {diffLayoutMode === 'split' ? (
                    <div className="grid grid-cols-1 lg:grid-cols-2 divide-y lg:divide-y-0 lg:divide-x divide-slate-800">
                      {/* Left Pane: Baseline Version A */}
                      <div className="flex flex-col">
                        <div className="px-4 py-2 bg-[#0B0F17] border-b border-slate-800 flex items-center justify-between text-xs font-mono text-slate-400 tabular-nums">
                          <span>
                            Baseline (A):{' '}
                            <strong className="text-slate-200">{report.targetName}</strong>
                          </span>
                          <span>SHA-256: {report.sha256.slice(0, 12)}...</span>
                        </div>
                        <div
                          ref={leftSplitRef}
                          onScroll={() => handleSplitScroll('left')}
                          className="p-4 max-h-[440px] overflow-y-auto space-y-1 font-mono text-xs tabular-nums"
                        >
                          {filteredDiffInstructions.map((row) => {
                            const ins = row.baseInsn;
                            if (!ins) {
                              return (
                                <div
                                  key={`left-${row.id}`}
                                  className="px-3 py-1.5 rounded bg-slate-900/40 text-slate-600 select-none"
                                >
                                  · · · (Inserted in Comparison B)
                                </div>
                              );
                            }
                            const isMod = row.kind === 'modified';
                            const isRem = row.kind === 'removed';
                            return (
                              <div
                                key={`left-${row.id}`}
                                className={`px-3 py-1.5 rounded flex items-center justify-between gap-3 ${
                                  isRem
                                    ? 'bg-rose-950/35 border border-rose-800/50 text-rose-200'
                                    : isMod
                                    ? 'bg-amber-950/30 border border-amber-800/50 text-amber-200'
                                    : 'text-slate-300 hover:bg-slate-800/40'
                                }`}
                              >
                                <div className="flex items-center gap-3 min-w-0">
                                  <span
                                    className={`w-5 font-bold shrink-0 ${
                                      isRem
                                        ? 'text-rose-400'
                                        : isMod
                                        ? 'text-amber-400'
                                        : 'text-slate-600'
                                    }`}
                                  >
                                    {isRem ? '-' : isMod ? '~' : '='}
                                  </span>
                                  <span className="text-indigo-300 shrink-0">{ins.address}</span>
                                  <span className="font-semibold shrink-0">{ins.mnemonic}</span>
                                  <span className="truncate">{ins.operands}</span>
                                </div>
                                <span className="text-slate-500 shrink-0">{ins.bytesHex}</span>
                              </div>
                            );
                          })}
                        </div>
                      </div>

                      {/* Right Pane: Comparison Version B */}
                      <div className="flex flex-col">
                        <div className="px-4 py-2 bg-[#0B0F17] border-b border-slate-800 flex items-center justify-between text-xs font-mono text-slate-400 tabular-nums">
                          <span>
                            Comparison (B):{' '}
                            <strong className="text-indigo-300">
                              {comparisonReport.targetName}
                            </strong>
                          </span>
                          <span>SHA-256: {comparisonReport.sha256.slice(0, 12)}...</span>
                        </div>
                        <div
                          ref={rightSplitRef}
                          onScroll={() => handleSplitScroll('right')}
                          className="p-4 max-h-[440px] overflow-y-auto space-y-1 font-mono text-xs tabular-nums"
                        >
                          {filteredDiffInstructions.map((row) => {
                            const ins = row.targetInsn;
                            if (!ins) {
                              return (
                                <div
                                  key={`right-${row.id}`}
                                  className="px-3 py-1.5 rounded bg-slate-900/40 text-slate-600 select-none"
                                >
                                  · · · (Removed from Baseline A)
                                </div>
                              );
                            }
                            const isMod = row.kind === 'modified';
                            const isAdd = row.kind === 'added';
                            return (
                              <div
                                key={`right-${row.id}`}
                                className={`px-3 py-1.5 rounded flex items-center justify-between gap-3 ${
                                  isAdd
                                    ? 'bg-emerald-950/35 border border-emerald-800/50 text-emerald-200'
                                    : isMod
                                    ? 'bg-amber-950/30 border border-amber-800/50 text-amber-200'
                                    : 'text-slate-300 hover:bg-slate-800/40'
                                }`}
                              >
                                <div className="flex items-center gap-3 min-w-0">
                                  <span
                                    className={`w-5 font-bold shrink-0 ${
                                      isAdd
                                        ? 'text-emerald-400'
                                        : isMod
                                        ? 'text-amber-400'
                                        : 'text-slate-600'
                                    }`}
                                  >
                                    {isAdd ? '+' : isMod ? '~' : '='}
                                  </span>
                                  <span className="text-indigo-300 shrink-0">{ins.address}</span>
                                  <span className="font-semibold shrink-0">{ins.mnemonic}</span>
                                  <span className="truncate">{ins.operands}</span>
                                </div>
                                <div className="flex items-center gap-3 shrink-0">
                                  {row.deltaSummary && (
                                    <span className="text-[11px] font-sans text-amber-300/90 hidden sm:inline">
                                      {row.deltaSummary}
                                    </span>
                                  )}
                                  <span className="text-slate-500">{ins.bytesHex}</span>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    </div>
                  ) : (
                    /* Unified Inline Instruction Diff View */
                    <div className="p-4 max-h-[440px] overflow-y-auto space-y-1 font-mono text-xs tabular-nums">
                      {filteredDiffInstructions.map((row) => {
                        if (row.kind === 'unchanged') {
                          const ins = row.baseInsn!;
                          return (
                            <div
                              key={row.id}
                              className="px-3 py-1.5 rounded flex items-center justify-between text-slate-400 hover:bg-slate-800/40"
                            >
                              <div className="flex items-center gap-3">
                                <span className="w-10 text-slate-600">=</span>
                                <span className="w-24 text-indigo-300/80">{ins.address}</span>
                                <span className="w-16 font-semibold text-slate-200">
                                  {ins.mnemonic}
                                </span>
                                <span>{ins.operands}</span>
                              </div>
                              <span className="text-slate-600">{ins.bytesHex}</span>
                            </div>
                          );
                        }
                        if (row.kind === 'modified') {
                          return (
                            <div
                              key={row.id}
                              className="px-3 py-2 rounded bg-amber-950/35 border border-amber-800/50 text-amber-200 flex flex-col sm:flex-row sm:items-center justify-between gap-2"
                            >
                              <div className="flex flex-wrap items-center gap-3">
                                <span className="w-10 font-bold text-amber-300">~ MOD</span>
                                <span className="text-slate-400">
                                  {row.baseInsn?.address} &rarr; {row.targetInsn?.address}
                                </span>
                                <span className="line-through text-rose-300/80">
                                  {row.baseInsn?.mnemonic} {row.baseInsn?.operands}
                                </span>
                                <span>&rarr;</span>
                                <span className="font-semibold text-emerald-300">
                                  {row.targetInsn?.mnemonic} {row.targetInsn?.operands}
                                </span>
                              </div>
                              <span className="text-xs font-sans text-amber-300">
                                {row.deltaSummary}
                              </span>
                            </div>
                          );
                        }
                        if (row.kind === 'added') {
                          const ins = row.targetInsn!;
                          return (
                            <div
                              key={row.id}
                              className="px-3 py-1.5 rounded bg-emerald-950/35 border border-emerald-800/50 text-emerald-200 flex items-center justify-between"
                            >
                              <div className="flex items-center gap-3">
                                <span className="w-10 font-bold text-emerald-300">+ ADD</span>
                                <span className="w-24">{ins.address}</span>
                                <span className="w-16 font-semibold">{ins.mnemonic}</span>
                                <span>{ins.operands}</span>
                              </div>
                              <span className="text-emerald-300/80">{ins.bytesHex}</span>
                            </div>
                          );
                        }
                        const ins = row.baseInsn!;
                        return (
                          <div
                            key={row.id}
                            className="px-3 py-1.5 rounded bg-rose-950/35 border border-rose-800/50 text-rose-200 flex items-center justify-between"
                          >
                            <div className="flex items-center gap-3">
                              <span className="w-10 font-bold text-rose-300">- REM</span>
                              <span className="w-24">{ins.address}</span>
                              <span className="w-16 font-semibold">{ins.mnemonic}</span>
                              <span>{ins.operands}</span>
                            </div>
                            <span className="text-rose-300/80">{ins.bytesHex}</span>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              )}

              {/* SUB-VIEW 2: DECOMPILED PSEUDOCODE LINE-BY-LINE DIFFING */}
              {diffSubView === 'pseudocode' && (
                <div>
                  {diffLayoutMode === 'split' ? (
                    <div className="grid grid-cols-1 lg:grid-cols-2 divide-y lg:divide-y-0 lg:divide-x divide-slate-800">
                      <div
                        ref={leftSplitRef}
                        onScroll={() => handleSplitScroll('left')}
                        className="p-4 max-h-[440px] overflow-y-auto space-y-0.5 font-mono text-xs tabular-nums"
                      >
                        {filteredDiffPseudocode.map((row) => (
                          <div
                            key={`p-left-${row.id}`}
                            className={`px-3 py-1 rounded flex items-start gap-3 ${
                              row.kind === 'removed'
                                ? 'bg-rose-950/35 text-rose-200'
                                : row.kind === 'modified'
                                ? 'bg-amber-950/30 text-amber-200'
                                : row.kind === 'added'
                                ? 'bg-slate-900/40 text-slate-600'
                                : 'text-slate-300'
                            }`}
                          >
                            <span className="w-7 text-right text-slate-500 shrink-0">
                              {row.baseLineNumber ?? '·'}
                            </span>
                            <span className="w-4 font-bold shrink-0">
                              {row.kind === 'removed'
                                ? '-'
                                : row.kind === 'modified'
                                ? '~'
                                : row.kind === 'added'
                                ? ' '
                                : '='}
                            </span>
                            <span className="whitespace-pre-wrap break-all">
                              {row.baseText ?? ''}
                            </span>
                          </div>
                        ))}
                      </div>

                      <div
                        ref={rightSplitRef}
                        onScroll={() => handleSplitScroll('right')}
                        className="p-4 max-h-[440px] overflow-y-auto space-y-0.5 font-mono text-xs tabular-nums"
                      >
                        {filteredDiffPseudocode.map((row) => (
                          <div
                            key={`p-right-${row.id}`}
                            className={`px-3 py-1 rounded flex items-start gap-3 ${
                              row.kind === 'added'
                                ? 'bg-emerald-950/35 text-emerald-200'
                                : row.kind === 'modified'
                                ? 'bg-amber-950/30 text-amber-200'
                                : row.kind === 'removed'
                                ? 'bg-slate-900/40 text-slate-600'
                                : 'text-slate-300'
                            }`}
                          >
                            <span className="w-7 text-right text-slate-500 shrink-0">
                              {row.targetLineNumber ?? '·'}
                            </span>
                            <span className="w-4 font-bold shrink-0">
                              {row.kind === 'added'
                                ? '+'
                                : row.kind === 'modified'
                                ? '~'
                                : row.kind === 'removed'
                                ? ' '
                                : '='}
                            </span>
                            <span className="whitespace-pre-wrap break-all">
                              {row.targetText ?? ''}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : (
                    <div className="p-4 max-h-[440px] overflow-y-auto space-y-0.5 font-mono text-xs tabular-nums">
                      {filteredDiffPseudocode.map((row) => {
                        if (row.kind === 'modified') {
                          return (
                            <React.Fragment key={row.id}>
                              <div className="px-3 py-1 rounded bg-rose-950/35 text-rose-200 flex items-start gap-3">
                                <span className="w-8 text-right text-rose-400/80 shrink-0">
                                  {row.baseLineNumber}
                                </span>
                                <span className="w-8 text-right text-slate-600 shrink-0">·</span>
                                <span className="w-4 font-bold text-rose-300 shrink-0">-</span>
                                <span className="whitespace-pre-wrap break-all">
                                  {row.baseText}
                                </span>
                              </div>
                              <div className="px-3 py-1 rounded bg-emerald-950/35 text-emerald-200 flex items-start gap-3">
                                <span className="w-8 text-right text-slate-600 shrink-0">·</span>
                                <span className="w-8 text-right text-emerald-400/80 shrink-0">
                                  {row.targetLineNumber}
                                </span>
                                <span className="w-4 font-bold text-emerald-300 shrink-0">+</span>
                                <span className="whitespace-pre-wrap break-all">
                                  {row.targetText}
                                </span>
                              </div>
                            </React.Fragment>
                          );
                        }
                        const isAdd = row.kind === 'added';
                        const isRem = row.kind === 'removed';
                        return (
                          <div
                            key={row.id}
                            className={`px-3 py-1 rounded flex items-start gap-3 ${
                              isAdd
                                ? 'bg-emerald-950/35 text-emerald-200'
                                : isRem
                                ? 'bg-rose-950/35 text-rose-200'
                                : 'text-slate-300'
                            }`}
                          >
                            <span className="w-8 text-right text-slate-500 shrink-0">
                              {row.baseLineNumber ?? '·'}
                            </span>
                            <span className="w-8 text-right text-slate-500 shrink-0">
                              {row.targetLineNumber ?? '·'}
                            </span>
                            <span className="w-4 font-bold shrink-0">
                              {isAdd ? '+' : isRem ? '-' : '='}
                            </span>
                            <span className="whitespace-pre-wrap break-all">
                              {isAdd ? row.targetText : row.baseText}
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              )}

              {/* SUB-VIEW 3: CONTROL-FLOW BLOCK & BRANCH DELTA SUMMARY */}
              {diffSubView === 'control-flow' && (
                <div className="p-5 grid grid-cols-1 md:grid-cols-2 gap-4 max-h-[460px] overflow-y-auto">
                  {filteredControlFlowDeltas.map((delta) => {
                    const isUnchanged = delta.changeType === 'unchanged';
                    const isAdded = delta.changeType === 'guard-block-added';
                    const isRemoved = delta.changeType === 'block-removed';
                    const isBranchMut = delta.changeType === 'branch-condition-mutated';

                    return (
                      <div
                        key={delta.id}
                        className={`p-4 rounded-xl border space-y-3 text-xs ${
                          isBranchMut
                            ? 'bg-amber-950/25 border-amber-800/60'
                            : isAdded
                            ? 'bg-emerald-950/25 border-emerald-800/60'
                            : isRemoved
                            ? 'bg-rose-950/25 border-rose-800/60'
                            : isUnchanged
                            ? 'bg-[#0B0F17] border-slate-800'
                            : 'bg-indigo-950/25 border-indigo-800/60'
                        }`}
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2 font-mono">
                          <span className="font-semibold text-white">{delta.blockLabel}</span>
                          <span
                            className={`font-semibold ${
                              isBranchMut
                                ? 'text-amber-300'
                                : isAdded
                                ? 'text-emerald-300'
                                : isRemoved
                                ? 'text-rose-300'
                                : isUnchanged
                                ? 'text-slate-400'
                                : 'text-indigo-300'
                            }`}
                          >
                            {delta.changeType.toUpperCase()}
                          </span>
                        </div>

                        <p className="text-slate-200 leading-relaxed">{delta.impactNote}</p>

                        <div className="grid grid-cols-1 gap-2 pt-2 border-t border-slate-800/80 font-mono text-[11px]">
                          <div className="p-2 bg-[#0B0F17] rounded border border-slate-800/80">
                            <span className="text-slate-400">Baseline (A): </span>
                            <span className="text-slate-200">{delta.baseSummary}</span>
                          </div>
                          <div className="p-2 bg-[#0B0F17] rounded border border-slate-800/80">
                            <span className="text-indigo-300">Comparison (B): </span>
                            <span className="text-slate-200">{delta.targetSummary}</span>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}
        </section>

        {/* Section 03: Epistemic Evidence Ledger */}
        <section
          id="evidence-ledger"
          className="space-y-5 scroll-mt-16 border-t border-slate-800/80 pt-10"
        >
          <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
            <div className="space-y-0.5">
              <div className="text-xs text-slate-400">
                03. Provenance-Backed Investigation Records
              </div>
              <h2 className="text-2xl font-bold text-white font-display">
                Epistemic Evidence Ledger
              </h2>
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <div className="flex flex-wrap items-center gap-1.5 p-1 bg-[#111827] border border-slate-800 rounded-lg">
                {(
                  [
                    { id: 'all', label: 'All Evidence' },
                    { id: 'observed', label: 'Observed' },
                    { id: 'derived', label: 'Derived' },
                    { id: 'inferred', label: 'Inferred' },
                    { id: 'unknown', label: 'Unknowns' },
                  ] as const
                ).map((tab) => (
                  <button
                    key={tab.id}
                    type="button"
                    onClick={() => setEvidenceFilter(tab.id)}
                    className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                      evidenceFilter === tab.id
                        ? 'bg-indigo-600 text-white'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {tab.label}
                  </button>
                ))}
              </div>

              <button
                type="button"
                onClick={handleOpenPdfModal}
                disabled={!report}
                className="px-4 py-2 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 rounded-lg transition-colors flex items-center gap-2 whitespace-nowrap shrink-0 cursor-pointer"
              >
                <FileText className="w-3.5 h-3.5" />
                <span>Export PDF Report</span>
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {filteredEvidence.map((item) => (
              <div
                key={item.id}
                className="bg-[#111827] border border-slate-800 rounded-xl p-5 flex flex-col justify-between space-y-3"
              >
                <div className="space-y-2">
                  <div className="flex flex-wrap items-center gap-2 text-xs font-mono tabular-nums">
                    <span
                      className={`font-semibold ${
                        item.category === 'observed'
                          ? 'text-indigo-300'
                          : item.category === 'derived'
                          ? 'text-emerald-300'
                          : item.category === 'inferred'
                          ? 'text-amber-300'
                          : 'text-rose-300'
                      }`}
                    >
                      {item.category.toUpperCase()}
                    </span>
                    <span aria-hidden="true" className="text-slate-600">
                      ·
                    </span>
                    <span className="text-slate-400">{item.provenance}</span>
                    <span aria-hidden="true" className="text-slate-600">
                      ·
                    </span>
                    <span className="text-slate-500">via {item.toolUsed}</span>
                  </div>

                  <h3 className="text-sm font-semibold text-white font-display">
                    {item.title}
                  </h3>
                  <p className="text-xs text-slate-300 leading-relaxed">{item.statement}</p>
                </div>

                {item.snippet && (
                  <pre className="p-2.5 bg-[#0B0F17] border border-slate-800/80 rounded-lg text-[11px] font-mono text-slate-300 overflow-x-auto">
                    {item.snippet}
                  </pre>
                )}
              </div>
            ))}
          </div>
        </section>
      </main>

      {/* PDF Export Quick Configure Modal */}
      {isPdfModalOpen && report && (
        <div
          className="fixed inset-0 z-50 bg-black/75 backdrop-blur-xs flex items-center justify-center p-4"
          role="dialog"
          aria-modal="true"
          aria-labelledby="pdf-modal-title"
        >
          <div className="bg-[#111827] border border-slate-800 rounded-xl max-w-xl w-full p-6 space-y-5 shadow-2xl">
            <div className="flex items-start justify-between gap-4 border-b border-slate-800 pb-4">
              <div className="space-y-1">
                <div className="text-xs text-indigo-400 font-mono">
                  High-Contrast Light Document · A4 Vector PDF
                </div>
                <h2
                  id="pdf-modal-title"
                  className="text-lg font-bold text-white font-display"
                >
                  Configure Structured PDF Evidence Report
                </h2>
              </div>
              <button
                type="button"
                onClick={() => setIsPdfModalOpen(false)}
                className="text-slate-400 hover:text-white p-1 rounded-lg transition-colors cursor-pointer"
                aria-label="Close modal"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <label className="block space-y-1">
                <span className="text-slate-300 font-medium">Report Title</span>
                <input
                  type="text"
                  value={pdfReportTitle}
                  onChange={(e) => setPdfReportTitle(e.target.value)}
                  className="w-full px-3 py-2 bg-[#0B0F17] border border-slate-800 rounded-lg text-slate-100 focus:outline-none focus:border-indigo-500"
                />
              </label>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <label className="block space-y-1">
                  <span className="text-slate-300 font-medium">Analyst / Author Name</span>
                  <input
                    type="text"
                    value={pdfAuthorName}
                    onChange={(e) => setPdfAuthorName(e.target.value)}
                    className="w-full px-3 py-2 bg-[#0B0F17] border border-slate-800 rounded-lg text-slate-100 focus:outline-none focus:border-indigo-500"
                  />
                </label>

                <label className="block space-y-1">
                  <span className="text-slate-300 font-medium">Case / Reference ID</span>
                  <input
                    type="text"
                    value={pdfCaseId}
                    onChange={(e) => setPdfCaseId(e.target.value)}
                    className="w-full px-3 py-2 bg-[#0B0F17] border border-slate-800 rounded-lg text-slate-100 font-mono focus:outline-none focus:border-indigo-500"
                  />
                </label>
              </div>

              <label className="block space-y-1">
                <span className="text-slate-300 font-medium">
                  Optional Analyst Scope &amp; Assessment Notes
                </span>
                <textarea
                  rows={2}
                  value={pdfAnalystNotes}
                  onChange={(e) => setPdfAnalystNotes(e.target.value)}
                  placeholder="Add formal scope notes, authorization references, or reproduction context..."
                  className="w-full p-2.5 bg-[#0B0F17] border border-slate-800 rounded-lg text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-indigo-500"
                />
              </label>
            </div>

            <div className="space-y-2.5 border-t border-slate-800 pt-4 text-xs">
              <div className="font-semibold text-slate-200">Included Report Sections</div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                <label className="flex items-center gap-2.5 p-2.5 bg-[#0B0F17] border border-slate-800 rounded-lg cursor-pointer">
                  <input
                    type="checkbox"
                    checked={pdfIncludeTargetHeader}
                    onChange={(e) => setPdfIncludeTargetHeader(e.target.checked)}
                    className="accent-indigo-600"
                  />
                  <span className="text-slate-200">Target Metadata &amp; SHA-256 Header</span>
                </label>

                <label className="flex items-center gap-2.5 p-2.5 bg-[#0B0F17] border border-slate-800 rounded-lg cursor-pointer">
                  <input
                    type="checkbox"
                    checked={pdfIncludeEvidenceLedger}
                    onChange={(e) => setPdfIncludeEvidenceLedger(e.target.checked)}
                    className="accent-indigo-600"
                  />
                  <span className="text-slate-200">Full Epistemic Evidence Ledger</span>
                </label>

                <label className="flex items-center gap-2.5 p-2.5 bg-[#0B0F17] border border-slate-800 rounded-lg cursor-pointer">
                  <input
                    type="checkbox"
                    checked={pdfIncludeReconstructedCode}
                    onChange={(e) => setPdfIncludeReconstructedCode(e.target.checked)}
                    className="accent-indigo-600"
                  />
                  <span className="text-slate-200">Reconstructed Source &amp; Notes</span>
                </label>

                {aiSummary && (
                  <label className="flex items-center gap-2.5 p-2.5 bg-[#0B0F17] border border-slate-800 rounded-lg cursor-pointer">
                    <input
                      type="checkbox"
                      checked={pdfIncludeAiSummary}
                      onChange={(e) => setPdfIncludeAiSummary(e.target.checked)}
                      className="accent-indigo-600"
                    />
                    <span className="text-slate-200">AI Interrogation Summary</span>
                  </label>
                )}
              </div>
            </div>

            {pdfIncludeEvidenceLedger && (
              <div className="space-y-2 border-t border-slate-800 pt-4 text-xs">
                <div className="font-semibold text-slate-200">
                  Epistemic Provenance Categories to Include
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                  {(
                    [
                      { key: 'observed', label: 'Observed' },
                      { key: 'derived', label: 'Derived' },
                      { key: 'inferred', label: 'Inferred' },
                      { key: 'unknown', label: 'Unknowns' },
                    ] as { key: EvidenceCategory; label: string }[]
                  ).map((cat) => (
                    <label
                      key={cat.key}
                      className="flex items-center gap-2 p-2 bg-[#0B0F17] border border-slate-800 rounded-lg cursor-pointer"
                    >
                      <input
                        type="checkbox"
                        checked={pdfCategories[cat.key]}
                        onChange={(e) =>
                          setPdfCategories((prev) => ({
                            ...prev,
                            [cat.key]: e.target.checked,
                          }))
                        }
                        className="accent-indigo-600"
                      />
                      <span className="text-slate-200">{cat.label}</span>
                    </label>
                  ))}
                </div>
              </div>
            )}

            {pdfExportDownloadedFile && (
              <div className="p-3 bg-emerald-950/40 border border-emerald-800/70 rounded-lg text-xs text-emerald-200 flex items-center justify-between">
                <span>
                  Generated and downloaded{' '}
                  <strong className="font-mono">{pdfExportDownloadedFile}</strong>
                </span>
                <Check className="w-4 h-4 text-emerald-400 shrink-0" />
              </div>
            )}

            <div className="flex flex-wrap items-center justify-between gap-4 border-t border-slate-800 pt-4">
              <div className="text-xs font-mono text-slate-400 tabular-nums">
                {pdfSelectedSectionCount} Sections · {pdfSelectedEvidenceCount} Evidence
                Records Selected
              </div>

              <div className="flex items-center gap-2.5">
                <button
                  type="button"
                  onClick={() => setIsPdfModalOpen(false)}
                  className="px-3.5 py-2 text-xs font-medium text-slate-300 hover:text-white bg-slate-800 rounded-lg transition-colors cursor-pointer"
                >
                  Close
                </button>
                <button
                  type="button"
                  onClick={handleGeneratePdf}
                  disabled={pdfSelectedSectionCount === 0}
                  className="px-4 py-2 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 rounded-lg transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Download PDF Report</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Minimal Footer */}
      <footer className="border-t border-slate-800/80 py-6 px-6 mt-12 text-xs text-slate-400">
        <div className="max-w-[1400px] mx-auto flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div>
            <strong className="text-slate-200 font-display">Reverse Psychology</strong> ·
            Evidence-backed reverse engineering workbench.
          </div>
          <div className="flex items-center gap-4 shrink-0">
            <a href="#workbench" className="hover:text-white transition-colors">
              Workbench
            </a>
            <span>·</span>
            <a href="#visual-diff-studio" className="hover:text-white transition-colors">
              Visual Diff
            </a>
            <span>·</span>
            <a href="#evidence-ledger" className="hover:text-white transition-colors">
              Evidence Ledger
            </a>
          </div>
        </div>
      </footer>
    </div>
  );
}
