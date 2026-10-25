# Reverse Psychology — Visual Binary & Decompiler Diffing Engine

Add an interactive **Visual Diffing Engine** to the **Reverse Psychology** workbench that compares two versions of a binary, bytecode module, JavaScript/Electron bundle, or HAR capture—highlighting instruction-level opcode/operand mutations, decompiled pseudocode diffs, and control-flow branch deltas.

## User Review & Critical Decisions

> [!IMPORTANT]
> The following product and design choices have been confirmed from your clarifications and will govern the implementation:

- **Confirmed Diff Layout Mode**: A **Side-by-Side Split View** with synchronized vertical scrolling as the default view, paired with a segmented toggle to switch to a **Unified Inline Diff View** (`Side-by-Side` | `Unified Inline`) and a filter to show **All Lines** or **Changes Only**.
- **Confirmed Comparison Views**:
  1. **Instruction-Level Opcode & Operand Diffing**: Aligns instructions by mnemonic/control-flow anchor, highlighting added (`+`), removed (`-`), and modified (`~`) opcodes, immediate constants, register allocations, and branch targets.
  2. **Decompiled Pseudocode Line-by-Line Diffing**: Computes an exact Longest Common Subsequence (LCS) line and token diff between the baseline and comparison decompiler outputs.
  3. **Control Flow Block & Branch Delta Summary**: Compares basic blocks, branch instructions (`jcc`, `call`, `JUMPI`, `ret`, IPC handlers), and entry-to-exit paths—flagging altered clamp bounds, added security checks, or modified branch destinations.
- **Confirmed Comparison Target Loading**: Every built-in showcase target comes with a **paired Patched / Revision v2 Binary Preset** (e.g., `dxball_sound_pan_v2_patched.elf` with widened `[-1200, 1200]` saturation bounds and `×28` scaling, `notion_clipboard_bridge_v2_hardened.js` with URL scheme allowlist validation, `defi_vault_router_v2_reentrancy.evm` with added `_reentrancyLock` `SLOAD`/`SSTORE` guard) so users can inspect realistic binary diffs in one click, alongside a **Compare Custom File** upload button to diff any local file against the active target.

---

## 1. Overview & Core Concept

- **What It Does**: Enables analysts to load a Baseline (`Version A`) and Comparison (`Version B`) artifact side-by-side inside the workbench, automatically computing structural deltas across disassembled instructions, control-flow branches, and decompiled pseudocode, and optionally recording the discovered delta directly into the **Epistemic Evidence Ledger**.
- **Target Audience / Persona**: Patch diffing researchers, firmware/game preservationists comparing compiler outputs against original binaries, and security engineers verifying that a hotfix or Electron IPC patch actually closes a vulnerability.
- **Key Value**: Eliminates manual eye-balling of hex dumps and assembly listings by surfacing semantic opcode changes (e.g., immediate constant shifts, inverted branch conditions, or added guard blocks) with exact address and byte-offset provenance.

---

## 2. User Experience & Visual Design

- **Key User Flows**:
  1. **Open Visual Diff Tab**: In the main **Reverse Psychology Analysis Workbench**, a new primary tab **Visual Diff (`v1 vs v2`)** is added alongside `Disassembly & Trace`, `Static Decompiler`, `Sections & IPC`, `Hex Dump`, and `Strings` (plus a dedicated full-width **Visual Binary & Control-Flow Diff Studio** panel for spacious side-by-side inspection).
  2. **Select Comparison Target (`Version B`)**:
     - By default, selecting any showcase artifact automatically pairs its built-in **Patched / Revision v2** counterpart so a rich, realistic binary diff is immediately visible with zero setup.
     - Users can also switch the comparison target to any other preset or click **Upload Comparison Artifact (`v2`)** to diff a custom binary/bundle from disk.
  3. **Switch Sub-Views & Layout Modes**:
     - Switch between **Instruction & Opcode Diff**, **Decompiled Pseudocode Diff**, and **Control-Flow & Branch Deltas**.
     - Toggle between **Side-by-Side Split** (with synchronized scroll lock) and **Unified Inline Diff**, or filter to **Changes Only** (`Added / Removed / Modified`).
  4. **Commit Diff to Evidence Ledger**: Clicking **Record Diff in Evidence Ledger** appends a `DERIVED` provenance record summarizing the exact instruction/branch delta and SHA-256 pair (`sha256_A -> sha256_B`) so it is automatically included in JSON snapshots and exported PDF reports.

- **Visual Identity & Theme**:
  - *Aesthetic Direction*: High-density reverse-engineering studio aesthetic (`#0B0F17` canvas, `#111827` single-elevation containers, `1px solid` hairline borders).
  - *Semantic Diff Palette (WCAG AA High Contrast + Explicit Symbols)*:
    - **Added (`+`)**: Emerald surface tint (`bg-emerald-950/35`), `#6EE7B7` text, paired with explicit `+` prefix and `ADDED` status label (never signaling state by color alone).
    - **Removed (`-`)**: Crimson surface tint (`bg-rose-950/35`), `#FDA4AF` text, paired with explicit `-` prefix and `REMOVED` status label.
    - **Modified Opcode / Operand (`~`)**: Amber surface tint (`bg-amber-950/35`), `#FCD34D` text highlighting the exact mutated operand or immediate byte sequence (e.g., `cmp eax, -1000` $\rightarrow$ `cmp eax, -1200`), paired with explicit `~` marker.
    - **Unchanged (`=`)**: Subdued `#94A3B8` monospace rows for structural context.
  - *Typography & Tabular Discipline*: All addresses, byte offsets, opcodes, and delta metrics use `JetBrains Mono` with `font-variant-numeric: tabular-nums`. Metadata summaries use unboxed inline text with `·` separators.

---

## 3. Key Product Decisions & Trade-Offs

- **Decision 1: Deterministic LCS + Opcode-Aware Instruction Alignment**
  - *Chosen Approach*: Implement an in-process LCS (Longest Common Subsequence) diff engine in TypeScript that aligns instructions by normalized mnemonic + structural role first, then classifies pairs with identical mnemonics but different operands/bytes as **Modified (`~`)** rather than disconnected delete+insert pairs.
  - *Why*: In binary patch diffing, a single changed immediate constant or relocated jump offset shifts subsequent addresses; normalizing mnemonics and detecting operand mutations (`~`) highlights the exact instruction change cleanly without false-positive full-file mismatches.
- **Decision 2: Built-In Patched Revision Counterparts (`v2`) for All Showcases**
  - *Chosen Approach*: Synthesize real byte-level patched revisions for every built-in showcase binary/bundle alongside custom file upload.
  - *Why*: Lets users immediately experience instruction diffing, branch delta analysis, and pseudocode comparison on realistic security patches and compiler revisions without needing two external binaries on hand.

---

## 4. Technical Architecture & Data Strategy *(Technical Reference)*

### Architecture & Component Diagram

```text
┌────────────────────────────────────────────────────────────────────────────┐
│                     Reverse Psychology Workbench UI                        │
│                                                                            │
│  ┌────────────────────────────────┐    ┌────────────────────────────────┐  │
│  │  Baseline Artifact (Version A) │    │ Comparison Artifact (Version B)│  │
│  │  • Active Workbench Target     │    │ • Paired Patched v2 Preset OR  │  │
│  │  • AnalysisReport A            │    │ • Custom Uploaded File (v2)    │  │
│  └───────────────┬────────────────┘    └───────────────┬────────────────┘  │
│                  └──────────────────┬──────────────────┘                   │
│                                     ▼                                      │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │               Deterministic Binary & AST Diff Engine                 │  │
│  │  1. Instruction Aligner: LCS on normalized mnemonics + operand diff  │  │
│  │  2. Pseudocode Differ: Line-by-line LCS diff with change hunks       │  │
│  │  3. Control-Flow Analyzer: Basic block & branch target delta matrix  │  │
│  └───────────────┬──────────────────┬──────────────────┬────────────────┘  │
│                  ▼                  ▼                  ▼                   │
│  ┌──────────────────────┐ ┌──────────────────┐ ┌────────────────────────┐  │
│  │ Instruction & Opcode │ │ Decompiled Code  │ │ Control-Flow & Branch  │  │
│  │ Diff View            │ │ Diff View        │ │ Delta Summary          │  │
│  │ (Split Sync / Inline)│ │ (Split / Inline) │ │ (Block Graph + Table)  │  │
│  └───────────────┬──────┘ └─────────┬────────┘ └───────────┬────────────┘  │
│                  └──────────────────┼──────────────────────┘               │
│                                     ▼                                      │
│           [Record Diff in Epistemic Evidence Ledger (DERIVED)]             │
└────────────────────────────────────────────────────────────────────────────┘
```

### Data Model & State

- **`InstructionDiffRow`**:
  - `kind`: `'unchanged' | 'added' | 'removed' | 'modified'`
  - `baseInsn?`: `DisassembledInstruction` (address, bytesHex, mnemonic, operands, category)
  - `targetInsn?`: `DisassembledInstruction`
  - `deltaNote?`: `string` (e.g., `"Operand mutated: -1000 -> -1200"` or `"Added CALLVALUE guard"`)
- **`CodeLineDiffRow`**:
  - `kind`: `'unchanged' | 'added' | 'removed' | 'modified'`
  - `baseLineNumber?`: `number`
  - `targetLineNumber?`: `number`
  - `baseText?`: `string`
  - `targetText?`: `string`
- **`ControlFlowDelta`**:
  - `id`: `string`
  - `blockLabel`: `string`
  - `changeType`: `'branch-condition-mutated' | 'block-added' | 'block-removed' | 'call-target-changed' | 'unchanged'`
  - `baseSummary`: `string`
  - `targetSummary`: `string`
  - `securityOrBehavioralImpact`: `string`

### Interactive Component & State Mapping

- **Comparison Target Selector (`comparisonSource`)**: Defaults to `'paired-patch'` (automatically generating the patched v2 `AnalysisReport` whenever `selectedPresetId` changes), or switches to any preset ID or `'custom-upload'` when the user uploads a comparison file via `comparisonFileInputRef`.
- **Synchronized Split Scroll (`leftDiffPaneRef`, `rightDiffPaneRef`)**: When `diffLayoutMode === 'split'` and `syncScroll === true`, scrolling either the Baseline (`Version A`) or Comparison (`Version B`) pane programmatically syncs the scroll offset of its counterpart.
- **Filter & Mode Controls**:
  - `diffSubView`: `'instructions' | 'pseudocode' | 'control-flow'`
  - `diffLayoutMode`: `'split' | 'unified'`
  - `showChangesOnly`: `boolean` (filters out `'unchanged'` rows to focus strictly on `+`, `-`, and `~` mutations)
- **Ledger Integration (`handleRecordDiffEvidence`)**: Appends a structured `DERIVED` `EvidenceRecord` with exact SHA-256 digests and instruction mutation counts into `report.evidenceLedger`, enabling immediate export in the PDF Evidence Report.
