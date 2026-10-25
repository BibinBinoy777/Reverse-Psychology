import { AnalysisReport, DisassembledInstruction } from './analyzers';

export type DiffRowKind = 'unchanged' | 'added' | 'removed' | 'modified';

export interface InstructionDiffRow {
  id: string;
  kind: DiffRowKind;
  baseInsn?: DisassembledInstruction;
  targetInsn?: DisassembledInstruction;
  deltaSummary?: string;
}

export interface PseudocodeDiffRow {
  id: string;
  kind: DiffRowKind;
  baseLineNumber?: number;
  targetLineNumber?: number;
  baseText?: string;
  targetText?: string;
}

export interface ControlFlowBlock {
  blockId: string;
  startAddress: string;
  endAddress: string;
  instructions: DisassembledInstruction[];
  terminatorMnemonic: string;
  terminatorOperands: string;
  branchCategory: DisassembledInstruction['category'];
}

export interface ControlFlowDelta {
  id: string;
  blockLabel: string;
  changeType:
    | 'unchanged'
    | 'branch-condition-mutated'
    | 'guard-block-added'
    | 'block-removed'
    | 'instructions-mutated';
  baseBlock?: ControlFlowBlock;
  targetBlock?: ControlFlowBlock;
  baseSummary: string;
  targetSummary: string;
  impactNote: string;
}

export interface BinaryDiffReport {
  baseTargetName: string;
  targetTargetName: string;
  baseSha256: string;
  targetSha256: string;
  instructionRows: InstructionDiffRow[];
  pseudocodeRows: PseudocodeDiffRow[];
  controlFlowDeltas: ControlFlowDelta[];
  metrics: {
    unchangedInsns: number;
    modifiedInsns: number;
    addedInsns: number;
    removedInsns: number;
    branchMutations: number;
    similarityPercent: number;
  };
}

/**
 * Aligns two instruction streams using LCS on mnemonic identity, then coalesces
 * in-place operand/opcode replacements into 'modified' rows.
 */
export function computeInstructionDiff(
  baseInsns: DisassembledInstruction[],
  targetInsns: DisassembledInstruction[]
): InstructionDiffRow[] {
  const m = baseInsns.length;
  const n = targetInsns.length;

  // DP table for LCS over mnemonic + category similarity
  const dp: number[][] = Array.from({ length: m + 1 }, () =>
    new Array<number>(n + 1).fill(0)
  );

  const canMatch = (a: DisassembledInstruction, b: DisassembledInstruction): boolean => {
    if (a.mnemonic === b.mnemonic) return true;
    // Also allow epilogue/frame replacements like pop rbp <-> leave to align when categories match
    if (
      a.category === 'return' &&
      b.category === 'return' &&
      ((a.mnemonic === 'pop' && b.mnemonic === 'leave') ||
        (a.mnemonic === 'leave' && b.mnemonic === 'pop'))
    ) {
      return true;
    }
    if (a.category === 'branch' && b.category === 'branch') {
      return true;
    }
    return false;
  };

  for (let i = m - 1; i >= 0; i--) {
    for (let j = n - 1; j >= 0; j--) {
      if (canMatch(baseInsns[i]!, targetInsns[j]!)) {
        const exactBonus =
          baseInsns[i]!.mnemonic === targetInsns[j]!.mnemonic &&
          baseInsns[i]!.operands === targetInsns[j]!.operands
            ? 2
            : 1;
        dp[i]![j] = exactBonus + (dp[i + 1]?.[j + 1] ?? 0);
      } else {
        dp[i]![j] = Math.max(dp[i + 1]?.[j] ?? 0, dp[i]?.[j + 1] ?? 0);
      }
    }
  }

  const rawRows: InstructionDiffRow[] = [];
  let i = 0;
  let j = 0;
  let seq = 0;

  while (i < m && j < n) {
    const a = baseInsns[i]!;
    const b = targetInsns[j]!;
    if (canMatch(a, b)) {
      const exactBonus = a.mnemonic === b.mnemonic && a.operands === b.operands ? 2 : 1;
      if ((dp[i]?.[j] ?? 0) === exactBonus + (dp[i + 1]?.[j + 1] ?? 0)) {
        const isIdentical =
          a.mnemonic === b.mnemonic &&
          a.operands === b.operands &&
          a.bytesHex === b.bytesHex;

        if (isIdentical) {
          rawRows.push({
            id: `ins-diff-${seq++}`,
            kind: 'unchanged',
            baseInsn: a,
            targetInsn: b,
          });
        } else {
          let deltaSummary = '';
          if (a.mnemonic !== b.mnemonic) {
            deltaSummary = `Opcode mutated: ${a.mnemonic} ${a.operands} -> ${b.mnemonic} ${b.operands}`;
          } else if (a.operands !== b.operands) {
            deltaSummary = `Operand mutated: ${a.operands} -> ${b.operands}`;
          } else {
            deltaSummary = `Encoding bytes changed: [${a.bytesHex}] -> [${b.bytesHex}]`;
          }
          rawRows.push({
            id: `ins-diff-${seq++}`,
            kind: 'modified',
            baseInsn: a,
            targetInsn: b,
            deltaSummary,
          });
        }
        i++;
        j++;
        continue;
      }
    }

    if ((dp[i + 1]?.[j] ?? 0) >= (dp[i]?.[j + 1] ?? 0)) {
      rawRows.push({
        id: `ins-diff-${seq++}`,
        kind: 'removed',
        baseInsn: a,
        deltaSummary: `Removed ${a.mnemonic} ${a.operands}`,
      });
      i++;
    } else {
      rawRows.push({
        id: `ins-diff-${seq++}`,
        kind: 'added',
        targetInsn: b,
        deltaSummary: `Inserted ${b.mnemonic} ${b.operands}`,
      });
      j++;
    }
  }

  while (i < m) {
    const a = baseInsns[i++]!;
    rawRows.push({
      id: `ins-diff-${seq++}`,
      kind: 'removed',
      baseInsn: a,
      deltaSummary: `Removed ${a.mnemonic} ${a.operands}`,
    });
  }
  while (j < n) {
    const b = targetInsns[j++]!;
    rawRows.push({
      id: `ins-diff-${seq++}`,
      kind: 'added',
      targetInsn: b,
      deltaSummary: `Inserted ${b.mnemonic} ${b.operands}`,
    });
  }

  // Coalesce adjacent removed + added pairs with same category into 'modified'
  const coalesced: InstructionDiffRow[] = [];
  for (let k = 0; k < rawRows.length; k++) {
    const curr = rawRows[k]!;
    const next = rawRows[k + 1];
    if (
      curr.kind === 'removed' &&
      next?.kind === 'added' &&
      curr.baseInsn &&
      next.targetInsn &&
      curr.baseInsn.category === next.targetInsn.category
    ) {
      coalesced.push({
        id: curr.id,
        kind: 'modified',
        baseInsn: curr.baseInsn,
        targetInsn: next.targetInsn,
        deltaSummary: `Replaced ${curr.baseInsn.mnemonic} ${curr.baseInsn.operands} -> ${next.targetInsn.mnemonic} ${next.targetInsn.operands}`,
      });
      k++;
    } else {
      coalesced.push(curr);
    }
  }

  return coalesced;
}

/**
 * Computes line-by-line LCS diff on decompiled pseudocode, coalescing adjacent
 * removed + added lines into 'modified' rows for side-by-side alignment.
 */
export function computePseudocodeDiff(
  baseCode: string,
  targetCode: string
): PseudocodeDiffRow[] {
  const baseLines = baseCode.split(/\r?\n/);
  const targetLines = targetCode.split(/\r?\n/);
  const m = baseLines.length;
  const n = targetLines.length;

  const dp: number[][] = Array.from({ length: m + 1 }, () =>
    new Array<number>(n + 1).fill(0)
  );

  for (let i = m - 1; i >= 0; i--) {
    for (let j = n - 1; j >= 0; j--) {
      if (baseLines[i]!.trim() === targetLines[j]!.trim()) {
        dp[i]![j] = 1 + (dp[i + 1]?.[j + 1] ?? 0);
      } else {
        dp[i]![j] = Math.max(dp[i + 1]?.[j] ?? 0, dp[i]?.[j + 1] ?? 0);
      }
    }
  }

  const raw: PseudocodeDiffRow[] = [];
  let i = 0;
  let j = 0;
  let seq = 0;

  while (i < m && j < n) {
    if (baseLines[i]!.trim() === targetLines[j]!.trim()) {
      raw.push({
        id: `code-diff-${seq++}`,
        kind: 'unchanged',
        baseLineNumber: i + 1,
        targetLineNumber: j + 1,
        baseText: baseLines[i],
        targetText: targetLines[j],
      });
      i++;
      j++;
    } else if ((dp[i + 1]?.[j] ?? 0) >= (dp[i]?.[j + 1] ?? 0)) {
      raw.push({
        id: `code-diff-${seq++}`,
        kind: 'removed',
        baseLineNumber: i + 1,
        baseText: baseLines[i],
      });
      i++;
    } else {
      raw.push({
        id: `code-diff-${seq++}`,
        kind: 'added',
        targetLineNumber: j + 1,
        targetText: targetLines[j],
      });
      j++;
    }
  }

  while (i < m) {
    raw.push({
      id: `code-diff-${seq++}`,
      kind: 'removed',
      baseLineNumber: i + 1,
      baseText: baseLines[i++],
    });
  }
  while (j < n) {
    raw.push({
      id: `code-diff-${seq++}`,
      kind: 'added',
      targetLineNumber: j + 1,
      targetText: targetLines[j++],
    });
  }

  // Coalesce contiguous removed[] followed by added[] blocks into paired 'modified' lines
  const coalesced: PseudocodeDiffRow[] = [];
  let idx = 0;
  while (idx < raw.length) {
    if (raw[idx]!.kind === 'removed') {
      const remStart = idx;
      while (idx < raw.length && raw[idx]!.kind === 'removed') idx++;
      const addStart = idx;
      while (idx < raw.length && raw[idx]!.kind === 'added') idx++;

      const remSlice = raw.slice(remStart, addStart);
      const addSlice = raw.slice(addStart, idx);
      const maxLen = Math.max(remSlice.length, addSlice.length);

      for (let k = 0; k < maxLen; k++) {
        const r = remSlice[k];
        const a = addSlice[k];
        if (r && a) {
          coalesced.push({
            id: r.id,
            kind: 'modified',
            baseLineNumber: r.baseLineNumber,
            targetLineNumber: a.targetLineNumber,
            baseText: r.baseText,
            targetText: a.targetText,
          });
        } else if (r) {
          coalesced.push(r);
        } else if (a) {
          coalesced.push(a);
        }
      }
    } else {
      coalesced.push(raw[idx]!);
      idx++;
    }
  }

  return coalesced;
}

/** Partition disassembled instruction stream into Basic Blocks (CFG nodes) */
export function partitionBasicBlocks(
  insns: DisassembledInstruction[]
): ControlFlowBlock[] {
  if (insns.length === 0) return [];
  const blocks: ControlFlowBlock[] = [];
  let current: DisassembledInstruction[] = [];

  const flushBlock = () => {
    if (current.length === 0) return;
    const first = current[0]!;
    const last = current[current.length - 1]!;
    blocks.push({
      blockId: `BB_${blocks.length.toString().padStart(2, '0')}`,
      startAddress: first.address,
      endAddress: last.address,
      instructions: [...current],
      terminatorMnemonic: last.mnemonic,
      terminatorOperands: last.operands,
      branchCategory: last.category,
    });
    current = [];
  };

  for (let i = 0; i < insns.length; i++) {
    const ins = insns[i]!;
    // Start a new block on explicit jump target landing pads
    if (ins.mnemonic === 'JUMPDEST' && current.length > 0) {
      flushBlock();
    }
    current.push(ins);
    if (
      ins.category === 'branch' ||
      ins.category === 'return' ||
      ins.category === 'call' ||
      ins.mnemonic === 'IPC_CALL'
    ) {
      flushBlock();
    }
  }
  flushBlock();
  return blocks;
}

/** Compare Basic Blocks and Branch Conditions between Baseline and Comparison reports */
export function computeControlFlowDeltas(
  baseInsns: DisassembledInstruction[],
  targetInsns: DisassembledInstruction[]
): ControlFlowDelta[] {
  const baseBlocks = partitionBasicBlocks(baseInsns);
  const targetBlocks = partitionBasicBlocks(targetInsns);
  const maxBlocks = Math.max(baseBlocks.length, targetBlocks.length);
  const deltas: ControlFlowDelta[] = [];

  for (let i = 0; i < maxBlocks; i++) {
    const bA = baseBlocks[i];
    const bB = targetBlocks[i];

    if (bA && bB) {
      const aSig = bA.instructions.map((x) => `${x.mnemonic} ${x.operands}`).join(' ; ');
      const bSig = bB.instructions.map((x) => `${x.mnemonic} ${x.operands}`).join(' ; ');

      if (aSig === bSig) {
        deltas.push({
          id: `cfg-delta-${i}`,
          blockLabel: `${bA.blockId} (${bA.startAddress})`,
          changeType: 'unchanged',
          baseBlock: bA,
          targetBlock: bB,
          baseSummary: `${bA.instructions.length} insns · ends with ${bA.terminatorMnemonic} ${bA.terminatorOperands}`,
          targetSummary: `${bB.instructions.length} insns · ends with ${bB.terminatorMnemonic} ${bB.terminatorOperands}`,
          impactNote: 'Identical control-flow edges and instruction sequence.',
        });
      } else {
        const isBranchMutated =
          bA.terminatorMnemonic !== bB.terminatorMnemonic ||
          bA.terminatorOperands !== bB.terminatorOperands ||
          bA.instructions.some((ins, idx) => {
            const peer = bB.instructions[idx];
            return (
              ins.mnemonic === 'cmp' &&
              peer?.mnemonic === 'cmp' &&
              ins.operands !== peer.operands
            );
          });

        deltas.push({
          id: `cfg-delta-${i}`,
          blockLabel: `${bA.blockId} (${bA.startAddress} -> ${bB.startAddress})`,
          changeType: isBranchMutated
            ? 'branch-condition-mutated'
            : 'instructions-mutated',
          baseBlock: bA,
          targetBlock: bB,
          baseSummary: aSig,
          targetSummary: bSig,
          impactNote: isBranchMutated
            ? `Branch / comparison predicate or jump target altered between Baseline (${bA.terminatorMnemonic} ${bA.terminatorOperands}) and Comparison (${bB.terminatorMnemonic} ${bB.terminatorOperands}).`
            : `Basic block body mutated (${bA.instructions.length} -> ${bB.instructions.length} instructions).`,
        });
      }
    } else if (!bA && bB) {
      deltas.push({
        id: `cfg-delta-${i}`,
        blockLabel: `${bB.blockId} (${bB.startAddress})`,
        changeType: 'guard-block-added',
        targetBlock: bB,
        baseSummary: '(Block absent in Baseline v1)',
        targetSummary: bB.instructions.map((x) => `${x.mnemonic} ${x.operands}`).join(' ; '),
        impactNote: `Added basic block (${bB.instructions.length} instructions) ending with ${bB.terminatorMnemonic} ${bB.terminatorOperands}.`,
      });
    } else if (bA && !bB) {
      deltas.push({
        id: `cfg-delta-${i}`,
        blockLabel: `${bA.blockId} (${bA.startAddress})`,
        changeType: 'block-removed',
        baseBlock: bA,
        baseSummary: bA.instructions.map((x) => `${x.mnemonic} ${x.operands}`).join(' ; '),
        targetSummary: '(Block removed in Comparison v2)',
        impactNote: `Removed basic block (${bA.instructions.length} instructions) that ended with ${bA.terminatorMnemonic}.`,
      });
    }
  }

  return deltas;
}

/** Build complete BinaryDiffReport between two AnalysisReports */
export function buildBinaryDiffReport(
  baseReport: AnalysisReport,
  targetReport: AnalysisReport
): BinaryDiffReport {
  const instructionRows = computeInstructionDiff(
    baseReport.instructions,
    targetReport.instructions
  );
  const pseudocodeRows = computePseudocodeDiff(
    baseReport.decompiledPseudocode,
    targetReport.decompiledPseudocode
  );
  const controlFlowDeltas = computeControlFlowDeltas(
    baseReport.instructions,
    targetReport.instructions
  );

  const unchangedInsns = instructionRows.filter((r) => r.kind === 'unchanged').length;
  const modifiedInsns = instructionRows.filter((r) => r.kind === 'modified').length;
  const addedInsns = instructionRows.filter((r) => r.kind === 'added').length;
  const removedInsns = instructionRows.filter((r) => r.kind === 'removed').length;
  const branchMutations = controlFlowDeltas.filter(
    (d) => d.changeType !== 'unchanged'
  ).length;

  const totalRows = Math.max(1, instructionRows.length);
  const similarityPercent = Math.round((unchangedInsns / totalRows) * 100);

  return {
    baseTargetName: baseReport.targetName,
    targetTargetName: targetReport.targetName,
    baseSha256: baseReport.sha256,
    targetSha256: targetReport.sha256,
    instructionRows,
    pseudocodeRows,
    controlFlowDeltas,
    metrics: {
      unchangedInsns,
      modifiedInsns,
      addedInsns,
      removedInsns,
      branchMutations,
      similarityPercent,
    },
  };
}
