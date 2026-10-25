import { NextResponse } from 'next/server';
import { GoogleGenAI, Type } from '@google/genai';

const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY,
  httpOptions: {
    headers: {
      'User-Agent': 'aistudio-build',
    },
  },
});

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const {
      question,
      targetName,
      format,
      architecture,
      entryPoint,
      sha256,
      instructions,
      decompiledPseudocode,
      strings,
      sections,
    } = body;

    if (!question || typeof question !== 'string') {
      return NextResponse.json(
        { error: 'Investigation question is required.' },
        { status: 400 }
      );
    }

    const promptContext = `You are Reverse Psychology (rp-agents), an evidence-backed reverse engineering engine.
Follow the strict Epistemic Provenance Contract:
1. Distinguish OBSERVED facts (direct bytes, offsets, instructions, AST nodes, headers), DERIVED relationships (CFG, arithmetic formulas, IPC call chains), INFERRED intent (architectural purpose, feature behavior), and UNKNOWNS (explicitly state NOT_ENOUGH_INFO for unexamined external callers or runtime state).
2. Cite exact addresses, offsets, or module line numbers from the provided artifact telemetry.
3. Produce a clean, verifiable code reconstruction that implements the discovered behavior.

TARGET ARTIFACT TELEMETRY:
- Target Name: ${targetName}
- Format: ${format}
- Architecture: ${architecture}
- Entry Point: ${entryPoint}
- SHA-256: ${sha256}
- Sections / Modules: ${JSON.stringify(sections?.slice(0, 10) ?? [])}
- Disassembled Instructions / Trace (first 30): ${JSON.stringify(instructions?.slice(0, 30) ?? [])}
- Static Decompiled / Reconstructed View:
${(decompiledPseudocode ?? '').slice(0, 4000)}
- Extracted Strings (first 25): ${JSON.stringify(strings?.slice(0, 25) ?? [])}

ANALYST QUESTION:
${question}`;

    const response = await ai.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: promptContext,
      config: {
        responseMimeType: 'application/json',
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            executiveSummary: {
              type: Type.STRING,
              description: 'Concise, evidence-backed technical answer to the analyst question.',
            },
            observedFacts: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                properties: {
                  title: { type: Type.STRING },
                  statement: { type: Type.STRING },
                  provenance: { type: Type.STRING },
                },
                required: ['title', 'statement', 'provenance'],
              },
            },
            derivedAnalysis: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                properties: {
                  title: { type: Type.STRING },
                  statement: { type: Type.STRING },
                  provenance: { type: Type.STRING },
                },
                required: ['title', 'statement', 'provenance'],
              },
            },
            inferredIntent: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                properties: {
                  title: { type: Type.STRING },
                  statement: { type: Type.STRING },
                  provenance: { type: Type.STRING },
                },
                required: ['title', 'statement', 'provenance'],
              },
            },
            unknownsAndLimits: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                properties: {
                  title: { type: Type.STRING },
                  statement: { type: Type.STRING },
                  provenance: { type: Type.STRING },
                },
                required: ['title', 'statement', 'provenance'],
              },
            },
            reconstructedCode: {
              type: Type.STRING,
              description: 'Runnable, clean code implementation reconstructing the reverse-engineered feature.',
            },
            reconstructedLanguage: {
              type: Type.STRING,
              description: 'Programming language of the reconstructed code (e.g. C, TypeScript, C++, Solidity, Python).',
            },
          },
          required: [
            'executiveSummary',
            'observedFacts',
            'derivedAnalysis',
            'inferredIntent',
            'unknownsAndLimits',
            'reconstructedCode',
            'reconstructedLanguage',
          ],
        },
      },
    });

    const text = response.text?.trim() ?? '{}';
    const parsed = JSON.parse(text);
    return NextResponse.json(parsed);
  } catch (error: unknown) {
    const message =
      error instanceof Error ? error.message : 'Investigation engine failed to complete request.';
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
