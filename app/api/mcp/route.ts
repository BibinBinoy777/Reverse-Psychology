import { NextResponse } from 'next/server';
import {
  analyzeArtifact,
  buildRlEnvironmentFromHar,
  withoutUserinfoWhatwg,
} from '@/lib/analyzers';
import { SAMPLE_ARTIFACT_PRESETS } from '@/lib/sample-targets';

const MCP_TOOLS_CATALOG = [
  {
    name: 'rp_inspect_binary',
    description:
      'Inspect a native binary (ELF64, PE32+, Mach-O, or 16-bit DOS COM), returning sections, disassembled instructions, pseudocode, strings, and Evidence Ledger provenance.',
    inputSchema: {
      type: 'object',
      properties: {
        presetId: {
          type: 'string',
          description: 'Preset ID (e.g., dx-ball-elf, th04-dos-com, evm-vault-router)',
        },
        hexBytes: {
          type: 'string',
          description: 'Optional hex-encoded binary bytes to inspect directly',
        },
      },
    },
  },
  {
    name: 'rp_analyze_javascript_application',
    description:
      'Static AST & Electron boundary reconstruction. Recovers bundled modules, imports, exports, contextBridge exposures, and ipcRenderer/ipcMain channels without executing target code.',
    inputSchema: {
      type: 'object',
      properties: {
        presetId: {
          type: 'string',
          description: 'Preset ID (default: notion-electron-ipc)',
        },
        sourceCode: {
          type: 'string',
          description: 'Optional JavaScript/Electron bundle source text',
        },
      },
    },
  },
  {
    name: 'rp_environment_build',
    description:
      'Convert a recorded browser HAR session into a deterministic RL AgentEnv tool suite while redacting WHATWG URL userinfo and transport credentials.',
    inputSchema: {
      type: 'object',
      properties: {
        envName: {
          type: 'string',
          description: 'Target RL environment name (e.g., my-env)',
        },
        harJson: {
          type: 'string',
          description: 'Optional raw HAR JSON string (uses workspace_folders_session.har if omitted)',
        },
      },
    },
  },
  {
    name: 'rp_redact_whatwg_url',
    description:
      'Apply Reverse Psychology WHATWG URL authority userinfo parser and credential redactor (matching bridge/mitmproxy/capture.py).',
    inputSchema: {
      type: 'object',
      properties: {
        url: {
          type: 'string',
          description: 'URL or Location header value to sanitize',
        },
      },
      required: ['url'],
    },
  },
];

export async function GET() {
  return NextResponse.json({
    $schema: 'https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json',
    name: 'io.github.reverse-psychology/rp',
    title: 'Reverse Psychology',
    description:
      'Reverse engineer anything from your terminal or agent with one CLI and MCP server.',
    version: '6.8.0',
    transport: ['stdio', 'streamable-http'],
    toolsCount: MCP_TOOLS_CATALOG.length,
    tools: MCP_TOOLS_CATALOG,
  });
}

export async function POST(request: Request) {
  try {
    const rpc = await request.json();
    const id = rpc.id ?? 1;
    const method = rpc.method ?? 'tools/list';
    const params = rpc.params ?? {};

    if (method === 'initialize') {
      return NextResponse.json({
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: '2025-06-18',
          serverInfo: {
            name: 'reverse-psychology-mcp',
            version: '6.8.0',
          },
          capabilities: {
            tools: { listChanged: false },
          },
        },
      });
    }

    if (method === 'tools/list') {
      return NextResponse.json({
        jsonrpc: '2.0',
        id,
        result: {
          tools: MCP_TOOLS_CATALOG,
        },
      });
    }

    if (method === 'tools/call') {
      const toolName = params.name;
      const args = params.arguments ?? {};

      if (toolName === 'rp_redact_whatwg_url') {
        const inputUrl = String(args.url ?? 'https://admin:secret_pw@example.test\\path@tail');
        const outcome = withoutUserinfoWhatwg(inputUrl);
        return NextResponse.json({
          jsonrpc: '2.0',
          id,
          result: {
            isError: false,
            content: [
              {
                type: 'text',
                text: JSON.stringify(
                  {
                    tool: 'rp_redact_whatwg_url',
                    input: inputUrl,
                    safeUrl: outcome.safeUrl,
                    credentialRedacted: outcome.redacted,
                    policy: 'WHATWG special-scheme authority terminator & userinfo stripper',
                  },
                  null,
                  2
                ),
              },
            ],
          },
        });
      }

      if (toolName === 'rp_environment_build') {
        const preset =
          SAMPLE_ARTIFACT_PRESETS.find((p) => p.id === 'har-rl-env') ??
          SAMPLE_ARTIFACT_PRESETS[3]!;
        const harText =
          typeof args.harJson === 'string' && args.harJson.trim()
            ? args.harJson
            : new TextDecoder().decode(preset.buildBytes());
        const envBuild = buildRlEnvironmentFromHar(
          harText,
          typeof args.envName === 'string' ? args.envName : 'my-env'
        );
        return NextResponse.json({
          jsonrpc: '2.0',
          id,
          result: {
            isError: false,
            content: [
              {
                type: 'text',
                text: JSON.stringify(envBuild, null, 2),
              },
            ],
          },
        });
      }

      if (toolName === 'rp_analyze_javascript_application') {
        const preset =
          SAMPLE_ARTIFACT_PRESETS.find((p) => p.id === (args.presetId || 'notion-electron-ipc')) ??
          SAMPLE_ARTIFACT_PRESETS[1]!;
        const bytes =
          typeof args.sourceCode === 'string' && args.sourceCode.trim()
            ? new TextEncoder().encode(args.sourceCode)
            : preset.buildBytes();
        const report = await analyzeArtifact(preset.fileName, bytes);
        return NextResponse.json({
          jsonrpc: '2.0',
          id,
          result: {
            isError: false,
            content: [
              {
                type: 'text',
                text: JSON.stringify(
                  {
                    target: report.targetName,
                    sha256: report.sha256,
                    jsAnalysis: report.jsAnalysis,
                    evidenceLedger: report.evidenceLedger,
                  },
                  null,
                  2
                ),
              },
            ],
          },
        });
      }

      // Default: rp_inspect_binary
      const presetId = typeof args.presetId === 'string' ? args.presetId : 'dx-ball-elf';
      const preset =
        SAMPLE_ARTIFACT_PRESETS.find((p) => p.id === presetId) ?? SAMPLE_ARTIFACT_PRESETS[0]!;
      let bytes = preset.buildBytes();
      if (typeof args.hexBytes === 'string' && args.hexBytes.trim()) {
        const cleaned = args.hexBytes.replace(/[^0-9a-fA-F]/g, '');
        if (cleaned.length >= 2) {
          const arr = new Uint8Array(Math.floor(cleaned.length / 2));
          for (let i = 0; i < arr.length; i++) {
            arr[i] = parseInt(cleaned.slice(i * 2, i * 2 + 2), 16);
          }
          bytes = arr;
        }
      }

      const report = await analyzeArtifact(preset.fileName, bytes);
      return NextResponse.json({
        jsonrpc: '2.0',
        id,
        result: {
          isError: false,
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  target: report.targetName,
                  format: report.format,
                  architecture: report.architecture,
                  entryPoint: report.entryPoint,
                  sha256: report.sha256,
                  instructionsCount: report.instructions.length,
                  instructions: report.instructions.slice(0, 16),
                  decompiledPseudocode: report.decompiledPseudocode,
                  evidenceLedger: report.evidenceLedger,
                },
                null,
                2
              ),
            },
          ],
        },
      });
    }

    return NextResponse.json({
      jsonrpc: '2.0',
      id,
      error: {
        code: -32601,
        message: `Unsupported MCP method: ${method}`,
      },
    });
  } catch (error: unknown) {
    return NextResponse.json(
      {
        jsonrpc: '2.0',
        id: null,
        error: {
          code: -32603,
          message: error instanceof Error ? error.message : 'Internal MCP error',
        },
      },
      { status: 500 }
    );
  }
}
