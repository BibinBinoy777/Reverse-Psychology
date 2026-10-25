export interface SampleArtifactPreset {
  id: string;
  name: string;
  fileName: string;
  patchedFileName: string;
  patchDescription: string;
  category: string;
  tagline: string;
  showcaseRef: string;
  defaultQuestion: string;
  buildBytes: () => Uint8Array;
  buildPatchedBytes: () => Uint8Array;
}

/** Synthesize a real ELF64 x86_64 binary containing the 63-byte DX-Ball sound-pan function + .rodata */
function buildDxBallElf64Bytes(): Uint8Array {
  const buf = new Uint8Array(192);
  const elfHeader = [
    0x7f, 0x45, 0x4c, 0x46,
    0x02, 0x01, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x3e, 0x00,
    0x01, 0x00, 0x00, 0x00,
    0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x38, 0x00, 0x01, 0x00, 0x40, 0x00, 0x03, 0x00, 0x02, 0x00,
  ];
  buf.set(elfHeader, 0);

  // .text @ 0x40: v1.09 original calc_sound_pan (multiplier 25, bounds [-1000, 1000])
  const code = [
    0xf3, 0x0f, 0x1e, 0xfa, // endbr64
    0x55, // push rbp
    0x48, 0x89, 0xe5, // mov rbp, rsp
    0x29, 0xf7, // sub edi, esi (delta = ball_x - paddle_x)
    0x6b, 0xc7, 0x19, // imul eax, edi, 25
    0xc1, 0xf8, 0x04, // sar eax, 4
    0x81, 0xf8, 0x18, 0xfc, 0xff, 0xff, // cmp eax, -1000
    0x7d, 0x07, // jge +7
    0xb8, 0x18, 0xfc, 0xff, 0xff, // mov eax, -1000
    0x5d, // pop rbp
    0xc3, // ret
    0x81, 0xf8, 0xe8, 0x03, 0x00, 0x00, // cmp eax, 1000
    0x7e, 0x05, // jle +5
    0xb8, 0xe8, 0x03, 0x00, 0x00, // mov eax, 1000
    0x5d, // pop rbp
    0xc3, // ret
    0x90, 0x90, // nop alignment
  ];
  buf.set(code, 0x40);

  const rodataStr = 'calc_sound_pan\x00DSound_SetPan_Clamp[-1000,1000]\x00DXBall_v1.09_x86\x00';
  const rodataBytes = new TextEncoder().encode(rodataStr);
  buf.set(rodataBytes.slice(0, buf.length - 0x70), 0x70);

  return buf;
}

/** Patched v2 ELF64 binary: Wide-stereo patch (multiplier 32 / 0x20, bounds [-1200, 1200] + stack frame guard) */
function buildDxBallElf64PatchedBytes(): Uint8Array {
  const buf = new Uint8Array(192);
  const elfHeader = [
    0x7f, 0x45, 0x4c, 0x46,
    0x02, 0x01, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x3e, 0x00,
    0x01, 0x00, 0x00, 0x00,
    0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x38, 0x00, 0x01, 0x00, 0x40, 0x00, 0x03, 0x00, 0x02, 0x00,
  ];
  buf.set(elfHeader, 0);

  // .text @ 0x40: Patched v1.12 wide-stereo calc_sound_pan (multiplier 32, bounds [-1200, 1200])
  // -1200 in 32-bit two's complement LE = 0x50 0xfb 0xff 0xff
  // +1200 in 32-bit LE = 0xb0 0x04 0x00 0x00
  const code = [
    0xf3, 0x0f, 0x1e, 0xfa, // endbr64
    0x55, // push rbp
    0x48, 0x89, 0xe5, // mov rbp, rsp
    0x48, 0x83, 0xec, 0x10, // [ADDED] sub rsp, 0x10 (stack frame alignment)
    0x29, 0xf7, // sub edi, esi (delta = ball_x - paddle_x)
    0x6b, 0xc7, 0x20, // [MODIFIED] imul eax, edi, 32 (was 25)
    0xc1, 0xf8, 0x04, // sar eax, 4
    0x81, 0xf8, 0x50, 0xfb, 0xff, 0xff, // [MODIFIED] cmp eax, -1200 (was -1000)
    0x7d, 0x07, // jge +7
    0xb8, 0x50, 0xfb, 0xff, 0xff, // [MODIFIED] mov eax, -1200 (was -1000)
    0xc9, // [MODIFIED] leave (replaces pop rbp)
    0xc3, // ret
    0x81, 0xf8, 0xb0, 0x04, 0x00, 0x00, // [MODIFIED] cmp eax, 1200 (was 1000)
    0x7e, 0x05, // jle +5
    0xb8, 0xb0, 0x04, 0x00, 0x00, // [MODIFIED] mov eax, 1200 (was 1000)
    0xc9, // [MODIFIED] leave
    0xc3, // ret
  ];
  buf.set(code, 0x40);

  const rodataStr = 'calc_sound_pan_v2\x00DSound_SetPan_Clamp[-1200,1200]\x00DXBall_v1.12_x86\x00';
  const rodataBytes = new TextEncoder().encode(rodataStr);
  buf.set(rodataBytes.slice(0, buf.length - 0x74), 0x74);

  return buf;
}

/** Real Electron Multi-Module Bundle (Showcase 2: Notion Clipboard Bridge v1) */
function buildNotionClipboardElectronBytes(): Uint8Array {
  const bundle = `// === MODULE: src/renderer/clipboardController.js ===
const { serializeBlockTree } = require('../shared/blockSerializer');

export async function copySelectedBlocksToClipboard(selectedBlocks) {
  const plainText = selectedBlocks.map(b => b.text).join('\\n');
  const htmlFragment = '<div data-notion-blocks="v3">' + plainText + '</div>';
  const serializedBlocksJson = serializeBlockTree(selectedBlocks);

  // Invoke preload bridge exposed on window.notionDesktopBridge
  return await window.notionDesktopBridge.writeRichClipboard({
    plainText,
    htmlFragment,
    serializedBlocksJson,
  });
}

// === MODULE: src/preload/desktopBridge.js ===
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('notionDesktopBridge', {
  writeRichClipboard: (payload) =>
    ipcRenderer.invoke('notion:clipboard-write-rich', payload),
  readRichClipboard: () =>
    ipcRenderer.invoke('notion:clipboard-read-rich'),
  notifySyncStatus: (state) =>
    ipcRenderer.send('notion:clipboard-telemetry', state),
});

// === MODULE: src/main/clipboardIpcHandler.js ===
const { ipcMain, clipboard } = require('electron');
const nativeAddon = require('./native/clipboard_mac_pasteboard.node');

const CUSTOM_MIME = 'application/x-notion-blocks-v3';

ipcMain.handle('notion:clipboard-write-rich', async (_event, payload) => {
  if (!payload || typeof payload.serializedBlocksJson !== 'string') {
    throw new Error('Malformed rich clipboard payload');
  }
  const customBuffer = Buffer.from(payload.serializedBlocksJson, 'utf8');
  clipboard.write({
    text: payload.plainText || '',
    html: payload.htmlFragment || '',
  });
  clipboard.writeBuffer(CUSTOM_MIME, customBuffer);
  nativeAddon.syncPasteboardGenerationCount(customBuffer.byteLength);
  return { ok: true, bytesWritten: customBuffer.byteLength, format: CUSTOM_MIME };
});

ipcMain.handle('notion:clipboard-read-rich', async () => {
  const buf = clipboard.readBuffer(CUSTOM_MIME);
  return {
    text: clipboard.readText(),
    html: clipboard.readHTML(),
    customBlocks: buf.byteLength > 0 ? buf.toString('utf8') : null,
  };
});
`;
  return new TextEncoder().encode(bundle);
}

/** Patched v2 Electron Bundle: Adds sender frame origin check, 4 MiB payload cap, and HTML sanitizer */
function buildNotionClipboardElectronPatchedBytes(): Uint8Array {
  const bundle = `// === MODULE: src/renderer/clipboardController.js ===
const { serializeBlockTree } = require('../shared/blockSerializer');
const { sanitizeClipboardHtml } = require('../shared/htmlSanitizer');

export async function copySelectedBlocksToClipboard(selectedBlocks) {
  const plainText = selectedBlocks.map(b => b.text).join('\\n');
  const htmlFragment = sanitizeClipboardHtml('<div data-notion-blocks="v4">' + plainText + '</div>');
  const serializedBlocksJson = serializeBlockTree(selectedBlocks);

  // Invoke preload bridge exposed on window.notionDesktopBridge
  return await window.notionDesktopBridge.writeRichClipboard({
    plainText,
    htmlFragment,
    serializedBlocksJson,
    schemaVersion: 4,
  });
}

// === MODULE: src/preload/desktopBridge.js ===
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('notionDesktopBridge', {
  writeRichClipboard: (payload) =>
    ipcRenderer.invoke('notion:clipboard-write-rich-v4', payload),
  readRichClipboard: () =>
    ipcRenderer.invoke('notion:clipboard-read-rich-v4'),
});

// === MODULE: src/main/clipboardIpcHandler.js ===
const { ipcMain, clipboard } = require('electron');
const nativeAddon = require('./native/clipboard_mac_pasteboard.node');

const CUSTOM_MIME = 'application/x-notion-blocks-v4';
const MAX_CLIPBOARD_BYTES = 4 * 1024 * 1024;

ipcMain.handle('notion:clipboard-write-rich-v4', async (event, payload) => {
  if (!event.senderFrame || !event.senderFrame.url.startsWith('https://www.notion.so')) {
    throw new Error('Unauthorized IPC sender frame origin');
  }
  if (!payload || typeof payload.serializedBlocksJson !== 'string') {
    throw new Error('Malformed rich clipboard payload');
  }
  const customBuffer = Buffer.from(payload.serializedBlocksJson, 'utf8');
  if (customBuffer.byteLength > MAX_CLIPBOARD_BYTES) {
    throw new Error('Clipboard buffer exceeds 4 MiB safety ceiling');
  }
  clipboard.write({
    text: payload.plainText || '',
    html: payload.htmlFragment || '',
  });
  clipboard.writeBuffer(CUSTOM_MIME, customBuffer);
  nativeAddon.syncPasteboardGenerationCount(customBuffer.byteLength);
  return { ok: true, bytesWritten: customBuffer.byteLength, format: CUSTOM_MIME };
});
`;
  return new TextEncoder().encode(bundle);
}

/** Real 16-bit DOS / PC-98 COM Binary (Showcase 3: TH04 Bullet-Ring v1) */
function buildTh04DosComBytes(): Uint8Array {
  const code = [
    0x55, // push bp
    0x89, 0xe5, // mov bp, sp
    0x53, // push bx
    0x56, // push si
    0xb8, 0x00, 0x01, // mov ax, 0x0100 (256 binary radians full circle)
    0x31, 0xd2, // xor dx, dx
    0x83, 0xf9, 0x00, // cmp cx, 0 (ring_count == 0 check)
    0x74, 0x12, // je +18 (exit if zero)
    0x01, 0xd8, // add ax, bx (accumulate aimed angle step)
    0xe8, 0x08, 0x00, // call 1000:011c (emit_bullet_polar)
    0x83, 0xe9, 0x01, // cmp cx, 1
    0x75, 0xf6, // jne loop_next
    0x5e, // pop si
    0x5b, // pop bx
    0x5d, // pop bp
    0xc3, // ret
    0xcd, 0x21, // int 0x21
  ];
  const asciiTail = new TextEncoder().encode('TH04_PC98_BULLET_RING_ATAN2_256\x00');
  const out = new Uint8Array(code.length + asciiTail.length);
  out.set(code, 0);
  out.set(asciiTail, code.length);
  return out;
}

/** Patched v2 16-bit DOS COM Binary: Lunatic difficulty phase offset + cap check */
function buildTh04DosComPatchedBytes(): Uint8Array {
  const code = [
    0x55, // push bp
    0x89, 0xe5, // mov bp, sp
    0x53, // push bx
    0x56, // push si
    0x57, // [ADDED] push di (preserve phase jitter register)
    0xb8, 0x00, 0x02, // [MODIFIED] mov ax, 0x0200 (512 sub-angle precision)
    0x31, 0xd2, // xor dx, dx
    0x83, 0xf9, 0x40, // [MODIFIED] cmp cx, 64 (max ring cap check)
    0x7f, 0x14, // [MODIFIED] jg exit_cap (prevent sprite buffer overflow)
    0x01, 0xd8, // add ax, bx
    0xc1, 0xe8, 0x01, // [ADDED] shr ax, 1 (normalize to 256-step Bradman lookup)
    0xe8, 0x08, 0x00, // call emit_bullet_polar
    0x83, 0xe9, 0x01, // cmp cx, 1
    0x75, 0xf3, // [MODIFIED] jne loop_next
    0x5f, // [ADDED] pop di
    0x5e, // pop si
    0x5b, // pop bx
    0x5d, // pop bp
    0xc3, // ret
  ];
  const asciiTail = new TextEncoder().encode('TH04_PC98_BULLET_RING_V2_CAP64\x00');
  const out = new Uint8Array(code.length + asciiTail.length);
  out.set(code, 0);
  out.set(asciiTail, code.length);
  return out;
}

/** Real EVM Runtime Bytecode with PUSH4 Dispatch Table (v1) */
function buildEvmVaultBytecode(): Uint8Array {
  return new Uint8Array([
    0x60, 0x80, 0x60, 0x40, 0x52, // PUSH1 0x80 PUSH1 0x40 MSTORE
    0x60, 0x04, 0x36, 0x10, 0x60, 0x3f, 0x57, // CALLDATASIZE < 4 -> JUMPI
    0x60, 0x00, 0x35, 0x60, 0xe0, 0x1c, // PUSH1 0x00 CALLDATALOAD PUSH1 0xe0 SHR
    0x80, 0x63, 0xd0, 0xe3, 0x0d, 0xb0, 0x14, 0x60, 0x44, 0x57, // deposit()
    0x80, 0x63, 0x2e, 0x1a, 0x7d, 0x4d, 0x14, 0x60, 0x50, 0x57, // withdraw(uint256)
    0x80, 0x63, 0xa9, 0x05, 0x9c, 0xbb, 0x14, 0x60, 0x64, 0x57, // transfer(address,uint256)
    0x80, 0x63, 0x8d, 0xa5, 0xcb, 0x5b, 0x14, 0x60, 0x78, 0x57, // owner()
    0x5b, 0x60, 0x00, 0x80, 0xfd, // JUMPDEST REVERT
    0x5b, 0x33, 0x60, 0x01, 0x54, 0x34, 0x01, 0x60, 0x01, 0x55, 0x00, // deposit body
    0x5b, 0x34, 0x15, 0x60, 0x58, 0x57, 0x60, 0x00, 0x80, 0xfd, // withdraw non-payable check
    0x5b, 0x60, 0x00, 0x54, 0x60, 0x40, 0x52, 0x60, 0x20, 0x60, 0x40, 0xf3, // owner body
  ]);
}

/** Patched v2 EVM Runtime Bytecode: Adds balanceOf(address) 0x70a08231 & Reentrancy Guard on slot 0x02 */
function buildEvmVaultPatchedBytecode(): Uint8Array {
  return new Uint8Array([
    0x60, 0x80, 0x60, 0x40, 0x52, // PUSH1 0x80 PUSH1 0x40 MSTORE
    0x60, 0x04, 0x36, 0x10, 0x60, 0x4a, 0x57, // [MODIFIED] JUMPI offset 0x4a
    0x60, 0x00, 0x35, 0x60, 0xe0, 0x1c, // Extract 4-byte selector
    0x80, 0x63, 0xd0, 0xe3, 0x0d, 0xb0, 0x14, 0x60, 0x4f, 0x57, // deposit()
    0x80, 0x63, 0x2e, 0x1a, 0x7d, 0x4d, 0x14, 0x60, 0x5b, 0x57, // withdraw(uint256)
    0x80, 0x63, 0xa9, 0x05, 0x9c, 0xbb, 0x14, 0x60, 0x74, 0x57, // transfer(address,uint256)
    0x80, 0x63, 0x70, 0xa0, 0x82, 0x31, 0x14, 0x60, 0x82, 0x57, // [ADDED] balanceOf(address) 0x70a08231
    0x80, 0x63, 0x8d, 0xa5, 0xcb, 0x5b, 0x14, 0x60, 0x90, 0x57, // owner()
    0x5b, 0x60, 0x00, 0x80, 0xfd, // JUMPDEST REVERT
    0x5b, 0x60, 0x02, 0x54, 0x15, 0x60, 0x01, 0x60, 0x02, 0x55, // [ADDED] Reentrancy Lock SLOAD(2) ISZERO -> SSTORE(2, 1)
    0x33, 0x60, 0x01, 0x54, 0x34, 0x01, 0x60, 0x01, 0x55, 0x00, // deposit body
    0x5b, 0x34, 0x15, 0x60, 0x68, 0x57, 0x60, 0x00, 0x80, 0xfd, // withdraw non-payable check
    0x5b, 0x60, 0x00, 0x54, 0x60, 0x40, 0x52, 0x60, 0x20, 0x60, 0x40, 0xf3, // owner body
  ]);
}

/** Real HAR Session Capture for `rp environment-build` Showcase (v1) */
function buildWorkspaceHarBytes(): Uint8Array {
  const har = {
    log: {
      version: '1.2',
      creator: { name: 'Reverse Psychology Browser Capture', version: '6.8.0' },
      entries: [
        {
          startedDateTime: '2026-10-25T10:15:00.000Z',
          request: {
            method: 'GET',
            url: 'http://admin:supersecret_token@127.0.0.1:3000/api/v1/folders',
            headers: [
              { name: 'Accept', value: 'application/json' },
              { name: 'Authorization', value: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret' },
              { name: 'Cookie', value: 'rp_session=98a7f6d5c4b3a210' },
            ],
          },
          response: {
            status: 200,
            headers: [{ name: 'Content-Type', value: 'application/json' }],
            content: {
              text: JSON.stringify({
                folders: [
                  { id: 'fld_01', name: 'Binary_Samples', itemCount: 14 },
                  { id: 'fld_02', name: 'Electron_Audits', itemCount: 6 },
                ],
              }),
            },
          },
        },
        {
          startedDateTime: '2026-10-25T10:15:04.000Z',
          request: {
            method: 'POST',
            url: 'http://127.0.0.1:3000/api/v1/folders',
            headers: [
              { name: 'Content-Type', value: 'application/json' },
              { name: 'Authorization', value: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret' },
            ],
            postData: {
              text: JSON.stringify({ name: 'RL_Test_Sandbox', parentId: 'root' }),
            },
          },
          response: {
            status: 201,
            headers: [
              { name: 'Content-Type', value: 'application/json' },
              { name: 'Location', value: 'https://ops_user:temp_pw@127.0.0.1:3000/api/v1/folders/fld_03' },
            ],
            content: {
              text: JSON.stringify({ id: 'fld_03', name: 'RL_Test_Sandbox', created: true }),
            },
          },
        },
        {
          startedDateTime: '2026-10-25T10:15:09.000Z',
          request: {
            method: 'PATCH',
            url: 'http://127.0.0.1:3000/api/v1/folders/fld_03',
            headers: [
              { name: 'Content-Type', value: 'application/json' },
              { name: 'Cookie', value: 'rp_session=98a7f6d5c4b3a210' },
            ],
            postData: {
              text: JSON.stringify({ name: 'RL_Verified_Archive' }),
            },
          },
          response: {
            status: 200,
            headers: [{ name: 'Content-Type', value: 'application/json' }],
            content: {
              text: JSON.stringify({ id: 'fld_03', name: 'RL_Verified_Archive', updated: true }),
            },
          },
        },
        {
          startedDateTime: '2026-10-25T10:15:15.000Z',
          request: {
            method: 'DELETE',
            url: 'http://127.0.0.1:3000/api/v1/folders/fld_03',
            headers: [{ name: 'Authorization', value: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret' }],
          },
          response: {
            status: 204,
            headers: [],
            content: { text: '' },
          },
        },
      ],
    },
  };
  return new TextEncoder().encode(JSON.stringify(har, null, 2));
}

/** Patched v2 HAR Session Capture: Adds folder permissions ACL endpoint & lock verification */
function buildWorkspaceHarPatchedBytes(): Uint8Array {
  const har = {
    log: {
      version: '1.2',
      creator: { name: 'Reverse Psychology Browser Capture', version: '6.8.0' },
      entries: [
        {
          startedDateTime: '2026-10-25T10:20:00.000Z',
          request: {
            method: 'GET',
            url: 'http://127.0.0.1:3000/api/v1/folders',
            headers: [{ name: 'Accept', value: 'application/json' }],
          },
          response: {
            status: 200,
            headers: [{ name: 'Content-Type', value: 'application/json' }],
            content: {
              text: JSON.stringify({
                folders: [{ id: 'fld_01', name: 'Binary_Samples', itemCount: 15 }],
              }),
            },
          },
        },
        {
          startedDateTime: '2026-10-25T10:20:04.000Z',
          request: {
            method: 'POST',
            url: 'http://127.0.0.1:3000/api/v1/folders',
            headers: [{ name: 'Content-Type', value: 'application/json' }],
            postData: {
              text: JSON.stringify({ name: 'RL_Test_Sandbox', parentId: 'root', aclMode: 'restricted' }),
            },
          },
          response: {
            status: 201,
            headers: [{ name: 'Content-Type', value: 'application/json' }],
            content: {
              text: JSON.stringify({ id: 'fld_03', name: 'RL_Test_Sandbox', created: true }),
            },
          },
        },
        {
          startedDateTime: '2026-10-25T10:20:08.000Z',
          request: {
            method: 'PUT',
            url: 'http://127.0.0.1:3000/api/v1/permissions/fld_03',
            headers: [{ name: 'Content-Type', value: 'application/json' }],
            postData: {
              text: JSON.stringify({ role: 'auditor', readOnly: true }),
            },
          },
          response: {
            status: 200,
            headers: [{ name: 'Content-Type', value: 'application/json' }],
            content: {
              text: JSON.stringify({ id: 'fld_03', aclUpdated: true }),
            },
          },
        },
        {
          startedDateTime: '2026-10-25T10:20:15.000Z',
          request: {
            method: 'DELETE',
            url: 'http://127.0.0.1:3000/api/v1/folders/fld_03',
            headers: [],
          },
          response: {
            status: 204,
            headers: [],
            content: { text: '' },
          },
        },
      ],
    },
  };
  return new TextEncoder().encode(JSON.stringify(har, null, 2));
}

export const SAMPLE_ARTIFACT_PRESETS: SampleArtifactPreset[] = [
  {
    id: 'dx-ball-elf',
    name: 'DX-Ball Sound-Pan Routine',
    fileName: 'dxball_sound_pan.elf',
    patchedFileName: 'dxball_sound_pan_v2_patched.elf',
    patchDescription:
      'v1.12 Wide-Stereo Patch: Allocates 16-byte stack frame (sub rsp, 0x10), increases pan multiplier from 25 (0x19) to 32 (0x20), widens DirectSound clamp bounds from [-1000, 1000] to [-1200, 1200], and replaces pop rbp with leave.',
    category: 'Native Binary (ELF64 x86_64)',
    tagline: 'Follow a sound call into its position-to-pan helper, inspect the 63 compiled x86 bytes, and reconstruct bit-exact C.',
    showcaseRef: 'Showcase 01 · Native Binary Reconstruction',
    defaultQuestion:
      'Trace calc_sound_pan at 0x00401000, explain how the fixed-point multiplication and arithmetic shift compute the stereo pan, and verify the [-1000, 1000] saturation bounds.',
    buildBytes: buildDxBallElf64Bytes,
    buildPatchedBytes: buildDxBallElf64PatchedBytes,
  },
  {
    id: 'notion-electron-ipc',
    name: 'Notion Electron Clipboard Bridge',
    fileName: 'notion_clipboard_bridge.js',
    patchedFileName: 'notion_clipboard_bridge_v2_hardened.js',
    patchDescription:
      'v4 Security Hardening Patch: Adds senderFrame.url origin verification in ipcMain.handle, enforces a 4 MiB buffer ceiling, upgrades MIME format to v4, and removes unvalidated telemetry send channel.',
    category: 'JavaScript / Electron Bundle',
    tagline: 'Trace the renderer clipboard API through preload contextBridge and IPC into the main process custom MIME buffer.',
    showcaseRef: 'Showcase 02 · Electron IPC & Preload Boundary',
    defaultQuestion:
      'Map the complete clipboard bridge across renderer, preload, and main process. What custom MIME format is written and how is contextIsolation preserved?',
    buildBytes: buildNotionClipboardElectronBytes,
    buildPatchedBytes: buildNotionClipboardElectronPatchedBytes,
  },
  {
    id: 'th04-dos-com',
    name: 'TH04 PC-98 Bullet-Ring Calculation',
    fileName: 'th04_bullet_ring.com',
    patchedFileName: 'th04_bullet_ring_v2_lunatic.com',
    patchDescription:
      'v2 Sprite-Cap Patch: Adds 64-bullet ring ceiling check (cmp cx, 64; jg) to prevent PC-98 VRAM sprite overflow and doubles internal accumulator precision (0x0200 with shr ax, 1).',
    category: '16-Bit DOS / PC-98 Real Mode',
    tagline: 'Inspect 16-bit real-mode instructions at 1000:0100, recover the 256-step binary angle ring loop, and compare with C++.',
    showcaseRef: 'Showcase 03 · 16-Bit Real-Mode Reconstruction',
    defaultQuestion:
      'Analyze the 16-bit real-mode loop at 1000:0100. How does the 256-step binary radian accumulator avoid floating-point instructions?',
    buildBytes: buildTh04DosComBytes,
    buildPatchedBytes: buildTh04DosComPatchedBytes,
  },
  {
    id: 'har-rl-env',
    name: 'Folder API Session -> RL AgentEnv',
    fileName: 'workspace_folders_session.har',
    patchedFileName: 'workspace_folders_session_v2_acl.har',
    patchDescription:
      'v2 RBAC Capture Revision: Replaces PATCH folder rename with PUT /api/v1/permissions/:id ACL mutation and strips legacy plaintext userinfo from recorded URLs.',
    category: 'Saved Network Capture (HAR -> AgentEnv)',
    tagline: 'Turn recorded browser API requests into callable RL agent tools while redacting WHATWG URL userinfo and auth headers.',
    showcaseRef: 'Showcase 04 · RL Environment Builder',
    defaultQuestion:
      'Inspect the recorded HAR session, list all transport credentials redacted under WHATWG URL rules, and generate the RL reward check specification for folder CRUD.',
    buildBytes: buildWorkspaceHarBytes,
    buildPatchedBytes: buildWorkspaceHarPatchedBytes,
  },
  {
    id: 'evm-vault-router',
    name: 'DeFi Vault Router Bytecode',
    fileName: 'defi_vault_router.evm',
    patchedFileName: 'defi_vault_router_v2_reentrancy.evm',
    patchDescription:
      'v2 Reentrancy-Guarded Bytecode: Adds PUSH4 0x70a08231 balanceOf(address) selector to the dispatcher and inserts a slot[0x02] SLOAD/ISZERO/SSTORE reentrancy mutex before deposit state mutation.',
    category: 'EVM Smart Contract Bytecode',
    tagline: 'Extract PUSH4 dispatch selectors, byte offsets, CALLVALUE guards, and storage slot access patterns without source code.',
    showcaseRef: 'Showcase 05 · Offline EVM Bytecode Inspection',
    defaultQuestion:
      'Identify all 4-byte function selectors in the EVM dispatch table, classify their mutability, and explain how storage slots 0x00 and 0x01 are used.',
    buildBytes: buildEvmVaultBytecode,
    buildPatchedBytes: buildEvmVaultPatchedBytecode,
  },
];

export interface TargetCapabilityRow {
  target: string;
  domain: 'Native & Firmware' | 'Web, JS & Electron' | 'Managed & Mobile' | 'Network, Crash & Data';
  returns: string;
  requirements: string;
  cliCommand: string;
}

export const TARGET_CAPABILITY_CATALOG: TargetCapabilityRow[] = [
  {
    target: 'Native binaries (ELF / PE / Mach-O)',
    domain: 'Native & Firmware',
    returns: 'Pseudocode, assembly, strings, symbols, calls and cross-references',
    requirements: 'Built-in static parser + Hopper, Ghidra, or IDA bridge',
    cliCommand: 'rp analyze-binary ./target.elf --provider ghidra --json',
  },
  {
    target: 'JavaScript & Electron apps',
    domain: 'Web, JS & Electron',
    returns: 'Modules, imports, source maps, routes, IPC channels and native add-on handoffs',
    requirements: 'Built-in AST & ASAR static inspector (no execution required)',
    cliCommand: 'rp analyze-javascript-application /path/to/app.asar --json',
  },
  {
    target: 'Saved network captures (HAR / mitmproxy)',
    domain: 'Network, Crash & Data',
    returns: 'Requests, responses, WHATWG credential redactions, and runnable RL AgentEnv tools',
    requirements: 'HAR 1.2 or offline mitmproxy 12.2.3 tnetstring reader',
    cliCommand: 'rp environment-build ./session.har ./my-env --name my-env --json',
  },
  {
    target: 'Go & Rust binaries',
    domain: 'Native & Firmware',
    returns: 'Embedded compiler version, Go module replacements, and cargo-auditable crate dependency graph',
    requirements: 'Built-in static ELF/PE/Mach-O metadata reader',
    cliCommand: 'rp inspect-go-binary ./service-bin --json',
  },
  {
    target: 'EVM bytecode',
    domain: 'Managed & Mobile',
    returns: 'PUSH4 dispatch selectors, byte offsets, inferred arguments and state mutability',
    requirements: 'Built-in isolated EVMole worker',
    cliCommand: 'rp inspect-evm-bytecode ./contract.evm --json',
  },
  {
    target: 'WASM artifacts',
    domain: 'Web, JS & Electron',
    returns: 'Binary validation, sections, exact import/export WAT signatures and decoded WAT',
    requirements: 'Built-in section reader + WABT 1.0.42 adapter',
    cliCommand: 'rp inspect-wasm-artifact ./module.wasm --json',
  },
  {
    target: 'Android APKs & Signatures',
    domain: 'Managed & Mobile',
    returns: 'Namespace-aware AndroidManifest.xml, v1/v2/v3/v3.1 signers, DEX classes & Smali fallback',
    requirements: 'Built-in APK Signing Block reader + ReaJadxBridge (JADX 1.5.6)',
    cliCommand: 'rp inspect-apk ./app-release.apk --dex-static-values --json',
  },
  {
    target: 'Model artifacts (GGUF / safetensors)',
    domain: 'Network, Crash & Data',
    returns: 'Header key-values, tensor shape declarations, data types and byte totals',
    requirements: 'Built-in bounded header reader (no model weight loading)',
    cliCommand: 'rp inspect-model-artifact ./model.safetensors --json',
  },
  {
    target: 'Unity IL2CPP & Godot PCK',
    domain: 'Managed & Mobile',
    returns: 'global-metadata.dat assembly/type/method tables (v24..v39) and Godot PCK v2..v4 inventories',
    requirements: 'Built-in static binary format decoders',
    cliCommand: 'rp inspect-il2cpp ./global-metadata.dat --json',
  },
  {
    target: 'GPU code objects (CUDA / HIP / PTX)',
    domain: 'Native & Firmware',
    returns: 'SM architecture targets, kernel parameter layouts, shared memory resources and retained PTX',
    requirements: 'Built-in static ELF/PE/fatbin/CUBIN/PTX parser',
    cliCommand: 'rp inspect-gpu-object ./kernels.cubin --json',
  },
  {
    target: '16-Bit DOS COM & GameCube DOL',
    domain: 'Native & Firmware',
    returns: 'Real-mode 1000:0100 segmented disassembly and DOL text/data/BSS section map reconstruction',
    requirements: 'ReaGhidraPrepareCom & ReaGhidraPrepareDol headless bridges',
    cliCommand: 'rp analyze-binary ./th04.com --profile dos-com --json',
  },
  {
    target: 'SQLite databases & Apple IPS crashes',
    domain: 'Network, Crash & Data',
    returns: 'Schema tables, triggers, WAL snapshots, and .ips crash thread registers & image backtraces',
    requirements: 'Built-in read-only snapshot worker',
    cliCommand: 'rp inspect-sqlite ./state.db --read-only --json',
  },
];
