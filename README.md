# 🧠 Reverse Psychology

**One MCP and interactive workbench for evidence-backed reverse engineering** across native binaries, JavaScript/Electron bundles, WebAssembly, EVM bytecode, and recorded network captures.

Instead of guessing what a target does, Reverse Psychology aims to tie every finding back to evidence you can inspect.

---

## ✨ What It Covers

| Target | Examples |
|---|---|
| **Native binaries** | Executables and libraries (PE, ELF, Mach-O) |
| **JavaScript / Electron bundles** | Minified web bundles, packaged desktop apps |
| **WebAssembly** | `.wasm` modules |
| **EVM bytecode** | Smart contract bytecode |
| **Network captures** | Recorded traffic (for example HAR or PCAP files) |

## 🔌 Two Ways to Use It

- **Interactive workbench:** a web UI for loading a target, exploring it, and reviewing findings.
- **MCP server:** expose the same analysis to MCP-compatible AI clients, so an assistant can investigate targets with the same tools.

## 🧰 Tech Stack

| Layer | Technology |
|---|---|
| Framework | [Next.js 15](https://nextjs.org/) (App Router) |
| UI | React 19, TypeScript |
| Styling | Tailwind CSS 4 |
| Animation | [Motion](https://motion.dev/) |
| Icons | lucide-react |
| AI | [`@google/genai`](https://www.npmjs.com/package/@google/genai) (Gemini API, server-side) |
| Export | jsPDF |

## 📁 Project Structure

```
├── app/           # Next.js routes, pages and API routes
├── hooks/         # Custom React hooks
├── lib/           # Analysis logic and utilities
├── public/        # Static assets
├── .env.example   # Environment variable template
└── metadata.json  # AI Studio applet metadata
```

## 🚀 Getting Started

### Prerequisites

- Node.js 20 or later (or Bun, since the repo includes `bun.lock`)
- A [Gemini API key](https://aistudio.google.com/apikey)

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/BibinBinoy777/Reverse-Psychology.git
cd Reverse-Psychology

# 2. Install dependencies
npm install      # or: bun install

# 3. Set up environment variables
cp .env.example .env.local
```

Edit `.env.local`:

```env
GEMINI_API_KEY="your_gemini_api_key"
APP_URL="http://localhost:3000"
```

### Run locally

```bash
npm run dev      # or: bun dev
```

Open [http://localhost:3000](http://localhost:3000).

### Scripts

| Command | Description |
|---|---|
| `npm run dev` | Start the development server |
| `npm run build` | Create a production build |
| `npm run start` | Run the production build |
| `npm run lint` | Lint the codebase |
| `npm run clean` | Clean Next.js build output |

## 🔐 Environment Variables

| Variable | Required | Description |
|---|---|---|
| `GEMINI_API_KEY` | Yes | Gemini API key, used server-side |
| `APP_URL` | Yes | URL where the app is hosted |

> Keep `.env.local` out of version control. It is already covered by `.gitignore`.

## 🔌 MCP Setup

<!-- Fill in with your real MCP entry point and transport -->
```json
{
  "mcpServers": {
    "reverse-psychology": {
      "command": "<your command>",
      "args": ["<your args>"]
    }
  }
}
```

## 🎮 Usage

1. Open the workbench and load a target (binary, bundle, `.wasm`, bytecode, or capture).
2. Run the analysis and review the findings.
3. Check the evidence linked to each finding before trusting a conclusion.
4. Export your results.

## ⚠️ Responsible Use

Use this tool only on software, contracts, and traffic you own or have permission to analyze, such as security research, interoperability, malware triage, and audits. Follow the laws and license terms that apply to you.

## 🗺️ Roadmap

- [ ] More file formats and decompilation backends
- [ ] Saved sessions and shareable reports
- [ ] Richer evidence view with cross-references
- [ ] Docker image for easy self-hosting

## 🤝 Contributing

Contributions are welcome. Fork the repo, create a branch, and open a pull request.



## 👤 Author

**Bibin Binoy**
GitHub: [@BibinBinoy777](https://github.com/BibinBinoy777)
