import type { Metadata } from 'next';
import { Plus_Jakarta_Sans, DM_Sans, JetBrains_Mono } from 'next/font/google';
import './globals.css';

const jakarta = Plus_Jakarta_Sans({
  subsets: ['latin'],
  weight: ['600', '700'],
  variable: '--font-display',
});

const dmSans = DM_Sans({
  subsets: ['latin'],
  weight: ['400', '500', '600'],
  variable: '--font-sans',
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ['latin'],
  weight: ['400', '500', '600'],
  variable: '--font-mono',
});

export const metadata: Metadata = {
  title: 'Reverse Psychology',
  description:
    'One MCP and interactive workbench for evidence-backed reverse engineering across native binaries, JavaScript/Electron bundles, WebAssembly, EVM bytecode, and recorded network captures.',
  openGraph: {
    title: 'Reverse Psychology',
    description:
      'One MCP and interactive workbench for evidence-backed reverse engineering across native binaries, JavaScript/Electron bundles, WebAssembly, EVM bytecode, and recorded network captures.',
    type: 'website',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Reverse Psychology',
    description:
      'One MCP and interactive workbench for evidence-backed reverse engineering across native binaries, JavaScript/Electron bundles, WebAssembly, EVM bytecode, and recorded network captures.',
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html
      lang="en"
      className={`${jakarta.variable} ${dmSans.variable} ${jetbrainsMono.variable} dark`}
    >
      <body
        suppressHydrationWarning
        className="bg-[#0B0F17] text-slate-100 font-sans antialiased selection:bg-indigo-500/30 selection:text-indigo-200"
      >
        {children}
      </body>
    </html>
  );
}
