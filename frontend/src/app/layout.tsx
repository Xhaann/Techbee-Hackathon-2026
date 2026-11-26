import type { Metadata, Viewport } from "next";
import { Geist_Mono, Inter } from "next/font/google";
import { THEME_BOOTSTRAP } from "@/lib/theme-script";
import { Providers } from "./providers";
import "./globals.css";

// The reference mock is set in Inter with a monospace for readings and identifiers.
const inter = Inter({ variable: "--font-inter", subsets: ["latin"], display: "swap" });
const geistMono = Geist_Mono({ variable: "--font-geist-mono", subsets: ["latin"], display: "swap" });

export const metadata: Metadata = {
  title: { default: "Network diagnosis", template: "%s · Network diagnosis" },
  description: "Incident workspace for diagnosing enterprise network faults from telemetry, topology and runbooks.",
};

export const viewport: Viewport = {
  themeColor: [
    { media: "(prefers-color-scheme: dark)", color: "#17191d" },
    { media: "(prefers-color-scheme: light)", color: "#ffffff" },
  ],
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" data-theme="dark" suppressHydrationWarning className={`${inter.variable} ${geistMono.variable} h-full`}>
      <head>
        <script dangerouslySetInnerHTML={{ __html: THEME_BOOTSTRAP }} />
      </head>
      <body className="h-full bg-page text-ink">
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
