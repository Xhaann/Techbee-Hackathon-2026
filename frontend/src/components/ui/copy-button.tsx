"use client";

import { Check, Copy } from "lucide-react";
import { useState } from "react";
import { cn } from "@/lib/cn";

export function CopyButton({ text, label = "Copy", className }: { text: string; label?: string; className?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      aria-label={copied ? "Copied" : label}
      onClick={async () => {
        await navigator.clipboard.writeText(text);
        setCopied(true);
        window.setTimeout(() => setCopied(false), 1400);
      }}
      className={cn("grid size-7 shrink-0 place-items-center rounded-[6px] text-ink-3 hover:bg-hover hover:text-ink", className)}
    >
      {copied ? <Check className="size-3.5 text-green" aria-hidden /> : <Copy className="size-3.5" aria-hidden />}
    </button>
  );
}
