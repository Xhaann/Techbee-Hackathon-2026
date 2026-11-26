"use client";

import { ChevronRight, Menu, PanelLeft } from "lucide-react";
import Link from "next/link";
import { Fragment, type ReactNode } from "react";
import { Tip } from "@/components/ui/tip";
import { cn } from "@/lib/cn";
import { setPrefs, usePrefs } from "@/lib/prefs";
import { useShell } from "./shell-context";

export type Crumb = { label: string; href?: string; mono?: boolean };

export function Topbar({ crumbs, actions }: { crumbs: Crumb[]; actions?: ReactNode }) {
  const { sidebarCollapsed } = usePrefs();
  const { setMobileNavOpen } = useShell();

  return (
    <header className="flex h-[57px] shrink-0 items-center gap-3 bg-chrome px-4 shadow-[inset_0_-1px_0_var(--line)] md:px-6">
      <button
        type="button"
        aria-label="Open navigation"
        onClick={() => setMobileNavOpen(true)}
        className="-ml-1 grid size-8 place-items-center rounded-[7px] text-ink-3 hover:bg-hover hover:text-ink lg:hidden"
      >
        <Menu className="size-[18px]" aria-hidden />
      </button>
      {sidebarCollapsed ? (
        <Tip label="Show sidebar">
          <button
            type="button"
            aria-label="Show sidebar"
            onClick={() => setPrefs({ sidebarCollapsed: false })}
            className="-ml-2 hidden size-8 place-items-center rounded-[7px] text-ink-3 hover:bg-hover hover:text-ink lg:grid"
          >
            <PanelLeft className="size-[18px]" aria-hidden />
          </button>
        </Tip>
      ) : null}

      <nav aria-label="Breadcrumb" className="flex min-w-0 flex-1 items-center gap-2.5">
        {crumbs.map((crumb, index) => {
          const last = index === crumbs.length - 1;
          const text = (
            <span
              className={cn(
                "truncate",
                crumb.mono ? "font-mono text-[12px] text-ink-3" : "text-[15px] font-semibold tracking-[-0.015em]",
                !crumb.mono && (last && index > 0 ? "text-ink-2" : "text-ink"),
              )}
            >
              {crumb.label}
            </span>
          );
          return (
            <Fragment key={`${crumb.label}-${index}`}>
              {index > 0 ? <ChevronRight className="hidden size-3.5 shrink-0 text-ink-4 sm:block" aria-hidden /> : null}
              {crumb.href && !last ? (
                <Link href={crumb.href} className="hidden min-w-0 shrink-0 hover:opacity-80 sm:inline">
                  {text}
                </Link>
              ) : (
                <span className="flex min-w-0" aria-current={last ? "page" : undefined}>
                  {text}
                </span>
              )}
            </Fragment>
          );
        })}
      </nav>

      {actions ? <div className="flex shrink-0 items-center gap-2.5">{actions}</div> : null}
    </header>
  );
}
