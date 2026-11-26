"use client";

import { usePathname, useRouter } from "next/navigation";
import { useEffect, useMemo, useState, useSyncExternalStore, type ReactNode } from "react";
import { useAuth } from "@/lib/auth";
import { cn } from "@/lib/cn";
import { usePrefs } from "@/lib/prefs";
import { CommandPalette } from "./command-palette";
import { ShellContext } from "./shell-context";
import { Sidebar } from "./sidebar";

const noop = () => () => {};

/** True only after hydration, so nothing that reads browser storage renders on the server. */
export function useMounted() {
  return useSyncExternalStore(noop, () => true, () => false);
}

export function AppShell({ children }: { children: ReactNode }) {
  const mounted = useMounted();
  const { state } = useAuth();
  const router = useRouter();
  const pathname = usePathname();

  useEffect(() => {
    if (state.status === "signed-out") {
      window.sessionStorage.setItem("noc.returnTo", pathname);
      router.replace("/signin");
    }
  }, [state.status, router, pathname]);

  if (!mounted || state.status !== "signed-in") return <ShellPlaceholder />;
  return <SignedInShell>{children}</SignedInShell>;
}

function SignedInShell({ children }: { children: ReactNode }) {
  const { sidebarCollapsed } = usePrefs();
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const pathname = usePathname();

  // Close the mobile drawer whenever the route changes.
  const [lastPath, setLastPath] = useState(pathname);
  if (lastPath !== pathname) {
    setLastPath(pathname);
    setMobileNavOpen(false);
  }

  const context = useMemo(() => ({ openPalette: () => setPaletteOpen(true), mobileNavOpen, setMobileNavOpen }), [mobileNavOpen]);

  return (
    <ShellContext.Provider value={context}>
      <div className="flex h-dvh overflow-hidden bg-page">
        <div className={cn("hidden lg:block", sidebarCollapsed && "lg:hidden")}>
          <Sidebar />
        </div>

        {mobileNavOpen ? (
          <div className="fixed inset-0 z-40 lg:hidden">
            <button type="button" aria-label="Close navigation" className="absolute inset-0 bg-[var(--scrim)]" onClick={() => setMobileNavOpen(false)} />
            <div className="relative h-full w-[216px] shadow-[var(--shadow-pop)]">
              <Sidebar mobile />
            </div>
          </div>
        ) : null}

        <div className="flex min-w-0 flex-1 flex-col">{children}</div>
      </div>
      <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} />
    </ShellContext.Provider>
  );
}

function ShellPlaceholder() {
  return (
    <div className="flex h-dvh overflow-hidden bg-page" aria-busy="true">
      <div className="hidden w-[216px] shrink-0 bg-sidebar shadow-[inset_-1px_0_0_var(--line)] lg:block">
        <div className="h-[57px] bg-chrome shadow-[inset_0_-1px_0_var(--line)]" />
      </div>
      <div className="flex-1">
        <div className="h-[57px] bg-chrome shadow-[inset_0_-1px_0_var(--line)]" />
      </div>
    </div>
  );
}
