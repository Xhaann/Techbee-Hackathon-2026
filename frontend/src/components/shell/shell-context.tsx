"use client";

import { createContext, useContext } from "react";

export type ShellContextValue = {
  openPalette: () => void;
  /** Small screens: the sidebar slides over the page. */
  mobileNavOpen: boolean;
  setMobileNavOpen: (open: boolean) => void;
};

export const ShellContext = createContext<ShellContextValue | null>(null);

export function useShell() {
  const context = useContext(ShellContext);
  if (!context) throw new Error("useShell must be used inside AppShell");
  return context;
}
