"use client";

import { useSyncExternalStore } from "react";
import { PREFS_KEY } from "./theme-script";

export type Theme = "dark" | "light" | "system";
export type AgentMode = "auto" | "rule_based";

export type Prefs = {
  theme: Theme;
  /** auto: try the model, fall back to rule-based when none is configured. */
  agentMode: AgentMode;
  sidebarCollapsed: boolean;
  agentOpen: boolean;
};

const DEFAULTS: Prefs = { theme: "dark", agentMode: "auto", sidebarCollapsed: false, agentOpen: true };
const KEY = PREFS_KEY;
const listeners = new Set<() => void>();
let cached: Prefs | null = null;

function read(): Prefs {
  if (cached) return cached;
  try {
    cached = { ...DEFAULTS, ...JSON.parse(window.localStorage.getItem(KEY) ?? "{}") };
  } catch {
    cached = DEFAULTS;
  }
  return cached!;
}

export function setPrefs(update: Partial<Prefs>) {
  cached = { ...read(), ...update };
  window.localStorage.setItem(KEY, JSON.stringify(cached));
  if (update.theme) applyTheme(cached.theme);
  listeners.forEach((listener) => listener());
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function usePrefs(): Prefs {
  return useSyncExternalStore(subscribe, read, () => DEFAULTS);
}

export function applyTheme(theme: Theme) {
  const resolved =
    theme === "system" ? (window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark") : theme;
  document.documentElement.dataset.theme = resolved;
}
