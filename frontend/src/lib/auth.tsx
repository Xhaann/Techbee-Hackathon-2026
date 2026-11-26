"use client";

import { useQueryClient } from "@tanstack/react-query";
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { configureSession, DEFAULT_API_BASE, onUnauthorized } from "./api/client";
import { api } from "./api/endpoints";
import type { Permission, PrincipalView } from "./api/types";

const TOKEN_KEY = "noc.token";
const BASE_KEY = "noc.apiBase";

type AuthState =
  | { status: "loading" }
  | { status: "signed-out"; notice?: string }
  | { status: "signed-in"; principal: PrincipalView };

type AuthContextValue = {
  state: AuthState;
  baseUrl: string;
  signIn: (username: string, password: string) => Promise<PrincipalView>;
  signOut: (notice?: string) => void;
};

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const [state, setState] = useState<AuthState>({ status: "loading" });
  const [baseUrl, setBaseUrl] = useState(DEFAULT_API_BASE);

  const signOut = useCallback(
    (notice?: string) => {
      window.sessionStorage.removeItem(TOKEN_KEY);
      configureSession({ token: null });
      queryClient.clear();
      setState({ status: "signed-out", notice });
    },
    [queryClient],
  );

  useEffect(() => {
    const storedBase = window.localStorage.getItem(BASE_KEY) || DEFAULT_API_BASE;
    const storedToken = window.sessionStorage.getItem(TOKEN_KEY);
    configureSession({ baseUrl: storedBase, token: storedToken });
    // Reading browser storage has to wait for mount; this syncs React with it once.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setBaseUrl(storedBase);
    if (!storedToken) {
      setState({ status: "signed-out" });
      return;
    }
    let cancelled = false;
    api.auth
      .verify()
      .then((principal) => !cancelled && setState({ status: "signed-in", principal }))
      .catch(() => {
        if (cancelled) return;
        window.sessionStorage.removeItem(TOKEN_KEY);
        configureSession({ token: null });
        setState({ status: "signed-out", notice: "Your token was not accepted. It may have expired." });
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    onUnauthorized(() => signOut("Your session ended. Sign in with a current token."));
    return () => onUnauthorized(null);
  }, [signOut]);

  const signIn = useCallback(async (username: string, password: string) => {
    const { token, principal } = await api.auth.login({ username: username.trim(), password }, DEFAULT_API_BASE);
    window.sessionStorage.setItem(TOKEN_KEY, token);
    window.localStorage.setItem(BASE_KEY, DEFAULT_API_BASE);
    configureSession({ token, baseUrl: DEFAULT_API_BASE });
    setBaseUrl(DEFAULT_API_BASE);
    setState({ status: "signed-in", principal });
    return principal;
  }, []);

  const value = useMemo(() => ({ state, baseUrl, signIn, signOut }), [state, baseUrl, signIn, signOut]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used inside AuthProvider");
  return context;
}

/** The signed-in principal. Only call below the signed-in gate. */
export function usePrincipal() {
  const { state } = useAuth();
  if (state.status !== "signed-in") throw new Error("usePrincipal needs a signed-in session");
  return state.principal;
}

export function useCan() {
  const principal = usePrincipal();
  return useCallback((permission: Permission) => principal.permissions.includes(permission), [principal]);
}
