"use client";

import { ArrowRight, ShieldCheck } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useState, type FormEvent } from "react";
import { useMounted } from "@/components/shell/app-shell";
import { ErrorNote } from "@/components/ui/atoms";
import { Spinner } from "@/components/ui/button";
import { TextField } from "@/components/ui/fields";
import { describeError, isApiError } from "@/lib/api/client";
import { useAuth } from "@/lib/auth";

export default function SignInPage() {
  const mounted = useMounted();
  const { state, signIn } = useAuth();
  const router = useRouter();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (state.status === "signed-in") {
      const back = window.sessionStorage.getItem("noc.returnTo");
      window.sessionStorage.removeItem("noc.returnTo");
      router.replace(back && back !== "/signin" ? back : "/diagnose");
    }
  }, [state.status, router]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await signIn(username, password);
    } catch (caught) {
      if (isApiError(caught) && caught.status === 401) setError("That ID or password is incorrect.");
      else setError(describeError(caught));
    } finally {
      setBusy(false);
    }
  }

  const notice = state.status === "signed-out" ? state.notice : undefined;

  return (
    <main className="grid min-h-dvh place-items-center bg-page px-4 py-10">
      <div className="w-full max-w-[420px]">
        <div className="mb-6 flex items-center gap-2.5 text-ink-3">
          <ShieldCheck className="size-[18px] text-green" aria-hidden />
          <span className="text-[13px]">Read-only diagnosis, human-approved changes</span>
        </div>
        <h1 className="text-[28px] font-semibold leading-[1.1] tracking-[-0.03em] text-balance text-ink">Sign in to the incident workspace</h1>
        <p className="mt-2.5 text-[14px] leading-[1.5] text-ink-3 text-pretty">
          Sign in with your workspace ID and password. The session stays in this tab and ends when you close it.
        </p>

        {mounted ? (
          <form onSubmit={submit} className="mt-7 space-y-4">
            {notice ? <p className="rounded-[8px] bg-amber-soft px-3 py-2.5 text-[13px] text-amber">{notice}</p> : null}
            <TextField label="ID" name="username" autoComplete="username" autoFocus required value={username} onChange={setUsername} />
            <TextField label="Password" name="password" type="password" autoComplete="current-password" required value={password} onChange={setPassword} />
            {error ? <ErrorNote message={error} /> : null}
            <button
              type="submit"
              disabled={busy || !username.trim() || !password}
              className="inline-flex h-10 w-full items-center justify-center gap-2 rounded-[8px] bg-accent-strong text-[14px] font-medium text-accent-fg shadow-[inset_0_1px_0_rgb(255_255_255/0.14)] transition-[background-color,translate] duration-150 hover:bg-accent-strong-hover active:translate-y-px disabled:opacity-45"
            >
              {busy ? (
                <>
                  <Spinner /> Signing in
                </>
              ) : (
                <>
                  Sign in <ArrowRight className="size-4" aria-hidden />
                </>
              )}
            </button>
          </form>
        ) : (
          <div className="mt-7 h-[300px]" aria-busy="true" />
        )}
      </div>
    </main>
  );
}
