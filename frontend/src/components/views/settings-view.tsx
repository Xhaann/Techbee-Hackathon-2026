"use client";

import { LogOut, Monitor, Moon, Sun } from "lucide-react";
import type { ReactNode } from "react";
import { Topbar } from "@/components/shell/topbar";
import { Dot } from "@/components/ui/atoms";
import { Button } from "@/components/ui/button";
import { Segmented } from "@/components/ui/controls";
import { useHealth } from "@/lib/api/hooks";
import { useAuth, usePrincipal } from "@/lib/auth";
import { humanize, ROLE_TITLE } from "@/lib/labels";
import { setPrefs, usePrefs, type AgentMode, type Theme } from "@/lib/prefs";

function Row({ title, detail, children }: { title: string; detail?: ReactNode; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-3 px-5 py-4 sm:flex-row sm:items-center sm:justify-between">
      <div className="min-w-0">
        <div className="text-[14px] font-medium tracking-[-0.01em] text-ink">{title}</div>
        {detail ? <div className="mt-0.5 text-[12.5px] leading-[1.45] text-ink-3">{detail}</div> : null}
      </div>
      <div className="shrink-0">{children}</div>
    </div>
  );
}

export function SettingsView() {
  const prefs = usePrefs();
  const principal = usePrincipal();
  const { baseUrl, signOut } = useAuth();
  const health = useHealth(baseUrl);

  return (
    <>
      <Topbar crumbs={[{ label: "Settings" }]} />
      <div className="scroll-thin min-h-0 flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-[760px] space-y-8 px-5 pt-8 pb-16 md:px-8">
          <section aria-labelledby="look-heading">
            <h2 id="look-heading" className="mb-2.5 text-[13px] font-medium text-ink-3">
              Workspace
            </h2>
            <div className="card divide-y divide-line-soft">
              <Row title="Theme" detail={prefs.theme === "system" ? "Follows your computer." : undefined}>
                <Segmented<Theme>
                  ariaLabel="Theme"
                  value={prefs.theme}
                  onValueChange={(theme) => setPrefs({ theme })}
                  options={[
                    { value: "dark", label: "Dark", icon: <Moon className="size-3.5" aria-hidden /> },
                    { value: "light", label: "Light", icon: <Sun className="size-3.5" aria-hidden /> },
                    { value: "system", label: "System", icon: <Monitor className="size-3.5" aria-hidden /> },
                  ]}
                />
              </Row>
              <Row
                title="Diagnosis agent"
                detail={
                  prefs.agentMode === "auto"
                    ? "Uses the configured model; falls back to rule-based reasoning when the backend has none."
                    : "Always uses the deterministic rule-based planner. No model calls."
                }
              >
                <Segmented<AgentMode>
                  ariaLabel="Diagnosis agent"
                  value={prefs.agentMode}
                  onValueChange={(agentMode) => setPrefs({ agentMode })}
                  options={[
                    { value: "auto", label: "Model when available" },
                    { value: "rule_based", label: "Rule-based only" },
                  ]}
                />
              </Row>
            </div>
          </section>

          <section aria-labelledby="api-heading">
            <h2 id="api-heading" className="mb-2.5 text-[13px] font-medium text-ink-3">
              Connection
            </h2>
            <div className="card divide-y divide-line-soft">
              <Row title="API" detail={<span className="font-mono text-[12px]">{baseUrl}</span>}>
                <span className={health.isSuccess ? "inline-flex items-center gap-2 text-[13px] text-green" : "inline-flex items-center gap-2 text-[13px] text-red"}>
                  <Dot tone={health.isSuccess ? "green" : health.isPending ? "muted" : "red"} />
                  {health.isSuccess ? "Healthy" : health.isPending ? "Checking" : "Not responding"}
                </span>
              </Row>
              <Row title="API reference" detail="Interactive OpenAPI docs served by the backend in development.">
                <a href={`${baseUrl}/docs`} target="_blank" rel="noreferrer" className="text-[13px] text-accent hover:underline">
                  Open /docs
                </a>
              </Row>
            </div>
          </section>

          <section aria-labelledby="account-heading">
            <h2 id="account-heading" className="mb-2.5 text-[13px] font-medium text-ink-3">
              Signed in
            </h2>
            <div className="card divide-y divide-line-soft">
              <Row title={principal.subject} detail={`${principal.roles.map((r) => ROLE_TITLE[r] ?? r).join(", ")} · ${principal.kind} principal`}>
                <Button size="sm" onClick={() => signOut()}>
                  <LogOut className="size-3.5" aria-hidden />
                  Sign out
                </Button>
              </Row>
              <div className="px-5 py-4">
                <div className="text-[12.5px] text-ink-3">What this session can do</div>
                <ul className="mt-2 flex flex-wrap gap-1.5">
                  {principal.permissions.map((permission) => (
                    <li key={permission} className="rounded-[6px] bg-hover px-2 py-1 text-[12px] text-ink-2">
                      {humanize(permission)}
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </section>
        </div>
      </div>
    </>
  );
}
