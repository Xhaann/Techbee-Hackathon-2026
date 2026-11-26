"use client";

import { ArrowRight } from "lucide-react";
import { Fragment } from "react";
import { Topbar } from "@/components/shell/topbar";
import { Kbd } from "@/components/ui/atoms";
import { useAuth } from "@/lib/auth";
import { STATUS_LABEL } from "@/lib/labels";
import { SCENARIOS } from "@/lib/scenarios";

const FLOW = ["new", "acknowledged", "investigating", "diagnosed", "escalated", "monitoring", "resolved", "closed"] as const;

const WHO: [string, string][] = [
  ["Viewer", "Reads incidents, diagnoses, topology and reports."],
  ["Network engineer (operator)", "Opens incidents, runs diagnoses, recommends escalations and proposes fixes."],
  ["Incident manager", "Everything above, plus confirming the fault domain, changing severity, verifying fixes, closing and reopening."],
];

export function HelpView() {
  const { baseUrl } = useAuth();
  return (
    <>
      <Topbar crumbs={[{ label: "Help & support" }]} />
      <div className="scroll-thin min-h-0 flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-[820px] space-y-9 px-5 pt-8 pb-16 md:px-8">
          <section>
            <h1 className="text-[26px] font-semibold tracking-[-0.03em] text-ink">How an incident moves</h1>
            <p className="mt-2 text-[13.5px] leading-[1.5] text-ink-3">
              The workspace suggests the next step at the bottom of each incident. Anything that changes the record of what happened, like
              confirming a fault domain or closing, needs a person.
            </p>
            <ol className="mt-4 flex flex-wrap items-center gap-x-2 gap-y-2">
              {FLOW.map((status, index) => (
                <Fragment key={status}>
                  {index > 0 ? <ArrowRight className="size-3.5 text-ink-4" aria-hidden /> : null}
                  <li className="rounded-[7px] bg-surface px-2.5 py-1 text-[12.5px] text-ink-2 shadow-[var(--ring-card)]">{STATUS_LABEL[status]}</li>
                </Fragment>
              ))}
            </ol>
          </section>

          <section>
            <h2 className="text-[15px] font-semibold tracking-[-0.015em] text-ink">Who can do what</h2>
            <dl className="card mt-3 divide-y divide-line-soft">
              {WHO.map(([role, text]) => (
                <div key={role} className="grid gap-1 px-4 py-3 sm:grid-cols-[220px_1fr]">
                  <dt className="text-[13px] font-medium text-ink">{role}</dt>
                  <dd className="text-[13px] leading-[1.5] text-ink-3">{text}</dd>
                </div>
              ))}
            </dl>
          </section>

          <section>
            <h2 className="text-[15px] font-semibold tracking-[-0.015em] text-ink">Keyboard</h2>
            <ul className="mt-3 space-y-2 text-[13px] text-ink-2">
              <li className="flex items-center gap-3">
                <Kbd>⌘K</Kbd> Search incidents, devices, playbooks and pages
              </li>
              <li className="flex items-center gap-3">
                <Kbd>Enter</Kbd> Send a question to the diagnosis agent (<Kbd>Shift Enter</Kbd> for a new line)
              </li>
              <li className="flex items-center gap-3">
                <Kbd>← →</Kbd> Move between tabs in an incident
              </li>
            </ul>
          </section>

          <section>
            <h2 className="text-[15px] font-semibold tracking-[-0.015em] text-ink">Telemetry datasets</h2>
            <p className="mt-1.5 text-[13px] text-ink-3">Every incident is diagnosed against one synthetic dataset. Pick the one that matches what users report.</p>
            <dl className="card mt-3 divide-y divide-line-soft">
              {SCENARIOS.map((scenario) => (
                <div key={scenario.id} className="grid gap-1 px-4 py-3 sm:grid-cols-[220px_1fr]">
                  <dt className="font-mono text-[12px] text-ink">{scenario.id}</dt>
                  <dd className="text-[13px] leading-[1.5] text-ink-3">{scenario.summary}</dd>
                </div>
              ))}
            </dl>
          </section>

          <section>
            <h2 className="text-[15px] font-semibold tracking-[-0.015em] text-ink">Signing in and API tokens</h2>
            <p className="mt-1.5 text-[13px] leading-[1.5] text-ink-3">
              The workspace sign-in uses the ID and password set by <span className="font-mono">ADMIN_USERNAME</span> and{" "}
              <span className="font-mono">ADMIN_PASSWORD</span> in <span className="font-mono">backend/.env</span>. For scripts or
              Postman, issue a token on the backend host; it is shown once. Swap the role for{" "}
              <span className="font-mono">viewer</span> or <span className="font-mono">incident_manager</span>.
            </p>
            <pre className="mt-3 overflow-x-auto rounded-[8px] bg-sunken p-3 font-mono text-[12px] leading-[1.6] text-ink-2 shadow-[0_0_0_1px_var(--line-soft)]">
              {`cd backend
AUTH_TOKENS_FILE=var/auth/tokens.json .venv/bin/python -m app.security.tokens issue \\
  --subject noc.operator --kind human --role operator --expires-hours 24`}
            </pre>
            <p className="mt-3 text-[13px] text-ink-3">
              The full API reference is at{" "}
              <a href={`${baseUrl}/docs`} target="_blank" rel="noreferrer" className="text-accent hover:underline">
                {baseUrl}/docs
              </a>
              .
            </p>
          </section>
        </div>
      </div>
    </>
  );
}
