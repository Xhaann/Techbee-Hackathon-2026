"use client";

import { ShieldCheck } from "lucide-react";
import { useMemo, useState } from "react";
import { Counts, ENGINE_STATUS, FindingList, Tag } from "@/components/protocols/findings";
import { Topbar } from "@/components/shell/topbar";
import { Button } from "@/components/ui/button";
import { ErrorNote, Skeleton } from "@/components/ui/atoms";
import { SelectBox } from "@/components/ui/fields";
import { describeError } from "@/lib/api/client";
import { useActiveIncidents } from "@/lib/api/hooks";
import { useProtocolAnalysis, useProtocolCatalog, type EngineName, type ProtocolReport } from "@/lib/api/protocols";
import { useCan } from "@/lib/auth";
import { SCENARIOS } from "@/lib/scenarios";
import { cn } from "@/lib/cn";

const SPECIALIST: Record<string, string> = {
  routing: "Routing",
  switching: "Switching and wireless",
  wireless: "Switching and wireless",
  transport: "Transport and edge",
  security: "Security",
};
const KIND: Record<string, string> = { normal: "Normal", failure: "Failure", edge: "Edge case", adversarial: "Adversarial" };
const SITES = [
  { value: "__all", label: "All sites" },
  { value: "NYC", label: "New York" },
  { value: "SIN", label: "Singapore" },
  { value: "BLR", label: "Bengaluru" },
];

function Report({ report }: { report: ProtocolReport }) {
  const byId = Object.fromEntries(report.findings.map((f) => [f.finding_id, f]));
  const chain = report.causal_chain.map((id) => byId[id]?.title).filter(Boolean);
  return (
    <section className="space-y-4" aria-live="polite">
      <div className="rounded-[10px] bg-panel px-4 py-3.5 shadow-[0_0_0_1px_var(--line)]">
        <p className="text-[15px] font-medium tracking-[-0.01em] text-ink">{report.headline}</p>
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <Counts counts={report.counts} />
          <Tag tone={report.validation.grounded ? "bg-green-soft text-green" : "bg-amber-soft text-amber"}>
            {report.validation.grounded ? `All ${report.validation.references_checked} evidence references verified` : "Some references could not be verified"}
          </Tag>
        </div>
        {chain.length > 1 ? <p className="mt-2 text-[12.5px] text-ink-3">Chain: {chain.join(" → ")}</p> : null}
        <p className="mt-2 text-[11.5px] text-ink-4">{report.data_source}</p>
      </div>
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_300px]">
        <div>
          <h2 className="mb-2 text-[13px] font-medium text-ink-2">Findings</h2>
          {report.findings.length ? (
            <FindingList findings={report.findings} />
          ) : (
            <p className="rounded-[8px] bg-sunken px-3 py-2.5 text-[12.5px] text-ink-3">Nothing wrong found in these checks.</p>
          )}
        </div>
        <aside className="space-y-4">
          <div>
            <h2 className="mb-2 text-[13px] font-medium text-ink-2">Engines</h2>
            <ul className="space-y-1">
              {report.engines.map((e) => (
                <li key={e.engine} className="flex items-center gap-2 text-[12px]">
                  <span className="w-5 font-mono text-[11px] text-ink-4">{e.feature}</span>
                  <span className="min-w-0 flex-1 truncate text-ink-2">{e.title}</span>
                  <Tag tone={(ENGINE_STATUS[e.status] ?? ENGINE_STATUS.healthy).tone}>{(ENGINE_STATUS[e.status] ?? ENGINE_STATUS.healthy).label}</Tag>
                </li>
              ))}
            </ul>
          </div>
          {report.hypotheses.length && report.counts.confirmed_fault ? (
            <div>
              <h2 className="mb-1 text-[13px] font-medium text-ink-2">Fault area (Bayesian)</h2>
              <ul className="space-y-0.5 text-[12px] text-ink-3">
                {report.hypotheses.map((h) => (
                  <li key={h.domain} className="flex justify-between">
                    <span>{h.label}</span>
                    <span className="font-mono">{h.shown}</span>
                  </li>
                ))}
              </ul>
              <p className="mt-1 text-[11.5px] text-ink-4">{report.uncertainty}</p>
            </div>
          ) : null}
          {report.next_checks.length ? (
            <div>
              <h2 className="mb-1 text-[13px] font-medium text-ink-2">Worth checking next</h2>
              <ul className="space-y-1 text-[12px] text-ink-3">
                {report.next_checks.map((c) => (
                  <li key={c.engine}>
                    <span className="text-ink-2">{c.title}</span>: {c.reason}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
          {report.notes.length ? (
            <div>
              <h2 className="mb-1 text-[13px] font-medium text-ink-2">Notes</h2>
              <ul className="list-disc space-y-1 pl-4 text-[12px] text-ink-3">
                {report.notes.slice(0, 6).map((n) => (
                  <li key={n}>{n}</li>
                ))}
              </ul>
            </div>
          ) : null}
          {report.missing.length ? (
            <p className="text-[12px] text-amber">Missing data: {report.missing.slice(0, 3).join("; ")}</p>
          ) : null}
          {report.related_incidents.length ? (
            <p className="text-[12px] text-ink-3">
              Possibly related: {report.related_incidents.map((r) => `${r.incident_id} (${r.relation})`).join("; ")}
            </p>
          ) : null}
        </aside>
      </div>
    </section>
  );
}

export function ProtocolsView() {
  const catalog = useProtocolCatalog();
  const active = useActiveIncidents();
  const can = useCan();
  const analysis = useProtocolAnalysis();
  const [source, setSource] = useState<string>("scenario:P3-BGP-ROUTE-LEAK");
  const [site, setSite] = useState<string>("__all");
  const [selected, setSelected] = useState<Set<EngineName> | null>(null);
  const engines = useMemo(() => catalog.data?.engines ?? [], [catalog.data]);
  const chosen = selected ?? new Set(engines.map((e) => e.name));
  const groups = useMemo(() => {
    const out: Record<string, typeof engines> = {};
    for (const engine of engines) (out[SPECIALIST[engine.specialist] ?? engine.specialist] ??= []).push(engine);
    return out;
  }, [engines]);
  const scenarioOptions = [
    ...(catalog.data?.scenarios ?? []).map((s) => ({ value: `scenario:${s.scenario_id}`, label: `${KIND[s.kind]} · ${s.name}` })),
    ...SCENARIOS.filter((s) => !s.id.startsWith("P3-") && !s.id.startsWith("SCN-")).map((s) => ({ value: `scenario:${s.id}`, label: `Core · ${s.name}` })),
    ...(active.data?.items ?? []).map((i) => ({ value: `incident:${i.incident_id}`, label: `Incident · ${i.incident_id} ${i.title}` })),
  ];
  const picked = catalog.data?.scenarios.find((s) => `scenario:${s.scenario_id}` === source);
  const toggle = (name: EngineName) => {
    const next = new Set(chosen);
    if (next.has(name)) next.delete(name);
    else next.add(name);
    setSelected(next);
  };
  const run = () => {
    const cut = source.indexOf(":");
    const kind = source.slice(0, cut);
    const id = source.slice(cut + 1);
    void analysis.mutateAsync({
      ...(kind === "incident" ? { incident_id: id } : { scenario_id: id }),
      engines: [...chosen],
      site_id: site === "__all" ? null : site,
    }).catch(() => undefined);
  };
  const allowed = can("run_diagnostics");

  return (
    <>
      <Topbar crumbs={[{ label: "Protocols & security" }]} />
      <div className="scroll-thin min-h-0 flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-[1200px] space-y-5 px-5 pt-6 pb-16 md:px-8">
          <div>
            <h1 className="text-[24px] font-semibold tracking-[-0.03em] text-ink">Protocol and security intelligence</h1>
            <p className="mt-1 max-w-[720px] text-[13px] text-ink-3">
              Seventeen read-only engines over synthetic protocol telemetry. Findings are labelled confirmed, suspicious, possible or not enough data;
              nothing contacts a device, scans a network or changes configuration.
            </p>
          </div>
          {catalog.isError ? <ErrorNote message={describeError(catalog.error)} onRetry={() => catalog.refetch()} /> : null}
          <div className="rounded-[10px] bg-panel px-4 py-4 shadow-[0_0_0_1px_var(--line)]">
            <div className="flex flex-wrap items-end gap-3">
              <label className="block">
                <span className="mb-1 block text-[12px] text-ink-3">Telemetry</span>
                <SelectBox ariaLabel="Telemetry dataset or incident" className="w-[380px]" value={source} onValueChange={setSource} options={scenarioOptions} />
              </label>
              <label className="block">
                <span className="mb-1 block text-[12px] text-ink-3">Scope</span>
                <SelectBox ariaLabel="Site scope" className="w-[160px]" value={site} onValueChange={setSite} options={SITES} />
              </label>
              <div className="flex-1" />
              <Button
                variant="primary"
                onClick={run}
                disabled={!allowed || chosen.size === 0 || analysis.isPending}
                aria-describedby="protocols-approval"
              >
                <ShieldCheck className="size-4" aria-hidden />
                {analysis.isPending
                  ? "Running checks…"
                  : `Run ${chosen.size === engines.length ? "all" : chosen.size} read-only check${chosen.size === 1 ? "" : "s"}`}
              </Button>
            </div>
            <p id="protocols-approval" className="mt-2 text-[11.5px] text-ink-4">
              {allowed ? "Checks run only when you press the button. They read collected synthetic telemetry and change nothing." : "Running checks needs the run_diagnostics permission."}
            </p>
            {picked ? (
              <p className="mt-2 text-[12.5px] text-ink-3">
                <Tag tone="bg-hover text-ink-2">{KIND[picked.kind]}</Tag> <span className="ml-1">{picked.description}</span>
              </p>
            ) : null}
            {catalog.isPending ? (
              <Skeleton className="mt-4 h-28" />
            ) : (
              <div className="mt-4 grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                {Object.entries(groups).map(([group, items]) => (
                  <fieldset key={group}>
                    <legend className="mb-1.5 text-[12px] font-medium text-ink-2">{group}</legend>
                    <ul className="space-y-1">
                      {items.map((engine) => (
                        <li key={engine.name}>
                          <label className="flex cursor-pointer items-start gap-2 text-[12.5px] text-ink-2" title={engine.checks}>
                            <input type="checkbox" className="mt-[3px] accent-[var(--accent)]" checked={chosen.has(engine.name)} onChange={() => toggle(engine.name)} />
                            <span>
                              <span className="font-mono text-[11px] text-ink-4">{engine.feature}.</span> {engine.title}
                            </span>
                          </label>
                        </li>
                      ))}
                    </ul>
                  </fieldset>
                ))}
              </div>
            )}
          </div>
          {analysis.isError ? <ErrorNote message={describeError(analysis.error)} onRetry={run} /> : null}
          {analysis.isPending ? <Skeleton className="h-40" /> : null}
          {analysis.data && !analysis.isPending ? (
            <div className={cn(analysis.isPending && "opacity-60")}>
              <Report report={analysis.data} />
            </div>
          ) : null}
        </div>
      </div>
    </>
  );
}
