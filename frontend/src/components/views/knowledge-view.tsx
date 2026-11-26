"use client";

import { Search } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Topbar } from "@/components/shell/topbar";
import { ErrorNote, Pill, Skeleton } from "@/components/ui/atoms";
import { Segmented } from "@/components/ui/controls";
import { CopyButton } from "@/components/ui/copy-button";
import { ALL, SelectBox, controlClass } from "@/components/ui/fields";
import { describeError } from "@/lib/api/client";
import { useKnowledgeSearch, usePlaybook, usePlaybooks, useProcedures, useRunbooks, useTopology } from "@/lib/api/hooks";
import type { CommandSpec, DiagnosticProcedure, DiagnosticStep, FaultDomain, Playbook, Runbook } from "@/lib/api/types";
import { cn } from "@/lib/cn";
import { FAULT_DOMAINS, FAULT_LABEL, humanize } from "@/lib/labels";

type Kind = "playbooks" | "runbooks" | "procedures";
type Selected = { kind: Kind; id: string } | null;

function kindOf(id: string): Kind {
  if (id.startsWith("PB-")) return "playbooks";
  if (id.startsWith("RB-")) return "runbooks";
  return "procedures";
}

export function KnowledgeView() {
  const [kind, setKind] = useState<Kind>("playbooks");
  const [query, setQuery] = useState("");
  const [domain, setDomain] = useState<FaultDomain | typeof ALL>(ALL);
  const [site, setSite] = useState<string>(ALL);
  const [selected, setSelected] = useState<Selected>(null);
  const topology = useTopology();

  const playbooks = usePlaybooks({ fault_domain: domain === ALL ? undefined : domain });
  const runbooks = useRunbooks(site === ALL ? undefined : site);
  const procedures = useProcedures(domain === ALL ? undefined : domain);
  const search = useKnowledgeSearch({
    q: query.trim(),
    fault_domain: domain === ALL ? undefined : domain,
    site_id: site === ALL ? undefined : site,
  });
  const searching = query.trim().length > 0;

  useEffect(() => {
    const record = new URLSearchParams(window.location.search).get("record");
    if (record) {
      // Deep link from a diagnosis or the command palette: /knowledge?record=PB-PACKET-LOSS
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setSelected({ kind: kindOf(record), id: record });
      setKind(kindOf(record));
    }
  }, []);

  const list = useMemo(() => {
    if (kind === "playbooks") return (playbooks.data?.items ?? []).map((r) => ({ id: r.record_id, title: r.title, meta: r.category }));
    if (kind === "runbooks") return (runbooks.data?.items ?? []).map((r) => ({ id: r.record_id, title: r.title, meta: (r.applicability?.site_ids ?? []).join(", ") || "All sites" }));
    return (procedures.data?.items ?? []).map((r) => ({ id: r.record_id, title: r.title, meta: (r.fault_domains ?? []).map((d) => FAULT_LABEL[d]).join(", ") }));
  }, [kind, playbooks.data, runbooks.data, procedures.data]);
  const listQuery = kind === "playbooks" ? playbooks : kind === "runbooks" ? runbooks : procedures;

  return (
    <>
      <Topbar crumbs={[{ label: "Knowledge base" }]} />
      <div className="flex min-h-0 flex-1 flex-col lg:flex-row">
        <div className="scroll-thin flex min-h-0 w-full flex-col overflow-y-auto shadow-[inset_-1px_0_0_var(--line)] lg:w-[400px] lg:shrink-0">
          <div className="space-y-3 px-5 pt-5 pb-4">
            <label className="relative block">
              <span className="sr-only">Search playbooks, runbooks and procedures</span>
              <Search className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-ink-3" aria-hidden />
              <input
                type="search"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                maxLength={500}
                placeholder="Symptom, error code or device"
                className={cn(controlClass, "h-10 pl-9")}
              />
            </label>
            <div className="grid grid-cols-2 gap-2">
              <SelectBox
                size="sm"
                ariaLabel="Fault domain"
                value={domain}
                onValueChange={setDomain}
                options={[{ value: ALL, label: "Any fault domain" }, ...FAULT_DOMAINS.map((d) => ({ value: d, label: FAULT_LABEL[d] }))]}
              />
              <SelectBox
                size="sm"
                ariaLabel="Site"
                value={site}
                onValueChange={setSite}
                options={[{ value: ALL, label: "Any site" }, ...(topology.data?.sites ?? []).map((s) => ({ value: s.site_id, label: s.name }))]}
              />
            </div>
            {!searching ? (
              <Segmented
                ariaLabel="Record type"
                size="sm"
                value={kind}
                onValueChange={setKind}
                options={[
                  { value: "playbooks", label: "Playbooks" },
                  { value: "runbooks", label: "Runbooks" },
                  { value: "procedures", label: "Procedures" },
                ]}
              />
            ) : null}
          </div>

          {searching ? (
            <div className="px-3 pb-6">
              {search.isPending ? (
                <Skeleton className="mx-2 h-24" />
              ) : search.isError ? (
                <div className="px-2">
                  <ErrorNote message={describeError(search.error)} />
                </div>
              ) : search.data?.no_match ? (
                <p className="px-2 text-[12.5px] text-ink-3">{search.data.message}</p>
              ) : (
                <ul className="space-y-0.5">
                  {(search.data?.matches ?? []).map((match) => (
                    <li key={match.record_id}>
                      <button
                        type="button"
                        onClick={() => setSelected({ kind: kindOf(match.record_id), id: match.record_id })}
                        className={cn("w-full rounded-[8px] px-3 py-2.5 text-left hover:bg-hover", selected?.id === match.record_id && "bg-selected")}
                      >
                        <span className="flex items-center gap-2">
                          <span className="truncate text-[13.5px] font-medium text-ink">{match.title}</span>
                          <Pill className="ml-auto">{match.match_type}</Pill>
                        </span>
                        <span className="mt-1 block text-[12px] leading-[1.45] text-ink-3">{match.reasons.slice(0, 2).join(" · ")}</span>
                        <span className="mt-1 block font-mono text-[11px] text-ink-4">
                          {match.record_id} · {match.record_type} · {match.points} pts
                        </span>
                      </button>
                    </li>
                  ))}
                </ul>
              )}
              {search.data?.security_flags.length ? <p className="mt-2 px-2 text-[12px] text-amber">Search flagged: {search.data.security_flags.join(", ")}</p> : null}
            </div>
          ) : (
            <div className="px-3 pb-6">
              {listQuery.isPending ? (
                <Skeleton className="mx-2 h-40" />
              ) : listQuery.isError ? (
                <div className="px-2">
                  <ErrorNote message={describeError(listQuery.error)} onRetry={() => listQuery.refetch()} />
                </div>
              ) : list.length === 0 ? (
                <p className="px-2 text-[12.5px] text-ink-3">Nothing matches these filters.</p>
              ) : (
                <ul className="space-y-0.5">
                  {list.map((item) => (
                    <li key={item.id}>
                      <button
                        type="button"
                        onClick={() => setSelected({ kind, id: item.id })}
                        className={cn("w-full rounded-[8px] px-3 py-2.5 text-left hover:bg-hover", selected?.id === item.id && "bg-selected")}
                      >
                        <span className="block truncate text-[13.5px] font-medium text-ink">{item.title}</span>
                        <span className="mt-0.5 block truncate text-[12px] text-ink-3">
                          <span className="font-mono text-[11px]">{item.id}</span> · {humanize(item.meta || "General")}
                        </span>
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </div>

        <div className="scroll-thin min-h-0 min-w-0 flex-1 overflow-y-auto">
          {selected ? (
            <RecordDetail selected={selected} runbooks={runbooks.data?.items ?? []} procedures={procedures.data?.items ?? []} />
          ) : (
            <div className="mx-auto max-w-[560px] px-6 pt-16 text-center">
              <h1 className="text-[20px] font-semibold tracking-[-0.025em] text-ink">Guidance the diagnosis draws on</h1>
              <p className="mt-2 text-[13.5px] leading-[1.5] text-ink-3">
                Search by symptom or error code, or pick a record. Steps and commands are guidance, never run automatically.
              </p>
            </div>
          )}
        </div>
      </div>
    </>
  );
}

function RecordDetail({ selected, runbooks, procedures }: { selected: NonNullable<Selected>; runbooks: Runbook[]; procedures: DiagnosticProcedure[] }) {
  const playbook = usePlaybook(selected.kind === "playbooks" ? selected.id : null);
  const allRunbooks = useRunbooks();
  const allProcedures = useProcedures();
  if (selected.kind === "playbooks") {
    if (playbook.isPending) return <DetailSkeleton />;
    if (playbook.isError) return <div className="p-6"><ErrorNote message={describeError(playbook.error)} /></div>;
    return <PlaybookDetail record={playbook.data} />;
  }
  if (selected.kind === "runbooks") {
    const record = [...runbooks, ...(allRunbooks.data?.items ?? [])].find((r) => r.record_id === selected.id);
    return record ? <RunbookDetail record={record} /> : <DetailSkeleton />;
  }
  const record = [...procedures, ...(allProcedures.data?.items ?? [])].find((r) => r.record_id === selected.id);
  return record ? <ProcedureDetail record={record} /> : <DetailSkeleton />;
}

function DetailSkeleton() {
  return (
    <div className="space-y-3 p-8">
      <Skeleton className="h-7 w-80" />
      <Skeleton className="h-4 w-full max-w-[520px]" />
      <Skeleton className="h-40" />
    </div>
  );
}

function Header({ title, id, version, domains, extra }: { title: string; id: string; version: string; domains?: FaultDomain[]; extra?: string }) {
  return (
    <header>
      <div className="flex flex-wrap items-center gap-2 font-mono text-[11.5px] text-ink-3">
        <span>{id}</span>
        <span>v{version}</span>
        {extra ? <span>{extra}</span> : null}
      </div>
      <h1 className="mt-2 text-[24px] leading-[1.15] font-semibold tracking-[-0.03em] text-balance text-ink">{title}</h1>
      {domains?.length ? (
        <div className="mt-2.5 flex flex-wrap gap-1.5">
          {domains.map((d) => (
            <Pill key={d} tone="accent">
              {FAULT_LABEL[d]}
            </Pill>
          ))}
        </div>
      ) : null}
    </header>
  );
}

function List({ title, items }: { title: string; items: string[] }) {
  if (!items.length) return null;
  return (
    <section>
      <h2 className="text-[13px] font-medium text-ink-2">{title}</h2>
      <ul className="mt-1.5 list-disc space-y-1 pl-5 text-[13px] leading-[1.5] text-ink-3 marker:text-ink-4">
        {items.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>
    </section>
  );
}

function Commands({ commands }: { commands?: CommandSpec[] }) {
  if (!commands?.length) return null;
  return (
    <ul className="mt-2 space-y-1.5">
      {commands.map((command) => (
        <li key={`${command.platform}-${command.text}`} className="flex items-center gap-2 rounded-[7px] bg-sunken py-1 pr-1 pl-3 shadow-[0_0_0_1px_var(--line-soft)]">
          <code className="min-w-0 flex-1 truncate font-mono text-[12px] text-ink">{command.text}</code>
          <span className="shrink-0 text-[11px] text-ink-4">{command.platform}</span>
          <CopyButton text={command.text} />
        </li>
      ))}
    </ul>
  );
}

function Steps({ title, steps }: { title: string; steps: DiagnosticStep[] }) {
  if (!steps.length) return null;
  return (
    <section>
      <h2 className="text-[13px] font-medium text-ink-2">{title}</h2>
      <ol className="mt-2 space-y-2.5">
        {[...steps]
          .sort((a, b) => a.order - b.order)
          .map((step) => (
            <li key={step.order} className="card px-4 py-3">
              <div className="flex gap-3">
                <span className="font-mono text-[11.5px] leading-[20px] text-ink-4">{step.order}</span>
                <div className="min-w-0 flex-1">
                  <p className="text-[13.5px] leading-[1.5] text-ink">{step.action}</p>
                  {step.tool ? <p className="mt-0.5 font-mono text-[11.5px] text-accent">{step.tool.tool}</p> : null}
                  <Commands commands={step.commands} />
                  <p className="mt-2 text-[12.5px] text-ink-3">Expect: {step.expected_observation}</p>
                </div>
              </div>
            </li>
          ))}
      </ol>
    </section>
  );
}

function Escalations({ items }: { items: { condition: string; team: string; priority: string }[] }) {
  if (!items.length) return null;
  return (
    <section>
      <h2 className="text-[13px] font-medium text-ink-2">When to escalate</h2>
      <ul className="mt-1.5 space-y-1.5 text-[13px]">
        {items.map((item) => (
          <li key={item.condition} className="text-ink-3">
            {item.condition} <span className="text-ink-2">→ {item.team}</span> <span className="font-mono text-[11.5px]">{item.priority.toUpperCase()}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}

function PlaybookDetail({ record }: { record: Playbook }) {
  return (
    <article className="mx-auto max-w-[760px] space-y-5 px-6 py-7 md:px-8">
      <Header title={record.title} id={record.record_id} version={record.version} domains={record.fault_domains} extra={humanize(record.category)} />
      <p className="text-[14px] leading-[1.55] text-ink-2">{record.description}</p>
      <List title="Symptoms" items={record.symptoms} />
      <List title="Possible causes" items={record.possible_causes} />
      <List title="Evidence it needs" items={record.required_evidence.map((r) => `${r.description} (${r.tool.tool})`)} />
      <Steps title="Steps" steps={record.steps} />
      <List title="Decisions" items={record.decisions.map((d) => `If ${d.condition}: ${d.conclusion}`)} />
      <Escalations items={record.escalation} />
    </article>
  );
}

function RunbookDetail({ record }: { record: Runbook }) {
  return (
    <article className="mx-auto max-w-[760px] space-y-5 px-6 py-7 md:px-8">
      <Header title={record.title} id={record.record_id} version={record.version} domains={record.fault_domains} extra={(record.applicability?.site_ids ?? []).join(", ")} />
      <p className="text-[14px] leading-[1.55] text-ink-2">{record.context}</p>
      <List title="Before you start" items={record.preconditions} />
      <Steps title="Procedure" steps={record.procedures} />
      <List title="Verify" items={record.verification} />
      <Escalations items={record.escalation} />
    </article>
  );
}

function ProcedureDetail({ record }: { record: DiagnosticProcedure }) {
  return (
    <article className="mx-auto max-w-[760px] space-y-5 px-6 py-7 md:px-8">
      <Header title={record.title} id={record.record_id} version={record.version} domains={record.fault_domains} />
      <List title="Symptoms" items={record.symptoms} />
      <List title="Tools" items={record.tools.map((t) => `${t.tool}: ${t.purpose}`)} />
      {record.commands?.length ? (
        <section>
          <h2 className="text-[13px] font-medium text-ink-2">Commands</h2>
          <Commands commands={record.commands} />
        </section>
      ) : null}
      <List title="Expected output" items={record.expected_outputs} />
      <List title="Decisions" items={record.decisions.map((d) => `If ${d.condition}: ${d.conclusion}`)} />
      <List title="Escalate when" items={record.escalation_conditions} />
    </article>
  );
}
