"use client";

import { SquareTerminal } from "lucide-react";
import Link from "next/link";
import { useMemo, useState } from "react";
import { Topbar } from "@/components/shell/topbar";
import { ErrorNote, Skeleton } from "@/components/ui/atoms";
import { CopyButton } from "@/components/ui/copy-button";
import { SelectBox } from "@/components/ui/fields";
import { describeError } from "@/lib/api/client";
import { useIncident, useIncidents, useProcedures } from "@/lib/api/hooks";
import { activeRecord, openEscalations } from "@/components/workspace/model";

type Line = { command: string; purpose: string; expect?: string; source: string };

/** The read-only commands an engineer runs by hand, grouped by device. This page has no device access. */
export function CliView() {
  const incidents = useIncidents({ limit: 100 });
  const withDiagnosis = useMemo(
    () => [...(incidents.data?.items ?? [])].filter((i) => i.fault_domain).sort((a, b) => b.updated_at.localeCompare(a.updated_at)),
    [incidents.data],
  );
  const [chosen, setChosen] = useState<string | null>(null);
  const incidentId = chosen ?? withDiagnosis[0]?.incident_id ?? null;
  const incident = useIncident(incidentId);
  const record = incident.data ? activeRecord(incident.data) : undefined;
  const procedures = useProcedures(record?.probable_fault_domain);

  const byDevice = useMemo(() => {
    const groups = new Map<string, Line[]>();
    const add = (device: string, line: Line) => {
      const list = groups.get(device) ?? [];
      if (!list.some((l) => l.command === line.command)) list.push(line);
      groups.set(device, list);
    };
    for (const check of record?.diagnosis.next_checks ?? []) {
      add(check.device_id, { command: check.command, purpose: check.purpose, expect: check.expected_observation, source: "Diagnosis" });
    }
    for (const escalation of incident.data ? openEscalations(incident.data) : []) {
      for (const check of escalation.outstanding_checks ?? []) add(check.device_id, { command: check.command, purpose: check.purpose, source: escalation.escalation_id });
    }
    const faultDevices = record?.diagnosis.fault.device_ids ?? [];
    if (faultDevices.length) {
      for (const procedure of procedures.data?.items ?? []) {
        for (const command of procedure.commands ?? []) {
          add(faultDevices[0], { command: command.text, purpose: command.purpose, source: `${procedure.record_id} (${command.platform})` });
        }
      }
    }
    return [...groups.entries()];
  }, [record, incident.data, procedures.data]);

  return (
    <>
      <Topbar crumbs={[{ label: "Remote CLI" }]} />
      <div className="scroll-thin min-h-0 flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-[900px] space-y-5 px-5 pt-6 pb-16 md:px-8">
          <div className="flex flex-wrap items-end justify-between gap-3">
            <div>
              <h1 className="text-[24px] font-semibold tracking-[-0.03em] text-ink">Commands to run on the devices</h1>
              <p className="mt-1 max-w-[560px] text-[13px] leading-[1.5] text-ink-3">
                Read-only checks from the diagnosis, open escalations and matching procedures. This workspace never connects to a device; copy them into
                your own session.
              </p>
            </div>
            {withDiagnosis.length ? (
              <SelectBox
                ariaLabel="Incident"
                className="w-[300px]"
                value={incidentId}
                onValueChange={setChosen}
                options={withDiagnosis.map((i) => ({ value: i.incident_id, label: `${i.incident_id} · ${i.title}` }))}
              />
            ) : null}
          </div>

          {incidents.isPending || (incidentId && incident.isPending) ? (
            <Skeleton className="h-48" />
          ) : incidents.isError ? (
            <ErrorNote message={describeError(incidents.error)} onRetry={() => incidents.refetch()} />
          ) : !incidentId ? (
            <p className="card px-5 py-8 text-center text-[13.5px] text-ink-3">
              No incident has a diagnosis yet. <Link href="/diagnose" className="text-accent hover:underline">Open and diagnose one</Link> to get its checks.
            </p>
          ) : (
            <div className="space-y-4">
              {byDevice.map(([device, lines]) => {
                const script = lines.map((l) => l.command).join("\n");
                return (
                  <section key={device} aria-label={device} className="overflow-hidden rounded-[10px] bg-sunken shadow-[var(--shadow-card)]">
                    <header className="flex items-center gap-2.5 px-4 py-2.5 shadow-[inset_0_-1px_0_var(--line-soft)]">
                      <SquareTerminal className="size-4 text-ink-3" aria-hidden />
                      <span className="font-mono text-[12.5px] text-ink">{device.toLowerCase()}</span>
                      <span className="text-[12px] text-ink-4">
                        {lines.length} {lines.length === 1 ? "command" : "commands"}
                      </span>
                      <CopyButton text={script} label={`Copy all commands for ${device}`} className="ml-auto" />
                    </header>
                    <ol className="divide-y divide-line-soft">
                      {lines.map((line) => (
                        <li key={line.command} className="flex gap-3 px-4 py-2.5">
                          <div className="min-w-0 flex-1">
                            <code className="block font-mono text-[12.5px] break-all text-ink">
                              <span className="text-ink-4">{device.toLowerCase()}# </span>
                              {line.command}
                            </code>
                            <p className="mt-1 text-[12px] leading-[1.45] text-ink-3">
                              {line.purpose}
                              {line.expect ? ` · expect ${line.expect.charAt(0).toLowerCase()}${line.expect.slice(1)}` : ""}
                            </p>
                          </div>
                          <span className="shrink-0 font-mono text-[11px] text-ink-4">{line.source}</span>
                          <CopyButton text={line.command} />
                        </li>
                      ))}
                    </ol>
                  </section>
                );
              })}
              {!byDevice.length ? <p className="text-[13px] text-ink-3">This diagnosis has no device checks.</p> : null}
            </div>
          )}
        </div>
      </div>
    </>
  );
}
