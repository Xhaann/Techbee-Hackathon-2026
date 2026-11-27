"use client";

import { ArrowRight } from "lucide-react";
import { useState } from "react";
import { ErrorNote, Pill, Skeleton } from "@/components/ui/atoms";
import { Button } from "@/components/ui/button";
import { SelectBox, TextField } from "@/components/ui/fields";
import { describeError } from "@/lib/api/client";
import { type Journey, useJourney } from "@/lib/api/observability";
import { cn } from "@/lib/cn";
import type { Tone } from "@/lib/labels";
import { Panel, SourceNote } from "./shared";

const PRESETS = [
  { label: "Singapore user → ERP (HTTPS)", source: "10.20.10.100", destination: "DC1-SRV-APP-01", protocol: "tcp", port: "443" },
  { label: "Singapore switch → RADIUS", source: "SIN-SW-01", destination: "DC1-SRV-AUTH-01", protocol: "udp", port: "1812" },
  { label: "Bengaluru user → DNS", source: "10.30.10.100", destination: "DC1-SRV-DNS-01", protocol: "udp", port: "53" },
  { label: "New York user → internet", source: "10.10.10.100", destination: "203.0.113.10", protocol: "tcp", port: "443" },
];
const VERDICT_TONE: Record<Journey["verdict"], Tone> = {
  delivered: "green",
  leaves_network: "green",
  dropped_by_policy: "red",
  link_down: "red",
  no_route: "red",
  indeterminate: "amber",
};

export function JourneyPanel({ scenario }: { scenario: string }) {
  const [form, setForm] = useState(PRESETS[0]);
  const [request, setRequest] = useState<{ source: string; destination: string; protocol: string; port?: number } | null>({
    source: PRESETS[0].source,
    destination: PRESETS[0].destination,
    protocol: PRESETS[0].protocol,
    port: Number(PRESETS[0].port),
  });
  const journey = useJourney(scenario, request);
  const submit = () =>
    setRequest({ source: form.source.trim(), destination: form.destination.trim(), protocol: form.protocol, port: form.port ? Number(form.port) : undefined });

  return (
    <div className="space-y-3">
      <Panel title="Trace a packet" aside="Read-only: evaluated against the scenario's routing tables, firewall policy and link state">
        <form
          className="grid gap-3 md:grid-cols-[1fr_1fr_120px_110px_auto] md:items-end"
          onSubmit={(event) => {
            event.preventDefault();
            submit();
          }}
        >
          <TextField label="Source" mono value={form.source} onChange={(source) => setForm({ ...form, source })} placeholder="SIN-SW-01 or 10.20.10.100" maxLength={64} />
          <TextField label="Destination" mono value={form.destination} onChange={(destination) => setForm({ ...form, destination })} placeholder="DC1-SRV-APP-01" maxLength={64} />
          <div>
            <span className="mb-1.5 block text-[12.5px] font-medium text-ink-2">Protocol</span>
            <SelectBox
              ariaLabel="Protocol"
              value={form.protocol}
              onValueChange={(protocol) => setForm({ ...form, protocol })}
              options={[
                { value: "tcp", label: "TCP" },
                { value: "udp", label: "UDP" },
                { value: "icmp", label: "ICMP" },
              ]}
            />
          </div>
          <TextField label="Port" mono value={form.port} onChange={(port) => setForm({ ...form, port: port.replace(/\D/g, "").slice(0, 5) })} placeholder="443" />
          <Button type="submit" variant="primary" disabled={!form.source || !form.destination}>
            Trace
          </Button>
        </form>
        <div className="mt-3 flex flex-wrap gap-1.5">
          {PRESETS.map((preset) => (
            <button
              key={preset.label}
              type="button"
              onClick={() => {
                setForm(preset);
                setRequest({ source: preset.source, destination: preset.destination, protocol: preset.protocol, port: Number(preset.port) });
              }}
              className="rounded-[6px] bg-hover px-2 py-1 text-[12px] text-ink-2 hover:text-ink"
            >
              {preset.label}
            </button>
          ))}
        </div>
      </Panel>

      {journey.isFetching && !journey.data ? <Skeleton className="h-48" /> : null}
      {journey.isError ? <ErrorNote message={describeError(journey.error)} /> : null}
      {journey.data ? <JourneyResult journey={journey.data} /> : null}
    </div>
  );
}

function JourneyResult({ journey }: { journey: Journey }) {
  const tone = VERDICT_TONE[journey.verdict];
  return (
    <Panel
      title={
        <span className="inline-flex items-center gap-2">
          <Pill tone={tone} dot>
            {journey.verdict.replaceAll("_", " ")}
          </Pill>
          <span className="text-ink-2">{journey.verdict_text}</span>
        </span>
      }
      aside={`${journey.hops.length} hops · ${journey.total_latency_ms} ms one way · path MTU ${journey.path_mtu ?? "—"}`}
    >
      <ol className="scroll-thin flex items-stretch gap-2 overflow-x-auto pb-2" aria-label="Hops">
        {journey.hops.map((hop, index) => {
          const stop = hop.index === journey.verdict_hop && tone === "red";
          return (
            <li key={hop.index} className="flex shrink-0 items-center gap-2">
              <div className={cn("w-[196px] rounded-[8px] bg-panel px-3 py-2.5 shadow-[0_0_0_1px_var(--line-soft)]", stop && "shadow-[0_0_0_1px_var(--red-line)]")}>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[11px] text-ink-4">{hop.index}</span>
                  <span className="truncate font-mono text-[12px] text-ink">{hop.device_id}</span>
                </div>
                <p className="mt-0.5 text-[11.5px] text-ink-3">
                  {hop.device_type} · {hop.site_id}
                </p>
                {hop.route ? (
                  <p className="mt-1.5 truncate font-mono text-[11px] text-ink-2" title={`next hop ${hop.route.next_hop ?? "connected"}`}>
                    {hop.route.prefix} via {hop.route.protocol}
                  </p>
                ) : null}
                {hop.policy ? (
                  <p className={cn("mt-1 truncate text-[11.5px]", hop.policy.action === "deny" ? "text-red" : "text-green")}>
                    {hop.policy.action} · {hop.policy.name}
                  </p>
                ) : null}
                {hop.egress && !stop ? (
                  <p className={cn("mt-1 text-[11px]", hop.egress.status === "down" ? "text-red" : "text-ink-3")}>
                    {hop.egress.link_id.replace("LNK-", "")} {hop.egress.status} · {hop.egress.latency_ms} ms{hop.egress.measured ? "" : " (documented)"} · MTU {hop.egress.mtu}
                  </p>
                ) : null}
                <p className="mt-1 font-mono text-[10.5px] text-ink-4">Σ {hop.cumulative_latency_ms} ms</p>
              </div>
              {index < journey.hops.length - 1 ? <ArrowRight className="size-3.5 shrink-0 text-ink-4" aria-hidden /> : null}
            </li>
          );
        })}
      </ol>
      <div className="mt-2 space-y-1 text-[12.5px] text-ink-2">
        <p>
          {journey.request.protocol.toUpperCase()}/{journey.request.port ?? "any"} from <span className="font-mono">{journey.source.address}</span> to{" "}
          <span className="font-mono">{journey.destination.address}</span>. Matching flows seen in the window: {journey.observed_flows.matching} (
          {journey.observed_flows.forwarded} forwarded, {journey.observed_flows.dropped} dropped).
        </p>
        {journey.mtu_note ? <p className="text-amber">{journey.mtu_note}</p> : null}
        {journey.notes.map((note) => (
          <p key={note} className="text-ink-3">
            {note}
          </p>
        ))}
      </div>
      <div className="mt-2">
        <SourceNote>{journey.limitations.join(". ")}.</SourceNote>
      </div>
    </Panel>
  );
}
