"use client";

import { Popover, PopoverContent, PopoverTitle, PopoverTrigger } from "@ui-sdk/react/popover";
import { Bell } from "lucide-react";
import Link from "next/link";
import { useMemo, useState } from "react";
import { Dot } from "@/components/ui/atoms";
import { useReportIncidents } from "@/lib/api/hooks";
import type { IncidentReportRow } from "@/lib/api/types";
import { useCan } from "@/lib/auth";
import { cn } from "@/lib/cn";
import type { Tone } from "@/lib/labels";
import { ago } from "@/lib/time";

type Item = { key: string; incidentId: string; title: string; detail: string; tone: Tone; at: string };

const SEEN_KEY = "noc.seen-notifications";

function readSeen(): Set<string> {
  try {
    return new Set(JSON.parse(window.localStorage.getItem(SEEN_KEY) ?? "[]"));
  } catch {
    return new Set();
  }
}

/** Work that needs a person, derived from the incident report rows. */
function needsAttention(row: IncidentReportRow, canVerify: boolean, canConfirm: boolean): Item | null {
  const base = { incidentId: row.incident_id, title: row.title, at: row.created_at };
  if (row.resolution_verification === "pending" && canVerify) {
    return { ...base, key: `${row.incident_id}:verify`, detail: "Resolution is waiting for verification", tone: "amber" };
  }
  if (row.status === "new") return { ...base, key: `${row.incident_id}:new`, detail: "Waiting to be acknowledged", tone: "amber" };
  if (row.status === "escalated") {
    return { ...base, key: `${row.incident_id}:esc:${row.escalations}`, detail: "Escalation recommended; nothing has been sent", tone: "amber" };
  }
  if (row.status === "diagnosed" && !row.confirmed_fault_domain && canConfirm) {
    return { ...base, key: `${row.incident_id}:diag:${row.diagnoses}`, detail: "Diagnosis is ready for your review", tone: "accent" };
  }
  return null;
}

export function Notifications() {
  const rows = useReportIncidents();
  const can = useCan();
  const [seen, setSeen] = useState<Set<string>>(() => (typeof window === "undefined" ? new Set() : readSeen()));

  const items = useMemo(() => {
    const list = (rows.data?.items ?? [])
      .map((row) => needsAttention(row, can("verify_resolutions"), can("confirm_classification")))
      .filter((item): item is Item => item !== null);
    return list.sort((a, b) => b.at.localeCompare(a.at)).slice(0, 8);
  }, [rows.data, can]);

  const unseen = items.filter((item) => !seen.has(item.key)).length;

  function markSeen() {
    const next = new Set([...seen, ...items.map((item) => item.key)]);
    window.localStorage.setItem(SEEN_KEY, JSON.stringify([...next].slice(-200)));
    setSeen(next);
  }

  return (
    <Popover onOpenChange={(open) => !open && markSeen()}>
      <PopoverTrigger className="group flex h-[33px] w-full items-center gap-2.5 rounded-[7px] px-2.5 text-left text-[14px] text-ink-soft hover:bg-hover hover:text-ink data-open:bg-hover">
        <Bell className="size-[16px] shrink-0 text-ink-3 group-hover:text-ink-2" aria-hidden />
        <span className="flex-1">Notifications</span>
        {unseen > 0 ? <span className="text-[12px] tabular-nums text-ink-3">{unseen}</span> : null}
      </PopoverTrigger>
      <PopoverContent side="right" align="end" sideOffset={10} className="popup w-[330px] p-0">
        <PopoverTitle className="px-3.5 pt-3 pb-2 text-[13.5px] font-semibold text-ink">Needs your attention</PopoverTitle>
        {items.length === 0 ? (
          <p className="px-3.5 pb-3.5 text-[12.5px] leading-[1.45] text-ink-3">
            Nothing is waiting on you. New incidents, pending verifications and unsent escalations show up here.
          </p>
        ) : (
          <ul className="max-h-[360px] overflow-y-auto px-1.5 pb-1.5 scroll-thin">
            {items.map((item) => (
              <li key={item.key}>
                <Link href={`/diagnose/${item.incidentId}`} className="flex gap-2.5 rounded-[7px] px-2 py-2 hover:bg-hover">
                  <Dot tone={item.tone} className={cn("mt-[7px]", seen.has(item.key) && "opacity-40")} />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-[13px] font-medium text-ink">{item.title}</span>
                    <span className="mt-0.5 block text-[12px] text-ink-3">
                      {item.detail} · <span className="font-mono text-[11px]">{item.incidentId}</span>
                    </span>
                    <span className="mt-0.5 block text-[11.5px] text-ink-4">Opened {ago(item.at)}</span>
                  </span>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </PopoverContent>
    </Popover>
  );
}
