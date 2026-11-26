"use client";

import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandGroupLabel,
  CommandInput,
  CommandItem,
  CommandItemIcon,
  CommandList,
} from "@ui-sdk/react/command";
import { Dialog, DialogBackdrop, DialogContent, DialogTitle } from "@ui-sdk/react/dialog";
import { useShortcut } from "@ui-sdk/react/shortcuts";
import {
  Activity,
  BookOpen,
  ChartLine,
  CircleHelp,
  FileText,
  Plus,
  Router,
  Search,
  Settings,
  SquareTerminal,
  TriangleAlert,
} from "lucide-react";
import { useRouter } from "next/navigation";
import type { ComponentType } from "react";
import { useIncidents, usePlaybooks, useTopology } from "@/lib/api/hooks";
import { STATUS_LABEL } from "@/lib/labels";

type Entry = { value: string; label: string; hint?: string; href: string; icon: ComponentType<{ className?: string }>; keywords?: string[] };

const PAGES: Entry[] = [
  { value: "page:new", label: "Open a new incident", href: "/diagnose", icon: Plus, keywords: ["create", "report", "new"] },
  { value: "page:diagnose", label: "Diagnose", href: "/diagnose", icon: Activity },
  { value: "page:incidents", label: "Incidents", href: "/incidents", icon: TriangleAlert },
  { value: "page:insights", label: "Network insights", href: "/insights", icon: ChartLine, keywords: ["topology", "devices", "health"] },
  { value: "page:knowledge", label: "Knowledge base", href: "/knowledge", icon: BookOpen, keywords: ["playbook", "runbook"] },
  { value: "page:reports", label: "Reports", href: "/reports", icon: FileText },
  { value: "page:cli", label: "Remote CLI", href: "/cli", icon: SquareTerminal, keywords: ["commands", "checks"] },
  { value: "page:settings", label: "Settings", href: "/settings", icon: Settings, keywords: ["theme", "sign out"] },
  { value: "page:help", label: "Help & support", href: "/help", icon: CircleHelp },
];

export function CommandPalette({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const router = useRouter();
  const incidents = useIncidents({ limit: 100 });
  const topology = useTopology();
  const playbooks = usePlaybooks({});

  useShortcut("mod+k", () => onOpenChange(!open), { description: "Search workspace" });

  const incidentEntries: Entry[] = (incidents.data?.items ?? []).map((incident) => ({
    value: `incident:${incident.incident_id}`,
    label: incident.title,
    hint: `${incident.incident_id} · ${STATUS_LABEL[incident.status]}`,
    href: `/diagnose/${incident.incident_id}`,
    icon: TriangleAlert,
    keywords: [incident.incident_id, ...incident.site_ids],
  }));
  const deviceEntries: Entry[] = (topology.data?.devices ?? []).map((device) => ({
    value: `device:${device.device_id}`,
    label: device.device_id,
    hint: `${device.vendor} ${device.model} · ${device.site_id}`,
    href: `/insights?device=${device.device_id}`,
    icon: Router,
    keywords: [device.hostname, device.management_ip, device.role],
  }));
  const playbookEntries: Entry[] = (playbooks.data?.items ?? []).map((playbook) => ({
    value: `playbook:${playbook.record_id}`,
    label: playbook.title,
    hint: playbook.record_id,
    href: `/knowledge?record=${playbook.record_id}`,
    icon: BookOpen,
    keywords: [playbook.record_id, ...(playbook.tags ?? [])],
  }));

  const all = [...PAGES, ...incidentEntries, ...deviceEntries, ...playbookEntries];

  return (
    <Dialog open={open} onOpenChange={(next) => onOpenChange(next)}>
      <DialogBackdrop className="fixed inset-0 bg-[var(--scrim)] transition-opacity duration-150 data-starting-style:opacity-0 data-ending-style:opacity-0" />
      <DialogContent className="fixed inset-x-0 top-[12vh] mx-auto w-[min(600px,calc(100vw-24px))] overflow-hidden rounded-[12px] bg-raised text-ink shadow-[var(--shadow-pop)] transition-[opacity,scale] duration-200 ease-(--ease-spring) data-starting-style:scale-[0.98] data-starting-style:opacity-0 data-ending-style:opacity-0">
        <DialogTitle className="sr-only">Search workspace</DialogTitle>
        <Command
          filter="fuzzy"
          onAction={(value) => {
            const entry = all.find((item) => item.value === value);
            if (entry) router.push(entry.href);
            onOpenChange(false);
          }}
        >
          <div className="flex items-center gap-2.5 px-4 shadow-[inset_0_-1px_0_var(--line)]">
            <Search className="size-4 shrink-0 text-ink-3" aria-hidden />
            <CommandInput
              aria-label="Search workspace"
              placeholder="Search incidents, devices, playbooks and pages"
              className="h-12 flex-1 bg-transparent text-[14.5px] text-ink outline-none placeholder:text-ink-4"
            />
          </div>
          <CommandEmpty className="px-4 py-8 text-center text-[13px] text-ink-3">No incident, device, playbook or page matches.</CommandEmpty>
          <CommandList className="max-h-[min(420px,60vh)] overflow-y-auto p-1.5 scroll-thin">
            <Group label="Go to" entries={PAGES} />
            <Group label="Incidents" entries={incidentEntries} />
            <Group label="Devices" entries={deviceEntries} />
            <Group label="Playbooks" entries={playbookEntries} />
          </CommandList>
        </Command>
      </DialogContent>
    </Dialog>
  );
}

function Group({ label, entries }: { label: string; entries: Entry[] }) {
  if (entries.length === 0) return null;
  return (
    <CommandGroup className="mb-1">
      <CommandGroupLabel className="px-2.5 pt-2 pb-1 text-[11.5px] text-ink-4">{label}</CommandGroupLabel>
      {entries.map((entry) => (
        <CommandItem
          key={entry.value}
          value={entry.value}
          label={`${entry.label} ${entry.hint ?? ""}`}
          keywords={entry.keywords}
          className="popup-item"
        >
          <CommandItemIcon className="text-ink-3">
            <entry.icon className="size-4" />
          </CommandItemIcon>
          <span className="min-w-0 flex-1 truncate text-ink">{entry.label}</span>
          {entry.hint ? <span className="shrink-0 truncate font-mono text-[11px] text-ink-4">{entry.hint}</span> : null}
        </CommandItem>
      ))}
    </CommandGroup>
  );
}
