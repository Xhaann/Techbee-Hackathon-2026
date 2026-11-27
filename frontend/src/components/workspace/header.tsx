"use client";

import { Menu, MenuContent, MenuGroup, MenuGroupLabel, MenuItem, MenuSeparator, MenuTrigger } from "@ui-sdk/react/menu";
import { ChevronDown } from "lucide-react";
import { DemoTag, Pill } from "@/components/ui/atoms";
import type { Incident, Site } from "@/lib/api/types";
import { cn } from "@/lib/cn";
import { PRIORITY_LABEL, SEVERITY_LABEL, severityTone, STATUS_LABEL } from "@/lib/labels";
import { clock, stamp } from "@/lib/time";
import { useIncidentActions } from "./actions";
import type { ActionKey } from "./model";

const MENU: { group: string; items: { key: ActionKey; label: string }[] }[] = [
  {
    group: "Investigate",
    items: [
      { key: "diagnose", label: "Run diagnosis again" },
      { key: "confirm", label: "Confirm fault domain" },
      { key: "escalate", label: "Recommend escalation" },
      { key: "update-escalation", label: "Update escalation" },
    ],
  },
  {
    group: "Resolve",
    items: [
      { key: "propose", label: "Propose resolution" },
      { key: "monitor", label: "Start monitoring" },
      { key: "verify", label: "Verify resolution" },
      { key: "close", label: "Close incident" },
      { key: "reopen", label: "Reopen incident" },
    ],
  },
  {
    group: "Details",
    items: [
      { key: "edit", label: "Edit details" },
      { key: "status", label: "Change status" },
      { key: "severity", label: "Change severity" },
      { key: "priority", label: "Change priority" },
    ],
  },
];

export function IncidentHeader({ incident, site, subtitle }: { incident: Incident; site?: Site; subtitle: string }) {
  const siteId = incident.site_ids[0];
  return (
    <header>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <Pill tone={severityTone(incident.severity)} dot>
          {PRIORITY_LABEL[incident.priority]} · {SEVERITY_LABEL[incident.severity]}
        </Pill>
        <span className="text-[13px] text-ink-2">{STATUS_LABEL[incident.status]}</span>
        {incident.demo ? <DemoTag /> : null}
        <span className="ml-auto flex items-center gap-3">
          <span className="font-mono text-[11.5px] text-ink-3" title={stamp(incident.created_at, siteId)}>
            Opened {clock(incident.created_at, siteId)}
          </span>
          <ActionsMenu />
        </span>
      </div>
      <h1 className="mt-3 text-[clamp(26px,3.2vw,34px)] leading-[1.08] font-semibold tracking-[-0.035em] text-balance text-ink">{incident.title}</h1>
      <p className="mt-2 text-[14.5px] text-ink-2">
        {site?.name ?? siteId}
        {subtitle ? ` · ${subtitle}` : ""}
      </p>
    </header>
  );
}

function ActionsMenu() {
  const { states, trigger } = useIncidentActions();
  const permitted = MENU.some((section) => section.items.some((item) => states[item.key].allowed || !states[item.key].reason?.startsWith("Your role")));
  if (!permitted) return null;
  return (
    <Menu>
      <MenuTrigger className="inline-flex h-7 items-center gap-1 rounded-[7px] px-2 text-[12.5px] font-medium text-ink-2 shadow-[0_0_0_1px_var(--line)] hover:bg-hover hover:text-ink data-open:bg-hover">
        Actions
        <ChevronDown className="size-3.5 text-ink-3" aria-hidden />
      </MenuTrigger>
      <MenuContent side="bottom" align="end" sideOffset={6} className="popup w-[280px]">
        {MENU.map((section, index) => {
          const visible = section.items.filter((item) => states[item.key].allowed || !states[item.key].reason?.startsWith("Your role"));
          if (!visible.length) return null;
          return (
            <MenuGroup key={section.group}>
              {index > 0 ? <MenuSeparator className="my-1 h-px bg-line-soft" /> : null}
              <MenuGroupLabel className="px-2 pt-1.5 pb-1 text-[11.5px] text-ink-4">{section.group}</MenuGroupLabel>
              {visible.map((item) => {
                const state = states[item.key];
                return (
                  <MenuItem
                    key={item.key}
                    disabled={!state.allowed}
                    onSelect={() => {
                      void trigger(item.key);
                    }}
                    className={cn("popup-item flex-col items-start gap-0.5")}
                  >
                    <span>{item.label}</span>
                    {!state.allowed && state.reason ? <span className="text-[11.5px] leading-[1.35] text-ink-4">{state.reason}</span> : null}
                  </MenuItem>
                );
              })}
            </MenuGroup>
          );
        })}
      </MenuContent>
    </Menu>
  );
}
