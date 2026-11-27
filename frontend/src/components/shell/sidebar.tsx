"use client";

import { Menu, MenuContent, MenuItem, MenuSeparator, MenuTrigger } from "@ui-sdk/react/menu";
import { Popover, PopoverContent, PopoverTitle, PopoverTrigger } from "@ui-sdk/react/popover";
import {
  Activity,
  BookOpen,
  ChartLine,
  ChevronDown,
  CircleHelp,
  Ellipsis,
  ExternalLink,
  FileText,
  LogOut,
  PanelLeft,
  Radar,
  ShieldCheck,
  Search,
  Settings,
  SquareTerminal,
  TriangleAlert,
  X,
} from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useMemo, type ComponentType, type ReactNode } from "react";
import { DemoTag, Dot, Kbd } from "@/components/ui/atoms";
import { Tip } from "@/components/ui/tip";
import { useActiveIncidents, useHealth, useIncidents, useTopology } from "@/lib/api/hooks";
import type { IncidentSummary } from "@/lib/api/types";
import { useAuth, usePrincipal } from "@/lib/auth";
import { cn } from "@/lib/cn";
import { FAULT_SHORT, initials, ROLE_TITLE, STATUS_LABEL, statusTone } from "@/lib/labels";
import { setPrefs } from "@/lib/prefs";
import { ago } from "@/lib/time";
import { Notifications } from "./notifications";
import { useShell } from "./shell-context";

const WORKSPACE_NAME = process.env.NEXT_PUBLIC_WORKSPACE_NAME ?? "HCL Tech";
const WORKSPACE_SCOPE = process.env.NEXT_PUBLIC_WORKSPACE_SCOPE ?? "NOC · Production";

type NavEntry = { href: string; label: string; icon: ComponentType<{ className?: string }>; match: (path: string) => boolean };

const NAV: NavEntry[] = [
  { href: "/diagnose", label: "Diagnose", icon: Activity, match: (p) => p.startsWith("/diagnose") },
  { href: "/incidents", label: "Incidents", icon: TriangleAlert, match: (p) => p.startsWith("/incidents") },
  { href: "/insights", label: "Network insights", icon: ChartLine, match: (p) => p.startsWith("/insights") },
  { href: "/observability", label: "Observability", icon: Radar, match: (p) => p.startsWith("/observability") },
  { href: "/protocols", label: "Protocols & security", icon: ShieldCheck, match: (p) => p.startsWith("/protocols") },
  { href: "/knowledge", label: "Knowledge base", icon: BookOpen, match: (p) => p.startsWith("/knowledge") },
  { href: "/reports", label: "Reports", icon: FileText, match: (p) => p.startsWith("/reports") },
  { href: "/cli", label: "Remote CLI", icon: SquareTerminal, match: (p) => p.startsWith("/cli") },
];

export function Sidebar({ mobile = false }: { mobile?: boolean }) {
  const pathname = usePathname();
  const { openPalette, setMobileNavOpen } = useShell();
  const active = useActiveIncidents();
  const activeCount = active.data?.total;

  return (
    <aside className="flex h-full w-[216px] shrink-0 flex-col bg-sidebar shadow-[inset_-1px_0_0_var(--line)]">
      <div className="flex h-[57px] shrink-0 items-center justify-end bg-chrome px-3 shadow-[inset_0_-1px_0_var(--line),inset_-1px_0_0_var(--line)]">
        {mobile ? (
          <button
            type="button"
            aria-label="Close navigation"
            onClick={() => setMobileNavOpen(false)}
            className="grid size-8 place-items-center rounded-[7px] text-ink-3 hover:bg-hover hover:text-ink"
          >
            <X className="size-[18px]" aria-hidden />
          </button>
        ) : (
          <Tip label="Hide sidebar">
            <button
              type="button"
              aria-label="Hide sidebar"
              onClick={() => setPrefs({ sidebarCollapsed: true })}
              className="grid size-8 place-items-center rounded-[7px] text-ink-3 hover:bg-hover hover:text-ink"
            >
              <PanelLeft className="size-[18px]" aria-hidden />
            </button>
          </Tip>
        )}
      </div>

      <div className="flex min-h-0 flex-1 flex-col overflow-y-auto px-3 pt-4 pb-3 scroll-thin">
        <WorkspaceCard />

        <button
          type="button"
          onClick={openPalette}
          className="mt-4 flex h-[34px] items-center gap-2.5 rounded-[8px] bg-sunken px-2.5 text-left text-[13px] text-ink-3 shadow-[0_0_0_1px_var(--line-soft)] hover:text-ink-2"
        >
          <Search className="size-[15px]" aria-hidden />
          <span className="flex-1">Search workspace</span>
          <Kbd>⌘K</Kbd>
        </button>

        <div className="mt-5 mb-1.5 px-0.5 text-[12px] text-ink-3">Workspace</div>
        <nav aria-label="Workspace" className="flex flex-col gap-0.5">
          {NAV.map((item) => (
            <NavLink
              key={item.href}
              href={item.href}
              icon={item.icon}
              active={item.match(pathname)}
              count={item.href === "/incidents" && activeCount ? activeCount : undefined}
              onNavigate={() => setMobileNavOpen(false)}
            >
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div className="my-4 h-px bg-line-soft" />
        <RecentDiagnoses pathname={pathname} onNavigate={() => setMobileNavOpen(false)} />

        <div className="mt-auto pt-6">
          <ConnectionStatus />
          <div className="mt-2 flex flex-col gap-0.5">
            <Notifications />
            <NavLink href="/settings" icon={Settings} active={pathname.startsWith("/settings")} onNavigate={() => setMobileNavOpen(false)}>
              Settings
            </NavLink>
            <NavLink href="/help" icon={CircleHelp} active={pathname.startsWith("/help")} onNavigate={() => setMobileNavOpen(false)}>
              Help & support
            </NavLink>
          </div>
        </div>
      </div>

      <UserRow />
    </aside>
  );
}

export function NavLink({
  href,
  icon: Icon,
  active,
  count,
  children,
  onNavigate,
}: {
  href: string;
  icon: ComponentType<{ className?: string }>;
  active?: boolean;
  count?: number;
  children: ReactNode;
  onNavigate?: () => void;
}) {
  return (
    <Link
      href={href}
      onClick={onNavigate}
      aria-current={active ? "page" : undefined}
      className={cn(
        "group flex h-[33px] items-center gap-2.5 rounded-[7px] px-2.5 text-[14px] transition-colors duration-150",
        active ? "bg-selected text-ink" : "text-ink-soft hover:bg-hover hover:text-ink",
      )}
    >
      <Icon className={cn("size-[16px] shrink-0", active ? "text-ink-2" : "text-ink-3 group-hover:text-ink-2")} />
      <span className="flex-1 truncate">{children}</span>
      {count !== undefined ? <span className="text-[12px] tabular-nums text-ink-3">{count}</span> : null}
    </Link>
  );
}

function WorkspaceCard() {
  const { baseUrl, signOut } = useAuth();
  const health = useHealth(baseUrl);
  const up = health.isSuccess;

  return (
    <Popover>
      <PopoverTrigger className="flex w-full items-center gap-2 rounded-[9px] bg-raised px-3 py-2.5 text-left shadow-[0_0_0_1px_var(--line-soft)] hover:bg-hover data-open:bg-hover">
        <span className="min-w-0 flex-1">
          <span className="block truncate text-[15px] font-semibold tracking-[-0.015em] text-ink">{WORKSPACE_NAME}</span>
          <span className="mt-0.5 flex items-center gap-1.5 text-[11.5px] text-ink-3">
            <Dot tone={up ? "green" : health.isPending ? "muted" : "red"} />
            <span className="truncate">{WORKSPACE_SCOPE}</span>
          </span>
        </span>
        <ChevronDown className="size-4 shrink-0 text-ink-3" aria-hidden />
      </PopoverTrigger>
      <PopoverContent side="bottom" align="start" sideOffset={6} className="popup w-[260px] p-3">
        <PopoverTitle className="text-[13.5px] font-semibold text-ink">{WORKSPACE_NAME}</PopoverTitle>
        <dl className="mt-2.5 space-y-2 text-[12.5px]">
          <div>
            <dt className="text-ink-3">API</dt>
            <dd className="mt-0.5 break-all font-mono text-[12px] text-ink-2">{baseUrl}</dd>
          </div>
          <div>
            <dt className="text-ink-3">Status</dt>
            <dd className={cn("mt-0.5", up ? "text-green" : "text-red")}>
              {up ? "Healthy" : health.isPending ? "Checking" : "Not responding"}
            </dd>
          </div>
        </dl>
        <div className="mt-3 flex flex-col gap-0.5 border-t border-line-soft pt-2">
          <a href={`${baseUrl}/docs`} target="_blank" rel="noreferrer" className="popup-item">
            <ExternalLink className="size-3.5" aria-hidden />
            Open API reference
          </a>
          <button type="button" onClick={() => signOut()} className="popup-item text-left hover:bg-hover">
            <LogOut className="size-3.5" aria-hidden />
            Sign out
          </button>
        </div>
      </PopoverContent>
    </Popover>
  );
}

function siteCity(siteId: string | undefined, cities: Map<string, string>) {
  if (!siteId) return "Unknown site";
  return cities.get(siteId) ?? siteId;
}

function RecentDiagnoses({ pathname, onNavigate }: { pathname: string; onNavigate: () => void }) {
  const incidents = useIncidents({ limit: 50 });
  const topology = useTopology();
  const cities = useMemo(() => new Map((topology.data?.sites ?? []).map((s) => [s.site_id, s.city])), [topology.data]);

  const recent = useMemo(() => {
    const items = [...(incidents.data?.items ?? [])];
    items.sort((a, b) => b.updated_at.localeCompare(a.updated_at));
    return items.slice(0, 4);
  }, [incidents.data]);

  return (
    <section aria-labelledby="recent-heading">
      <h2 id="recent-heading" className="mb-1.5 px-0.5 text-[12px] text-ink-3">
        Recent diagnoses
      </h2>
      {incidents.isPending ? (
        <div className="space-y-2 px-2 py-1">
          <div className="h-3 w-3/4 animate-pulse rounded bg-hover" />
          <div className="h-3 w-1/2 animate-pulse rounded bg-hover" />
        </div>
      ) : recent.length === 0 ? (
        <Link href="/diagnose" onClick={onNavigate} className="block rounded-[7px] px-2.5 py-2 text-[12.5px] leading-[1.45] text-ink-3 hover:bg-hover hover:text-ink-2">
          Open an incident to start a diagnosis
        </Link>
      ) : (
        <ul className="flex flex-col gap-0.5">
          {recent.map((incident) => (
            <RecentItem
              key={incident.incident_id}
              incident={incident}
              city={siteCity(incident.site_ids[0], cities)}
              active={pathname === `/diagnose/${incident.incident_id}`}
              onNavigate={onNavigate}
            />
          ))}
        </ul>
      )}
    </section>
  );
}

function RecentItem({
  incident,
  city,
  active,
  onNavigate,
}: {
  incident: IncidentSummary;
  city: string;
  active: boolean;
  onNavigate: () => void;
}) {
  const done = incident.status === "resolved" || incident.status === "closed";
  const tag = incident.fault_domain ? FAULT_SHORT[incident.fault_domain] : incident.title;
  return (
    <li>
      <Link
        href={`/diagnose/${incident.incident_id}`}
        onClick={onNavigate}
        aria-current={active ? "page" : undefined}
        className={cn("flex gap-2.5 rounded-[7px] px-2.5 py-2", active ? "bg-hover" : "hover:bg-hover")}
      >
        <Dot tone={done ? "muted" : statusTone(incident.status)} className="mt-[7px]" />
        <span className="min-w-0 flex-1">
          <span className="flex items-center gap-1.5">
            <span className="min-w-0 truncate text-[13px] font-medium tracking-[-0.01em] text-ink">
              {city} · {tag}
            </span>
            {incident.demo ? <DemoTag /> : null}
          </span>
          <span className="mt-0.5 block truncate text-[11.5px] text-ink-3">
            {done ? `${STATUS_LABEL[incident.status]} ${ago(incident.updated_at)}` : `${incident.incident_id.slice(4)} · ${STATUS_LABEL[incident.status]}`}
          </span>
        </span>
      </Link>
    </li>
  );
}

function ConnectionStatus() {
  const { baseUrl } = useAuth();
  const health = useHealth(baseUrl);
  const tone = health.isSuccess ? "green" : health.isPending ? "muted" : "red";
  const text = health.isSuccess ? "Diagnosis API connected" : health.isPending ? "Checking the API" : "Diagnosis API unreachable";
  return (
    <Tip label={baseUrl}>
      <div tabIndex={0} aria-label={`${text} at ${baseUrl}`} className={cn("flex items-center gap-2 px-2.5 py-1 text-[12.5px]", health.isSuccess ? "text-green" : health.isPending ? "text-ink-3" : "text-red")}>
        <Dot tone={tone} />
        {text}
      </div>
    </Tip>
  );
}

function UserRow() {
  const principal = usePrincipal();
  const { signOut } = useAuth();
  const role = ROLE_TITLE[principal.roles[0]] ?? principal.roles[0];

  return (
    <div className="flex shrink-0 items-center gap-2.5 px-3 py-3 shadow-[inset_0_1px_0_var(--line-soft)]">
      <span className="grid size-[30px] shrink-0 place-items-center rounded-full bg-hover font-mono text-[11px] font-medium text-ink-soft shadow-[0_0_0_1px_var(--line)]">
        {initials(principal.subject)}
      </span>
      <span className="min-w-0 flex-1">
        <span className="block truncate text-[13.5px] font-medium tracking-[-0.01em] text-ink">{principal.subject}</span>
        <span className="block truncate text-[11.5px] text-ink-3">{role}</span>
      </span>
      <Menu>
        <MenuTrigger aria-label="Account" className="grid size-7 place-items-center rounded-[6px] text-ink-3 hover:bg-hover hover:text-ink data-open:bg-hover">
          <Ellipsis className="size-4" aria-hidden />
        </MenuTrigger>
        <MenuContent side="top" align="end" sideOffset={6} className="popup w-[200px]">
          <MenuItem render={<Link href="/settings" />} className="popup-item">
            <Settings className="size-3.5" aria-hidden />
            Settings
          </MenuItem>
          <MenuSeparator className="my-1 h-px bg-line-soft" />
          <MenuItem onSelect={() => signOut()} className="popup-item">
            <LogOut className="size-3.5" aria-hidden />
            Sign out
          </MenuItem>
        </MenuContent>
      </Menu>
    </div>
  );
}
