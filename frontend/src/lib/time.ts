// Times are shown in the incident site's local time, the way the NOC talks about them ("07:32 IST").
const SITE_ZONES: Record<string, { zone: string; abbr?: string }> = {
  BLR: { zone: "Asia/Kolkata", abbr: "IST" },
  SIN: { zone: "Asia/Singapore", abbr: "SGT" },
  NYC: { zone: "America/New_York" },
  CORE: { zone: "Europe/London" },
  DC1: { zone: "Europe/London" },
};

const LOCALE_FOR_ZONE: Record<string, string> = {
  "America/New_York": "en-US",
  "Europe/London": "en-GB",
};

export function siteZone(siteId?: string | null) {
  return (siteId && SITE_ZONES[siteId]) || null;
}

export function zoneAbbr(siteId: string | null | undefined, at: Date = new Date()) {
  const site = siteZone(siteId);
  if (!site) return "UTC";
  if (site.abbr) return site.abbr;
  const parts = new Intl.DateTimeFormat(LOCALE_FOR_ZONE[site.zone] ?? "en-US", {
    timeZone: site.zone,
    timeZoneName: "short",
  }).formatToParts(at);
  return parts.find((p) => p.type === "timeZoneName")?.value ?? site.zone;
}

function toDate(value: string | Date) {
  return typeof value === "string" ? new Date(value) : value;
}

/** "07:32 IST" */
export function clock(value: string | Date | null | undefined, siteId?: string | null) {
  if (!value) return "—";
  const date = toDate(value);
  const site = siteZone(siteId);
  const time = new Intl.DateTimeFormat("en-GB", {
    hour: "2-digit",
    minute: "2-digit",
    hourCycle: "h23",
    timeZone: site?.zone ?? "UTC",
  }).format(date);
  return `${time} ${zoneAbbr(siteId, date)}`;
}

/** "4 Mar, 09:15 ET" for anything not today in that zone, otherwise the clock. */
export function stamp(value: string | Date | null | undefined, siteId?: string | null, now: Date = new Date()) {
  if (!value) return "—";
  const date = toDate(value);
  const site = siteZone(siteId);
  const zone = site?.zone ?? "UTC";
  const day = (d: Date) => new Intl.DateTimeFormat("en-CA", { timeZone: zone }).format(d);
  if (day(date) === day(now)) return clock(date, siteId);
  const dateText = new Intl.DateTimeFormat("en-GB", {
    day: "numeric",
    month: "short",
    year: date.getFullYear() === now.getFullYear() ? undefined : "numeric",
    timeZone: zone,
  }).format(date);
  return `${dateText}, ${clock(date, siteId)}`;
}

const RELATIVE = new Intl.RelativeTimeFormat("en", { numeric: "auto" });

/** "2 hours ago" */
export function ago(value: string | Date | null | undefined, now: Date = new Date()) {
  if (!value) return "";
  const seconds = Math.round((toDate(value).getTime() - now.getTime()) / 1000);
  const abs = Math.abs(seconds);
  if (abs < 45) return "just now";
  if (abs < 3600) return RELATIVE.format(Math.round(seconds / 60), "minute");
  if (abs < 86400) return RELATIVE.format(Math.round(seconds / 3600), "hour");
  if (abs < 86400 * 30) return RELATIVE.format(Math.round(seconds / 86400), "day");
  return RELATIVE.format(Math.round(seconds / (86400 * 30)), "month");
}

/** Seconds between two timestamps as "4m 10s". */
export function span(from: string, to: string) {
  const seconds = Math.max(0, Math.round((new Date(to).getTime() - new Date(from).getTime()) / 1000));
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return m ? `${m}m ${s}s` : `${s}s`;
}
