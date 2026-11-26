import { IncidentsView } from "@/components/views/incidents-view";

export const instant = false;
export const metadata = { title: "Incidents" };

export default function Page() {
  return <IncidentsView />;
}
