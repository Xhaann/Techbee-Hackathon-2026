import { Suspense } from "react";
import { IncidentWorkspace } from "@/components/workspace/workspace";

export const instant = false;
export const metadata = { title: "Incident workspace" };

export default function IncidentWorkspacePage({ params }: PageProps<"/diagnose/[incidentId]">) {
  return (
    <Suspense fallback={null}>
      {params.then(({ incidentId }) => (
        <IncidentWorkspace key={incidentId} incidentId={decodeURIComponent(incidentId)} />
      ))}
    </Suspense>
  );
}
