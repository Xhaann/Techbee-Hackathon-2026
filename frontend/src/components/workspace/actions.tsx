"use client";

import { createContext, useContext, useMemo, useState, type FormEvent, type ReactNode } from "react";
import { ErrorNote } from "@/components/ui/atoms";
import { Button } from "@/components/ui/button";
import { Segmented } from "@/components/ui/controls";
import { FieldGroup, SelectBox, TextAreaField, TextField } from "@/components/ui/fields";
import { Modal } from "@/components/ui/modal";
import { notify } from "@/components/ui/toaster";
import { describeError, isApiError } from "@/lib/api/client";
import {
  useClassify,
  useCloseIncident,
  useEscalate,
  usePatchIncident,
  useReopenIncident,
  useResolution,
  useRunIncidentDiagnosis,
  useUpdateEscalation,
} from "@/lib/api/hooks";
import type { EscalationStatus, FaultDomain, Incident, IncidentPriority, IncidentSeverity, LifecycleStatus } from "@/lib/api/types";
import { useCan } from "@/lib/auth";
import {
  ESCALATION_STATUS_LABEL,
  FAULT_DOMAINS,
  FAULT_LABEL,
  inSentence,
  PRIORITY_LABEL,
  SEVERITY_LABEL,
  STATUS_LABEL,
} from "@/lib/labels";
import { actionStates, activeRecord, currentResolution, openEscalations, patchableTargets, type ActionKey, type ActionState } from "./model";

type DialogKey = Exclude<ActionKey, "acknowledge" | "diagnose" | "checks" | "monitor">;

type ActionsContextValue = {
  incident: Incident;
  states: Record<ActionKey, ActionState>;
  /** Runs a direct action, or opens the dialog that collects what it needs. */
  trigger: (key: ActionKey) => Promise<void> | void;
  busy: ActionKey | null;
};

const ActionsContext = createContext<ActionsContextValue | null>(null);

export function useIncidentActions() {
  const context = useContext(ActionsContext);
  if (!context) throw new Error("useIncidentActions must be used inside IncidentActions");
  return context;
}

function conflictMessage(error: unknown) {
  if (isApiError(error) && error.code === "INCIDENT_CONFLICT") {
    return "Someone changed this incident while you were working. The latest version is loaded; check it and try again.";
  }
  return describeError(error);
}

export function IncidentActions({ incident, onViewChecks, children }: { incident: Incident; onViewChecks: () => void; children: ReactNode }) {
  const can = useCan();
  const states = useMemo(() => actionStates(incident, can), [incident, can]);
  const [dialog, setDialog] = useState<DialogKey | null>(null);
  const [busy, setBusy] = useState<ActionKey | null>(null);
  const patch = usePatchIncident(incident.incident_id);
  const diagnose = useRunIncidentDiagnosis(incident.incident_id);

  async function direct(key: ActionKey, work: () => Promise<unknown>, success: string) {
    setBusy(key);
    try {
      await work();
      notify.success(success);
    } catch (error) {
      notify.error("That didn't go through", conflictMessage(error));
    } finally {
      setBusy(null);
    }
  }

  const trigger = (key: ActionKey) => {
    switch (key) {
      case "checks":
        onViewChecks();
        return;
      case "acknowledge":
        return direct(key, () => patch.mutateAsync({ expected_version: incident.version, status: "acknowledged" }), "Incident acknowledged");
      case "monitor":
        return direct(
          key,
          () => patch.mutateAsync({ expected_version: incident.version, status: "monitoring", reason: "Fix applied; watching before verification" }),
          "Monitoring started",
        );
      case "diagnose":
        return direct(key, () => diagnose.mutateAsync(incident.version), "Diagnosis attached to the incident");
      default:
        setDialog(key);
    }
  };

  const value = { incident, states, trigger, busy };
  const close = () => setDialog(null);

  return (
    <ActionsContext.Provider value={value}>
      {children}
      {dialog === "confirm" ? <ConfirmDialog incident={incident} onClose={close} /> : null}
      {dialog === "escalate" ? <EscalateDialog incident={incident} onClose={close} /> : null}
      {dialog === "update-escalation" ? <UpdateEscalationDialog incident={incident} onClose={close} /> : null}
      {dialog === "propose" ? <ProposeDialog incident={incident} onClose={close} /> : null}
      {dialog === "verify" ? <VerifyDialog incident={incident} onClose={close} /> : null}
      {dialog === "close" ? <CloseDialog incident={incident} onClose={close} /> : null}
      {dialog === "reopen" ? <ReopenDialog incident={incident} onClose={close} /> : null}
      {dialog === "edit" ? <EditDialog incident={incident} onClose={close} /> : null}
      {dialog === "severity" ? <SeverityDialog incident={incident} onClose={close} /> : null}
      {dialog === "priority" ? <PriorityDialog incident={incident} onClose={close} /> : null}
      {dialog === "status" ? <StatusDialog incident={incident} onClose={close} /> : null}
    </ActionsContext.Provider>
  );
}

// ---------- Dialog scaffolding ----------

function ActionForm({
  title,
  description,
  onClose,
  submitLabel,
  pendingLabel,
  onSubmit,
  children,
  disabled,
  danger,
}: {
  title: string;
  description?: ReactNode;
  onClose: () => void;
  submitLabel: string;
  pendingLabel: string;
  onSubmit: () => Promise<void>;
  children: ReactNode;
  disabled?: boolean;
  danger?: boolean;
}) {
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setPending(true);
    setError(null);
    try {
      await onSubmit();
      onClose();
    } catch (caught) {
      setError(conflictMessage(caught));
    } finally {
      setPending(false);
    }
  }

  return (
    <Modal open onOpenChange={(open) => !open && !pending && onClose()} title={title} description={description} dismissible={!pending}>
      <form onSubmit={submit} className="space-y-4">
        {children}
        {error ? <ErrorNote message={error} /> : null}
        <div className="flex items-center justify-end gap-2 pt-1">
          <Button variant="ghost" type="button" onClick={onClose} disabled={pending}>
            Cancel
          </Button>
          <Button variant={danger ? "danger" : "primary"} type="submit" disabled={disabled || pending}>
            {pending ? pendingLabel : submitLabel}
          </Button>
        </div>
      </form>
    </Modal>
  );
}

const domainOptions = FAULT_DOMAINS.map((value) => ({ value, label: FAULT_LABEL[value] }));
const priorityOptions = (Object.keys(PRIORITY_LABEL) as IncidentPriority[]).map((value) => ({ value, label: PRIORITY_LABEL[value] }));
const severityOptions = (Object.keys(SEVERITY_LABEL) as IncidentSeverity[]).map((value) => ({ value, label: SEVERITY_LABEL[value] }));

type DialogProps = { incident: Incident; onClose: () => void };

// ---------- Dialogs ----------

function ConfirmDialog({ incident, onClose }: DialogProps) {
  const record = activeRecord(incident);
  const probable = incident.classification?.probable_fault_domain ?? record?.probable_fault_domain ?? "unknown";
  const [domain, setDomain] = useState<FaultDomain>(incident.classification?.confirmed_fault_domain ?? probable);
  const [reason, setReason] = useState("");
  const classify = useClassify(incident.incident_id);

  return (
    <ActionForm
      title="Confirm the fault domain"
      description={
        record
          ? `The diagnosis says ${inSentence(FAULT_LABEL[probable])} with ${record.confidence.replaceAll("_", " ")} confidence. Recording it is a human decision.`
          : "Record the fault domain you've verified."
      }
      onClose={onClose}
      submitLabel={`Confirm ${inSentence(FAULT_LABEL[domain])}`}
      pendingLabel="Recording"
      disabled={!reason.trim()}
      onSubmit={async () => {
        await classify.mutateAsync({ expected_version: incident.version, fault_domain: domain, reason: reason.trim() });
        notify.success("Classification confirmed", FAULT_LABEL[domain]);
      }}
    >
      <FieldGroup label="Fault domain">
        <SelectBox ariaLabel="Fault domain" value={domain} onValueChange={setDomain} options={domainOptions} />
      </FieldGroup>
      <TextAreaField
        label="What you checked"
        value={reason}
        onChange={setReason}
        required
        maxLength={1000}
        placeholder="show interfaces Gi0/0/0 shows rising CRC errors; carrier confirmed a degraded circuit"
      />
    </ActionForm>
  );
}

function EscalateDialog({ incident, onClose }: DialogProps) {
  const recommendation = activeRecord(incident)?.diagnosis.escalation;
  const [team, setTeam] = useState(recommendation?.team ?? "");
  const [priority, setPriority] = useState<IncidentPriority>(recommendation?.priority ?? incident.priority);
  const [reason, setReason] = useState(recommendation?.reason ?? "");
  const escalate = useEscalate(incident.incident_id);
  const needsBoth = !recommendation;

  return (
    <ActionForm
      title="Recommend an escalation"
      description="This records the handover with the evidence and outstanding checks. Nothing is sent; you contact the team yourself."
      onClose={onClose}
      submitLabel="Record escalation"
      pendingLabel="Recording"
      disabled={needsBoth && (!team.trim() || !reason.trim())}
      onSubmit={async () => {
        const created = await escalate.mutateAsync({
          expected_version: incident.version,
          team: team.trim() || undefined,
          priority,
          reason: reason.trim() || undefined,
        });
        notify.success(`${created.escalation_id} recorded`, `Recommended to ${created.recommended_team}; not sent.`);
      }}
    >
      <TextField label="Team" value={team} onChange={setTeam} maxLength={120} required={needsBoth} placeholder="WAN Operations / carrier liaison" />
      <FieldGroup label="Priority">
        <SelectBox ariaLabel="Priority" value={priority} onValueChange={setPriority} options={priorityOptions} />
      </FieldGroup>
      <TextAreaField label="Reason" value={reason} onChange={setReason} maxLength={1000} required={needsBoth} />
    </ActionForm>
  );
}

const NEXT_ESCALATION: Record<EscalationStatus, EscalationStatus[]> = {
  recommended: ["assigned", "closed", "cancelled"],
  assigned: ["closed", "cancelled"],
  closed: [],
  cancelled: [],
};

function UpdateEscalationDialog({ incident, onClose }: DialogProps) {
  const open = openEscalations(incident);
  const [escalationId, setEscalationId] = useState(open[0]?.escalation_id ?? "");
  const escalation = open.find((e) => e.escalation_id === escalationId);
  const choices = escalation ? NEXT_ESCALATION[escalation.status] : [];
  const [status, setStatus] = useState<EscalationStatus>(choices[0] ?? "closed");
  const [note, setNote] = useState("");
  const [assignedTeam, setAssignedTeam] = useState(escalation?.assigned_team ?? escalation?.recommended_team ?? "");
  const update = useUpdateEscalation(incident.incident_id);

  return (
    <ActionForm
      title="Update escalation"
      description={escalation ? `Recommended to ${escalation.recommended_team} · ${ESCALATION_STATUS_LABEL[escalation.status]}` : undefined}
      onClose={onClose}
      submitLabel={`Mark ${status}`}
      pendingLabel="Saving"
      disabled={!escalation || !note.trim()}
      onSubmit={async () => {
        await update.mutateAsync({
          escalationId,
          body: {
            expected_version: incident.version,
            status,
            note: note.trim(),
            assigned_team: status === "assigned" && assignedTeam.trim() ? assignedTeam.trim() : undefined,
          },
        });
        notify.success(`${escalationId} ${status}`);
      }}
    >
      {open.length > 1 ? (
        <FieldGroup label="Escalation">
          <SelectBox
            ariaLabel="Escalation"
            value={escalationId}
            onValueChange={(next) => {
              setEscalationId(next);
              const picked = open.find((e) => e.escalation_id === next);
              if (picked) setStatus(NEXT_ESCALATION[picked.status][0]);
            }}
            options={open.map((e) => ({ value: e.escalation_id, label: `${e.escalation_id} · ${e.recommended_team}` }))}
          />
        </FieldGroup>
      ) : null}
      <FieldGroup label="New status">
        <Segmented
          ariaLabel="New status"
          value={status}
          onValueChange={setStatus}
          options={choices.map((choice) => ({ value: choice, label: choice.charAt(0).toUpperCase() + choice.slice(1) }))}
        />
      </FieldGroup>
      {status === "assigned" ? <TextField label="Assigned team" value={assignedTeam} onChange={setAssignedTeam} maxLength={120} /> : null}
      <TextAreaField label="Note" value={note} onChange={setNote} required maxLength={1000} placeholder="Carrier ticket CR-48812 opened; ETA 2 hours" />
    </ActionForm>
  );
}

function ProposeDialog({ incident, onClose }: DialogProps) {
  const [summary, setSummary] = useState("");
  const [domain, setDomain] = useState<FaultDomain>(
    incident.classification?.confirmed_fault_domain ?? incident.classification?.probable_fault_domain ?? "unknown",
  );
  const [team, setTeam] = useState(incident.assigned_team ?? "");
  const [notes, setNotes] = useState("");
  const resolution = useResolution(incident.incident_id);

  return (
    <ActionForm
      title="Propose a resolution"
      description="An incident manager verifies it while the incident is in monitoring. Closing needs that verification."
      onClose={onClose}
      submitLabel="Propose resolution"
      pendingLabel="Proposing"
      disabled={!summary.trim()}
      onSubmit={async () => {
        await resolution.mutateAsync({
          expected_version: incident.version,
          action: "propose",
          summary: summary.trim(),
          fault_domain: domain,
          responsible_team: team.trim() || undefined,
          notes: notes
            .split("\n")
            .map((line) => line.trim())
            .filter(Boolean)
            .slice(0, 20),
        });
        notify.success("Resolution proposed", "Move the incident to monitoring so it can be verified.");
      }}
    >
      <TextAreaField label="What fixed it" value={summary} onChange={setSummary} required maxLength={1000} placeholder="Carrier replaced the faulty optic on WAN-NYC-0001; loss back to 0%" />
      <FieldGroup label="Fault domain">
        <SelectBox ariaLabel="Fault domain" value={domain} onValueChange={setDomain} options={domainOptions} />
      </FieldGroup>
      <TextField label="Responsible team" value={team} onChange={setTeam} maxLength={120} />
      <TextAreaField label="Notes" hint="One per line, up to 20." value={notes} onChange={setNotes} rows={2} />
    </ActionForm>
  );
}

function VerifyDialog({ incident, onClose }: DialogProps) {
  const pending = currentResolution(incident);
  const [decision, setDecision] = useState<"approve" | "reject">("approve");
  const [note, setNote] = useState("");
  const resolution = useResolution(incident.incident_id);
  const canApprove = incident.status === "monitoring";

  return (
    <ActionForm
      title="Verify the resolution"
      description={pending ? `${pending.resolution_id}: ${pending.summary}` : undefined}
      onClose={onClose}
      submitLabel={decision === "approve" ? "Approve and resolve" : "Reject"}
      pendingLabel="Saving"
      danger={decision === "reject"}
      disabled={!note.trim() || (decision === "approve" && !canApprove)}
      onSubmit={async () => {
        await resolution.mutateAsync({ expected_version: incident.version, action: "verify", approved: decision === "approve", note: note.trim() });
        notify.success(decision === "approve" ? "Resolution verified; incident resolved" : "Resolution rejected");
      }}
    >
      <FieldGroup label="Decision" hint={!canApprove ? "Approving needs the incident in monitoring." : undefined}>
        <Segmented
          ariaLabel="Decision"
          value={decision}
          onValueChange={setDecision}
          options={[
            { value: "approve", label: "Approve" },
            { value: "reject", label: "Reject" },
          ]}
        />
      </FieldGroup>
      <TextAreaField label="Verification note" value={note} onChange={setNote} required maxLength={1000} placeholder="Loss at 0% for 30 minutes; users confirm ERP is normal" />
    </ActionForm>
  );
}

function CloseDialog({ incident, onClose }: DialogProps) {
  const [note, setNote] = useState("");
  const close = useCloseIncident(incident.incident_id);
  return (
    <ActionForm
      title="Close the incident"
      description="Closing records your note. You can reopen it later."
      onClose={onClose}
      submitLabel="Close incident"
      pendingLabel="Closing"
      disabled={!note.trim()}
      onSubmit={async () => {
        await close.mutateAsync({ expected_version: incident.version, note: note.trim() });
        notify.success("Incident closed");
      }}
    >
      <TextAreaField label="Closure note" value={note} onChange={setNote} required maxLength={1000} />
    </ActionForm>
  );
}

function ReopenDialog({ incident, onClose }: DialogProps) {
  const [reason, setReason] = useState("");
  const reopen = useReopenIncident(incident.incident_id);
  return (
    <ActionForm
      title="Reopen the incident"
      description="It goes back to investigating."
      onClose={onClose}
      submitLabel="Reopen"
      pendingLabel="Reopening"
      disabled={!reason.trim()}
      onSubmit={async () => {
        await reopen.mutateAsync({ expected_version: incident.version, reason: reason.trim() });
        notify.success("Incident reopened");
      }}
    >
      <TextAreaField label="Why it's back" value={reason} onChange={setReason} required maxLength={1000} />
    </ActionForm>
  );
}

function EditDialog({ incident, onClose }: DialogProps) {
  const [title, setTitle] = useState(incident.title);
  const [description, setDescription] = useState(incident.description);
  const [team, setTeam] = useState(incident.assigned_team ?? "");
  const [owner, setOwner] = useState(incident.assigned_owner ?? "");
  const patch = usePatchIncident(incident.incident_id);
  const changes = {
    ...(title.trim() !== incident.title ? { title: title.trim() } : {}),
    ...(description.trim() !== incident.description ? { description: description.trim() } : {}),
    ...(team.trim() && team.trim() !== (incident.assigned_team ?? "") ? { assigned_team: team.trim() } : {}),
    ...(owner.trim() && owner.trim() !== (incident.assigned_owner ?? "") ? { assigned_owner: owner.trim().toLowerCase() } : {}),
  };

  return (
    <ActionForm
      title="Edit details"
      onClose={onClose}
      submitLabel="Save changes"
      pendingLabel="Saving"
      disabled={Object.keys(changes).length === 0}
      onSubmit={async () => {
        await patch.mutateAsync({ expected_version: incident.version, ...changes });
        notify.success("Details saved");
      }}
    >
      <TextField label="Title" value={title} onChange={setTitle} minLength={3} maxLength={200} required />
      <TextAreaField label="Description" value={description} onChange={setDescription} maxLength={4000} rows={4} required />
      <div className="grid gap-4 sm:grid-cols-2">
        <TextField label="Assigned team" value={team} onChange={setTeam} maxLength={120} />
        <TextField label="Owner" value={owner} onChange={setOwner} mono placeholder="noc.operator" hint="Lowercase user id" />
      </div>
    </ActionForm>
  );
}

function SeverityDialog({ incident, onClose }: DialogProps) {
  const [severity, setSeverity] = useState<IncidentSeverity>(incident.severity);
  const [reason, setReason] = useState("");
  const patch = usePatchIncident(incident.incident_id);
  return (
    <ActionForm
      title="Change severity"
      description={`Currently ${SEVERITY_LABEL[incident.severity].toLowerCase()} (${incident.severity_source}).`}
      onClose={onClose}
      submitLabel="Change severity"
      pendingLabel="Saving"
      disabled={severity === incident.severity || !reason.trim()}
      onSubmit={async () => {
        await patch.mutateAsync({ expected_version: incident.version, severity, reason: reason.trim() });
        notify.success(`Severity set to ${SEVERITY_LABEL[severity].toLowerCase()}`);
      }}
    >
      <FieldGroup label="Severity">
        <SelectBox ariaLabel="Severity" value={severity} onValueChange={setSeverity} options={severityOptions} />
      </FieldGroup>
      <TextAreaField label="Reason" value={reason} onChange={setReason} required maxLength={1000} />
    </ActionForm>
  );
}

function PriorityDialog({ incident, onClose }: DialogProps) {
  const [priority, setPriority] = useState<IncidentPriority>(incident.priority);
  const [reason, setReason] = useState("");
  const patch = usePatchIncident(incident.incident_id);
  return (
    <ActionForm
      title="Change priority"
      description={`Currently ${PRIORITY_LABEL[incident.priority]} (${incident.priority_source}).`}
      onClose={onClose}
      submitLabel="Change priority"
      pendingLabel="Saving"
      disabled={priority === incident.priority || !reason.trim()}
      onSubmit={async () => {
        await patch.mutateAsync({ expected_version: incident.version, priority, reason: reason.trim() });
        notify.success(`Priority set to ${PRIORITY_LABEL[priority]}`);
      }}
    >
      <FieldGroup label="Priority">
        <SelectBox ariaLabel="Priority" value={priority} onValueChange={setPriority} options={priorityOptions} />
      </FieldGroup>
      <TextAreaField label="Reason" value={reason} onChange={setReason} required maxLength={1000} />
    </ActionForm>
  );
}

function StatusDialog({ incident, onClose }: DialogProps) {
  const targets = patchableTargets(incident);
  const [target, setTarget] = useState<LifecycleStatus>(targets[0]);
  const [reason, setReason] = useState("");
  const patch = usePatchIncident(incident.incident_id);
  return (
    <ActionForm
      title="Change status"
      description={`Currently ${STATUS_LABEL[incident.status].toLowerCase()}. Escalating, resolving and closing have their own steps.`}
      onClose={onClose}
      submitLabel={`Move to ${STATUS_LABEL[target].toLowerCase()}`}
      pendingLabel="Saving"
      onSubmit={async () => {
        await patch.mutateAsync({ expected_version: incident.version, status: target, reason: reason.trim() || undefined });
        notify.success(`Status set to ${STATUS_LABEL[target].toLowerCase()}`);
      }}
    >
      <FieldGroup label="New status">
        <SelectBox ariaLabel="New status" value={target} onValueChange={setTarget} options={targets.map((t) => ({ value: t, label: STATUS_LABEL[t] }))} />
      </FieldGroup>
      <TextAreaField label="Reason" value={reason} onChange={setReason} maxLength={1000} hint="Optional, recorded on the timeline." />
    </ActionForm>
  );
}
