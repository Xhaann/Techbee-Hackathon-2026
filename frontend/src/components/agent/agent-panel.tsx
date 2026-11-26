"use client";

import { Menu, MenuContent, MenuItem, MenuSeparator, MenuTrigger } from "@ui-sdk/react/menu";
import { Textarea } from "@ui-sdk/react/textarea";
import {
  ArrowUp,
  Check,
  ChevronRight,
  CircleSlash,
  Ellipsis,
  MessageSquarePlus,
  RotateCcw,
  Shield,
  ShieldCheck,
  Square,
  SquareActivity,
  TriangleAlert,
  UserCheck,
  X,
} from "lucide-react";
import { Fragment, useEffect, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import { Spinner } from "@/components/ui/button";
import { Tip } from "@/components/ui/tip";
import { notify } from "@/components/ui/toaster";
import { useIncidentActions } from "@/components/workspace/actions";
import type { ActionKey } from "@/components/workspace/model";
import { describeError } from "@/lib/api/client";
import type { ConversationMessage, EvidenceReference, Incident, QuickActionBody, SuggestedAction } from "@/lib/api/types";
import { useCan } from "@/lib/auth";
import { cn } from "@/lib/cn";
import { CONFIDENCE_LABEL, FAULT_LABEL } from "@/lib/labels";
import { setPrefs, usePrefs } from "@/lib/prefs";
import { clock } from "@/lib/time";
import { type LiveInvestigation, type LiveTool, useConversation } from "./use-conversation";

export type WorkspaceTab = "summary" | "evidence" | "checks" | "alternatives" | "timeline" | "escalations";

const TOOL_LABEL: Record<string, string> = {
  get_topology: "Site topology",
  get_device_logs: "Device logs",
  get_interface_stats: "Interface statistics",
  get_routing_state: "Routing state",
  get_firewall_logs: "Firewall logs",
  get_dhcp_dns_status: "DHCP and DNS status",
  check_network_reachability: "Path reachability",
  analyze_packet_loss: "Packet loss analysis",
  analyze_interface_errors: "Interface error analysis",
  analyze_routing_adjacency: "Routing adjacency analysis",
  check_device_availability: "Device availability",
  analyze_network_dependencies: "Dependency analysis",
  search_knowledge: "Knowledge search",
};

const INTENT_TAG: Partial<Record<string, string>> = {
  knowledge: "Knowledge base",
  incident_query: "Incident",
  symptom_report: "Clarifying",
  clarification: "Clarifying",
  targeted_diagnostic: "Targeted check",
  full_diagnosis: "Full diagnosis",
  evidence_explanation: "Evidence",
  status: "Status",
  human_action: "Needs a person",
};

const HUMAN_ACTIONS = new Set<ActionKey>(["confirm", "escalate", "close", "reopen", "severity", "priority", "propose", "verify", "edit"]);

export function AgentPanel({ incident, onClose, onShowTab }: { incident: Incident; onClose?: () => void; onShowTab?: (tab: WorkspaceTab) => void }) {
  const { agentMode } = usePrefs();
  const can = useCan();
  const actions = useIncidentActions();
  const conversation = useConversation(incident, agentMode === "rule_based" ? "rule_based" : "auto");
  const { state } = conversation;
  const [draft, setDraft] = useState("");
  const [saving, setSaving] = useState<string | null>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const siteId = incident.site_ids[0];
  const busy = state.live !== null;

  useEffect(() => {
    const list = listRef.current;
    if (!list) return;
    list.scrollTo({ top: list.scrollHeight, behavior: "smooth" });
  }, [state.messages.length, state.live, state.error]);

  const lastAssistant = useMemo(() => {
    for (let i = state.messages.length - 1; i >= 0; i--) if (state.messages[i].role === "assistant") return state.messages[i].message_id;
    return null;
  }, [state.messages]);
  const lastIsAssistant = state.messages.at(-1)?.role === "assistant";

  function submit() {
    const text = draft.trim();
    if (!text || busy) return;
    setDraft("");
    void conversation.send(text);
  }

  function onKeyDown(event: KeyboardEvent<HTMLTextAreaElement>) {
    if (event.key === "Enter" && !event.shiftKey && !event.nativeEvent.isComposing) {
      event.preventDefault();
      submit();
    }
  }

  async function runAction(action: SuggestedAction) {
    if (busy || !action.allowed) return;
    const params = action.params as Record<string, unknown>;
    switch (action.kind) {
      case "reply":
        void conversation.send(String(params.text ?? action.label));
        return;
      case "full_diagnosis":
        void conversation.act({ kind: "full_diagnosis", label: action.label });
        return;
      case "targeted_check":
        void conversation.act({
          kind: "targeted_check",
          tool: String(params.tool),
          arguments: params.arguments as Record<string, unknown>,
          label: action.label,
        });
        return;
      case "explain_evidence":
        void conversation.act({ kind: "explain_evidence", evidence_ids: (params.evidence_ids as string[]) ?? [], label: action.label });
        return;
      case "status":
        void conversation.act({ kind: "status", label: action.label });
        return;
      case "show_tab":
        onShowTab?.((params.tab as WorkspaceTab) ?? "summary");
        return;
      case "open_human_action": {
        const key = String(params.action) as ActionKey;
        if (HUMAN_ACTIONS.has(key)) void actions.trigger(key);
        return;
      }
      case "attach_investigation": {
        const investigationId = String(params.investigation_id);
        setSaving(investigationId);
        try {
          const saved = await conversation.attach(investigationId);
          notify.success("Diagnosis saved to the incident", `${saved.incident_id} · ${saved.active_diagnosis_id}`);
        } catch (error) {
          notify.error("Not saved", describeError(error));
        } finally {
          setSaving(null);
        }
        return;
      }
    }
  }

  const quick = (action: QuickActionBody) => !busy && void conversation.act(action);
  const fault = incident.active_diagnosis_id ? incident.diagnoses?.find((d) => d.diagnosis_id === incident.active_diagnosis_id) : undefined;
  const faultDevice = fault?.diagnosis.fault.device_ids[0];
  const canRun = can("run_diagnostics") && !!incident.dataset_scenario_id;

  return (
    <aside aria-label="Diagnosis agent" className="flex h-full w-full flex-col bg-panel">
      <header className="flex items-start gap-3 px-5 pt-4 pb-4 shadow-[inset_0_-1px_0_var(--line)]">
        <SquareActivity className="mt-[3px] size-[18px] shrink-0 text-ink-2" aria-hidden />
        <div className="min-w-0 flex-1">
          <h2 className="text-[16px] font-semibold tracking-[-0.015em] text-ink">Diagnosis agent</h2>
          <p className="mt-1 flex items-center gap-1.5 text-[12px] text-ink-3">
            <ShieldCheck className="size-3.5" aria-hidden />
            Read-only access
            {state.modelAvailable !== null ? (
              <>
                <span aria-hidden>·</span>
                {state.modelAvailable && agentMode !== "rule_based" ? "AI model" : "Rule-based"}
              </>
            ) : null}
          </p>
        </div>
        <Tip label="New conversation">
          <button
            type="button"
            aria-label="New conversation"
            disabled={busy}
            onClick={conversation.newConversation}
            className="grid size-7 place-items-center rounded-[6px] text-ink-3 hover:bg-hover hover:text-ink disabled:opacity-45"
          >
            <MessageSquarePlus className="size-4" aria-hidden />
          </button>
        </Tip>
        <Menu>
          <MenuTrigger aria-label="Agent options" className="grid size-7 place-items-center rounded-[6px] text-ink-3 hover:bg-hover hover:text-ink data-open:bg-hover">
            <Ellipsis className="size-4" aria-hidden />
          </MenuTrigger>
          <MenuContent side="bottom" align="end" sideOffset={6} className="popup w-[260px]">
            <MenuItem onSelect={conversation.newConversation} disabled={busy} className="popup-item">
              <MessageSquarePlus className="size-3.5" aria-hidden />
              New conversation
            </MenuItem>
            <MenuItem onSelect={() => void conversation.resetContext()} disabled={busy || !state.conversationId} className="popup-item">
              <RotateCcw className="size-3.5" aria-hidden />
              Forget what I told it
            </MenuItem>
            <MenuItem
              onSelect={() => {
                setPrefs({ agentMode: agentMode === "auto" ? "rule_based" : "auto" });
                conversation.newConversation();
              }}
              disabled={busy}
              className="popup-item"
            >
              <span className="grid size-3.5 place-items-center">{agentMode === "rule_based" ? <Check className="size-3.5" aria-hidden /> : null}</span>
              Rule-based planner only
            </MenuItem>
            {onClose ? (
              <>
                <MenuSeparator className="my-1 h-px bg-line-soft" />
                <MenuItem onSelect={onClose} className="popup-item">
                  <X className="size-3.5" aria-hidden />
                  Hide panel
                </MenuItem>
              </>
            ) : null}
          </MenuContent>
        </Menu>
      </header>

      <div ref={listRef} className="scroll-thin min-h-0 flex-1 space-y-3 overflow-y-auto px-4 py-4" aria-live="polite" aria-busy={busy}>
        {state.loading ? (
          <p className="flex items-center gap-2 px-1 text-[12.5px] text-ink-3">
            <Spinner /> Loading the conversation
          </p>
        ) : null}

        {!state.loading && state.messages.length === 0 ? (
          <Intro incident={incident}>
            <Chip onClick={() => void conversation.send("What can you do?")} disabled={busy}>
              What can you do?
            </Chip>
            {fault ? (
              <Chip onClick={() => quick({ kind: "explain_evidence", label: "Explain the current diagnosis" })} disabled={busy}>
                Explain the current diagnosis
              </Chip>
            ) : null}
            {canRun && faultDevice ? (
              <Chip
                runs
                onClick={() => quick({ kind: "targeted_check", tool: "get_routing_state", arguments: { device_id: faultDevice }, label: `Check ${faultDevice} routing` })}
                disabled={busy}
              >
                Check {faultDevice} routing
              </Chip>
            ) : null}
            {canRun ? (
              <Chip runs onClick={() => quick({ kind: "full_diagnosis", label: "Diagnose this incident" })} disabled={busy}>
                Diagnose this incident
              </Chip>
            ) : null}
          </Intro>
        ) : null}

        {state.notice ? <p className="px-1 text-[12px] leading-[1.45] text-ink-3">{state.notice}</p> : null}

        {state.messages.map((message) =>
          message.role === "user" ? (
            <div key={message.message_id} className="ml-8 rounded-[8px] bg-selected px-3.5 py-2.5 text-[13.5px] leading-[1.5] whitespace-pre-wrap text-ink">
              {message.content}
            </div>
          ) : (
            <AssistantMessage
              key={message.message_id}
              message={message}
              siteId={siteId}
              latest={message.message_id === lastAssistant && lastIsAssistant && !busy}
              steps={message.investigation_id ? state.steps[message.investigation_id] : undefined}
              attachedAs={message.investigation_id ? state.attached[message.investigation_id] : undefined}
              saving={saving}
              onLoadSteps={() => message.investigation_id && void conversation.loadSteps(message.investigation_id)}
              onAction={(action) => void runAction(action)}
              onOption={(text) => !busy && void conversation.send(text)}
              onEvidence={(id) => quick({ kind: "explain_evidence", evidence_ids: [id], label: `Explain ${id}` })}
            />
          ),
        )}

        {state.live ? (
          <>
            {state.live.investigation ? <ProgressCard investigation={state.live.investigation} cancelling={state.live.cancelling} /> : null}
            {state.live.text ? (
              <Bubble at="now">
                <RichText text={state.live.text} />
                <span className="ml-0.5 inline-block h-[14px] w-[6px] translate-y-[2px] animate-pulse rounded-[1px] bg-ink-3" aria-hidden />
              </Bubble>
            ) : !state.live.investigation || state.live.investigation.status !== "running" ? (
              <Typing cancelling={state.live.cancelling} />
            ) : null}
          </>
        ) : null}

        {state.error ? (
          <div className="mr-4 flex items-start gap-2.5 rounded-[8px] bg-red-soft px-3.5 py-2.5 text-[13px] leading-[1.45] text-red shadow-[0_0_0_1px_var(--red-line)]">
            <TriangleAlert className="mt-[2px] size-3.5 shrink-0" aria-hidden />
            <span className="flex-1">{state.error}</span>
            <button type="button" aria-label="Dismiss" onClick={conversation.dismissError} className="shrink-0 opacity-70 hover:opacity-100">
              <X className="size-3.5" aria-hidden />
            </button>
          </div>
        ) : null}
      </div>

      <div className="px-4 pt-2 pb-3">
        <div className="rounded-[9px] bg-sunken shadow-[0_0_0_1px_var(--line)] focus-within:shadow-[0_0_0_1px_var(--accent-ring),0_0_0_3px_var(--accent-soft)]">
          <Textarea
            aria-label="Message the diagnosis agent"
            autoResize
            value={draft}
            onValueChange={(value) => setDraft(value)}
            onKeyDown={onKeyDown}
            placeholder={busy ? "The agent is working…" : "Ask about this incident…"}
            className="block max-h-[160px] min-h-[46px] w-full resize-none bg-transparent px-3 pt-3 pb-1 text-[14px] leading-[1.5] text-ink outline-none placeholder:text-ink-3"
          />
          <div className="flex items-center gap-3 px-3 pb-2.5">
            <span className="flex items-center gap-1.5 text-[11.5px] text-ink-3">
              <Shield className="size-3" aria-hidden />
              Checks run only when you ask
            </span>
            {busy ? (
              <Tip label={state.live?.cancelling ? "Stopping" : "Stop"}>
                <button
                  type="button"
                  aria-label="Stop"
                  disabled={state.live?.cancelling || !state.conversationId}
                  onClick={() => void conversation.cancel()}
                  className="ml-auto grid size-[30px] place-items-center rounded-[7px] bg-raised text-ink-2 shadow-[0_0_0_1px_var(--line)] transition-colors hover:bg-hover hover:text-ink disabled:opacity-45"
                >
                  {state.live?.cancelling ? <Spinner /> : <Square className="size-3 fill-current" aria-hidden />}
                </button>
              </Tip>
            ) : (
              <button
                type="button"
                aria-label="Send"
                disabled={!draft.trim()}
                onClick={submit}
                className="ml-auto grid size-[30px] place-items-center rounded-[7px] bg-raised text-ink-2 shadow-[0_0_0_1px_var(--line)] transition-colors hover:bg-accent-strong hover:text-accent-fg disabled:opacity-45 disabled:hover:bg-raised disabled:hover:text-ink-2"
              >
                <ArrowUp className="size-4" aria-hidden />
              </button>
            )}
          </div>
        </div>
        <p className="mt-2 text-[11.5px] text-ink-3">
          {can("run_diagnostics") ? "The agent can inspect network data only." : "Your role can chat and read evidence but can't run checks."}
        </p>
      </div>
    </aside>
  );
}

function Intro({ incident, children }: { incident: Incident; children: ReactNode }) {
  return (
    <Bubble>
      <p className="text-[14px] leading-[1.5] text-ink-2">
        Ask me anything about {incident.incident_id}. I can explain the diagnosis and its evidence, run a specific read-only check, or
        investigate the whole incident. I only run checks when you ask.
      </p>
      <div className="mt-3 flex flex-wrap gap-1.5">{children}</div>
    </Bubble>
  );
}

function Bubble({ at, tag, children }: { at?: string; tag?: string; children: ReactNode }) {
  return (
    <div className="mr-4 rounded-[8px] bg-raised px-3.5 py-3 shadow-[0_0_0_1px_var(--line-soft)]">
      {at || tag ? (
        <div className="mb-1.5 flex items-center gap-2 font-mono text-[11px] text-ink-3">
          <SquareActivity className="size-3.5" aria-hidden />
          {at}
          {tag ? <span className="ml-auto rounded-[4px] bg-hover px-1.5 py-px font-sans text-[10.5px] text-ink-3">{tag}</span> : null}
        </div>
      ) : null}
      {children}
    </div>
  );
}

function Chip({ children, onClick, disabled, runs }: { children: ReactNode; onClick: () => void; disabled?: boolean; runs?: boolean }) {
  const button = (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className={cn(
        "inline-flex h-7 items-center gap-1.5 rounded-[7px] px-2.5 text-[12.5px] transition-colors disabled:opacity-45",
        runs ? "bg-accent-soft text-accent hover:brightness-125" : "bg-hover text-ink-2 hover:text-ink",
      )}
    >
      {children}
      {runs ? <ChevronRight className="size-3" aria-hidden /> : null}
    </button>
  );
  return runs ? <Tip label="Runs read-only checks when clicked">{button}</Tip> : button;
}

function Typing({ cancelling }: { cancelling: boolean }) {
  return (
    <div className="mr-4 inline-flex items-center gap-2 rounded-[8px] bg-raised px-3.5 py-2.5 shadow-[0_0_0_1px_var(--line-soft)]" role="status">
      {cancelling ? (
        <span className="flex items-center gap-2 text-[12.5px] text-ink-3">
          <Spinner /> Stopping
        </span>
      ) : (
        <span className="flex items-center gap-1" aria-label="The agent is replying">
          {[0, 1, 2].map((i) => (
            <span key={i} className="size-[5px] animate-bounce rounded-full bg-ink-3" style={{ animationDelay: `${i * 140}ms` }} />
          ))}
        </span>
      )}
    </div>
  );
}

function ToolIcon({ status }: { status: LiveTool["status"] }) {
  if (status === "running") return <Spinner className="size-3 text-accent" />;
  if (status === "executed") return <Check className="size-3 text-green" aria-label="Completed" />;
  if (status === "failed") return <X className="size-3 text-red" aria-label="Failed" />;
  return <CircleSlash className="size-3 text-ink-4" aria-label={status} />;
}

function ToolRow({ tool }: { tool: LiveTool }) {
  const label = TOOL_LABEL[tool.tool] ?? tool.label;
  return (
    <li className="flex gap-2.5 py-1">
      <span className="mt-[3px] grid size-3.5 shrink-0 place-items-center">
        <ToolIcon status={tool.status} />
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-baseline gap-x-1.5 text-[12.5px]">
          <span className="text-ink-2">{label}</span>
          {tool.target ? <span className="truncate font-mono text-[11px] text-ink-3">{tool.target}</span> : null}
          {tool.callId ? <span className="ml-auto font-mono text-[10.5px] text-ink-4">{tool.callId}</span> : null}
        </div>
        {tool.summary && tool.status !== "running" ? <p className="mt-0.5 text-[11.5px] leading-[1.4] text-ink-3">{tool.summary}</p> : null}
      </div>
    </li>
  );
}

function ProgressCard({ investigation, cancelling }: { investigation: LiveInvestigation; cancelling: boolean }) {
  const title = investigation.kind === "full_diagnosis" ? "Investigating the incident" : "Running the check";
  const running = investigation.status === "running";
  return (
    <section aria-label={title} className="mr-4 rounded-[8px] bg-raised px-3.5 py-3 shadow-[0_0_0_1px_var(--line-soft)]">
      <div className="flex items-center gap-2 text-[12.5px]">
        {running ? <Spinner className="text-accent" /> : <Check className="size-3.5 text-green" aria-hidden />}
        <span className="font-medium text-ink">{cancelling && running ? "Stopping…" : running ? title : "Checks finished"}</span>
        <span className="ml-auto font-mono text-[11px] text-ink-3">
          {investigation.toolCalls} / {investigation.budgetLimit} calls
        </span>
      </div>
      <p className="mt-1 text-[11.5px] text-ink-3">
        Read-only{investigation.mode === "agent" ? ` · ${investigation.model ?? "AI model"} choosing the checks` : investigation.mode === "rule_based" ? " · rule-based planner" : ""}
      </p>
      {investigation.tools.length ? (
        <ul className="mt-2 border-t border-line-soft pt-1.5">
          {investigation.tools.map((tool) => (
            <ToolRow key={tool.key} tool={tool} />
          ))}
        </ul>
      ) : running ? (
        <p className="mt-2 text-[12px] text-ink-3">Waiting for the first check…</p>
      ) : null}
      {investigation.correlated?.fault_domain ? (
        <p className="mt-2 border-t border-line-soft pt-2 text-[12px] text-ink-2">
          Correlated {investigation.correlated.count} evidence items:{" "}
          <span className="text-ink">{FAULT_LABEL[investigation.correlated.fault_domain as keyof typeof FAULT_LABEL] ?? investigation.correlated.fault_domain}</span>
          {investigation.correlated.confidence
            ? `, ${CONFIDENCE_LABEL[investigation.correlated.confidence as keyof typeof CONFIDENCE_LABEL]?.toLowerCase() ?? investigation.correlated.confidence} confidence`
            : ""}
        </p>
      ) : null}
    </section>
  );
}

function AssistantMessage({
  message,
  siteId,
  latest,
  steps,
  attachedAs,
  saving,
  onLoadSteps,
  onAction,
  onOption,
  onEvidence,
}: {
  message: ConversationMessage;
  siteId?: string;
  latest: boolean;
  steps?: LiveTool[];
  attachedAs?: string;
  saving: string | null;
  onLoadSteps: () => void;
  onAction: (action: SuggestedAction) => void;
  onOption: (text: string) => void;
  onEvidence: (id: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const tag = message.intent ? INTENT_TAG[message.intent] : undefined;
  const suggested = message.suggested_actions ?? [];
  const human = suggested.filter((a) => a.requires_human);
  const plain = suggested.filter((a) => !a.requires_human);
  const evidence = dedupeEvidence(message.evidence_refs ?? []);
  const options = message.clarification?.options ?? [];
  const ran = steps?.filter((s) => s.status === "executed" || s.status === "failed").length;

  return (
    <Bubble at={clock(message.created_at, siteId)} tag={message.status === "cancelled" ? "Stopped" : message.status === "failed" ? "Problem" : tag}>
      <RichText text={message.content} />

      {message.investigation_id ? (
        <div className="mt-2.5">
          <button
            type="button"
            onClick={() => {
              if (!open) onLoadSteps();
              setOpen(!open);
            }}
            aria-expanded={open}
            className="flex items-center gap-1 text-[12px] text-ink-3 hover:text-ink"
          >
            <ChevronRight className={cn("size-3 transition-transform", open && "rotate-90")} aria-hidden />
            {ran !== undefined ? `${ran} read-only check${ran === 1 ? "" : "s"}` : "Checks that ran"}
            <span className="font-mono text-[10.5px] text-ink-4">· {message.investigation_id}</span>
          </button>
          {open ? (
            steps ? (
              <ul className="mt-1 ml-1">
                {steps.map((tool) => (
                  <ToolRow key={tool.key} tool={tool} />
                ))}
              </ul>
            ) : (
              <p className="mt-1 ml-4 flex items-center gap-2 text-[12px] text-ink-3">
                <Spinner /> Loading
              </p>
            )
          ) : null}
        </div>
      ) : null}

      {evidence.length ? (
        <div className="mt-2.5 flex flex-wrap gap-1.5 border-t border-line-soft pt-2.5">
          {evidence.slice(0, 8).map((ref) => (
            <Tip key={`${ref.investigation_id ?? ref.diagnosis_id}-${ref.evidence_id}`} label={`${ref.summary} (${TOOL_LABEL[ref.tool] ?? ref.tool}, ${ref.call_id})`}>
              <button
                type="button"
                onClick={() => onEvidence(ref.evidence_id)}
                className="h-6 rounded-[5px] bg-accent-soft px-1.5 font-mono text-[11px] text-accent hover:brightness-125"
              >
                {ref.evidence_id}
              </button>
            </Tip>
          ))}
        </div>
      ) : null}

      {latest && options.length ? (
        <div className="mt-3 flex flex-wrap gap-1.5">
          {options.map((option) => (
            <Chip key={option} onClick={() => onOption(option)}>
              {option}
            </Chip>
          ))}
        </div>
      ) : null}

      {human.length ? (
        <div className="mt-3 rounded-[7px] bg-sunken px-3 py-2.5 shadow-[0_0_0_1px_var(--line-soft)]">
          <p className="flex items-center gap-1.5 text-[12px] font-medium text-ink-2">
            <UserCheck className="size-3.5" aria-hidden />
            Needs your approval. The agent won&apos;t do this itself.
          </p>
          <div className="mt-2 flex flex-wrap gap-1.5">
            {human.map((action) => {
              const investigationId = String((action.params as Record<string, unknown>).investigation_id ?? "");
              const done = action.kind === "attach_investigation" && !!attachedAs;
              const button = (
                <button
                  key={action.action_id}
                  type="button"
                  disabled={!action.allowed || done || saving === investigationId}
                  onClick={() => onAction(action)}
                  className="inline-flex h-7 items-center gap-1.5 rounded-[7px] bg-raised px-2.5 text-[12.5px] text-ink shadow-[0_0_0_1px_var(--line)] hover:bg-hover disabled:opacity-50"
                >
                  {saving === investigationId && action.kind === "attach_investigation" ? <Spinner /> : null}
                  {done ? `Saved as ${attachedAs}` : action.label}
                </button>
              );
              return action.allowed ? <Fragment key={action.action_id}>{button}</Fragment> : (
                <Tip key={action.action_id} label={action.reason ?? "Your role can't do this"}>
                  <span tabIndex={0}>{button}</span>
                </Tip>
              );
            })}
          </div>
        </div>
      ) : null}

      {latest && plain.length ? (
        <div className="mt-3 flex flex-wrap gap-1.5">
          {plain.map((action) => (
            <Chip key={action.action_id} runs={action.executes_tools} onClick={() => onAction(action)} disabled={!action.allowed}>
              {action.label}
            </Chip>
          ))}
        </div>
      ) : null}
    </Bubble>
  );
}

function dedupeEvidence(refs: EvidenceReference[]) {
  const seen = new Set<string>();
  return refs.filter((ref) => {
    const key = `${ref.investigation_id ?? ref.diagnosis_id}-${ref.evidence_id}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// ---------- A small, safe Markdown subset: paragraphs, "-" bullets, **bold**, `code` and evidence ids ----------

const INLINE = /(\*\*[^*\n]+\*\*|\*[^*\s][^*\n]*\*|`[^`\n]+`|\bE\d{1,3}\b)/g;

function Inline({ text }: { text: string }) {
  const parts = text.split(INLINE);
  return (
    <>
      {parts.map((part, index) => {
        if (!part) return null;
        if (part.startsWith("**") && part.endsWith("**") && part.length > 4)
          return (
            <strong key={index} className="font-semibold text-ink">
              <Inline text={part.slice(2, -2)} />
            </strong>
          );
        if (part.startsWith("*") && part.endsWith("*") && part.length > 2)
          return (
            <em key={index} className="text-ink not-italic">
              <Inline text={part.slice(1, -1)} />
            </em>
          );
        if (part.startsWith("`") && part.endsWith("`") && part.length > 2)
          return (
            <code key={index} className="rounded-[4px] bg-sunken px-1 py-px font-mono text-[12px] text-ink-2">
              {part.slice(1, -1)}
            </code>
          );
        if (/^E\d{1,3}$/.test(part))
          return (
            <span key={index} className="font-mono text-[12.5px] text-accent">
              {part}
            </span>
          );
        return <Fragment key={index}>{part}</Fragment>;
      })}
    </>
  );
}

export function RichText({ text }: { text: string }) {
  const blocks: { kind: "p" | "ul"; lines: string[] }[] = [];
  for (const raw of text.split("\n")) {
    const line = raw.trimEnd();
    const bullet = /^\s*(?:[-*•]|\d{1,2}[.)])\s+/.test(line);
    if (!line.trim()) {
      blocks.push({ kind: "p", lines: [] });
      continue;
    }
    const last = blocks.at(-1);
    const kind = bullet ? "ul" : "p";
    const content = bullet ? line.replace(/^\s*(?:[-*•]|\d{1,2}[.)])\s+/, "") : line;
    if (last && last.kind === kind && (kind === "ul" || last.lines.length)) last.lines.push(content);
    else blocks.push({ kind, lines: [content] });
  }
  return (
    <div className="space-y-2 text-[13.5px] leading-[1.55] text-ink-2">
      {blocks
        .filter((block) => block.lines.length)
        .map((block, index) =>
          block.kind === "ul" ? (
            <ul key={index} className="space-y-1">
              {block.lines.map((line, i) => (
                <li key={i} className="flex gap-2">
                  <span aria-hidden className="mt-[9px] size-[4px] shrink-0 rounded-full bg-ink-4" />
                  <span className="min-w-0">
                    <Inline text={line} />
                  </span>
                </li>
              ))}
            </ul>
          ) : (
            <p key={index} className="text-pretty">
              {block.lines.map((line, i) => (
                <Fragment key={i}>
                  {i ? <br /> : null}
                  <Inline text={line} />
                </Fragment>
              ))}
            </p>
          ),
        )}
    </div>
  );
}
