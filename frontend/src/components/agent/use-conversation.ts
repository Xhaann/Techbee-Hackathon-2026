"use client";

import { useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useRef, useState } from "react";
import { describeError, isApiError, readEvents } from "@/lib/api/client";
import { api } from "@/lib/api/endpoints";
import { refreshIncident } from "@/lib/api/hooks";
import type {
  AttachedIncident,
  ConversationContext,
  ConversationEvent,
  ConversationMessage,
  ConversationView,
  HumanConfirmation,
  Incident,
  MessageBody,
  QuickActionBody,
  ToolStep,
  TurnResult,
} from "@/lib/api/types";

export type LiveTool = {
  key: string;
  callId: string | null;
  tool: string;
  label: string;
  status: ToolStep["status"];
  summary?: string | null;
  target?: string;
  evidence: { evidence_id: string; summary: string }[];
};

export type LiveInvestigation = {
  id: string;
  kind: "full_diagnosis" | "targeted_check" | "multi_agent" | "protocol_check";
  mode: string;
  model?: string | null;
  budgetLimit: number;
  status: "running" | "completed" | "partial" | "failed" | "cancelled";
  tools: LiveTool[];
  toolCalls: number;
  correlated?: { fault_domain?: string; confidence?: string; root_cause?: string; count: number };
};

export type LiveTurn = {
  turnId: string | null;
  intent?: string;
  executesTools: boolean;
  typing: boolean;
  text: string;
  investigation?: LiveInvestigation;
  confirmations: HumanConfirmation[];
  cancelling: boolean;
};

type State = {
  conversationId: string | null;
  messages: ConversationMessage[];
  context: ConversationContext | null;
  /** Tool steps per investigation, from live events or loaded on demand. */
  steps: Record<string, LiveTool[]>;
  attached: Record<string, string>;
  modelAvailable: boolean | null;
  live: LiveTurn | null;
  error: string | null;
  notice: string | null;
  loading: boolean;
};

const EMPTY: State = {
  conversationId: null,
  messages: [],
  context: null,
  steps: {},
  attached: {},
  modelAvailable: null,
  live: null,
  error: null,
  notice: null,
  loading: true,
};

const storageKey = (incidentId: string) => `noc.conversation.${incidentId}`;

function targetOf(args: Record<string, unknown> | undefined) {
  if (!args) return undefined;
  if (typeof args.device_id === "string") return args.interface ? `${args.device_id} ${args.interface}` : args.device_id;
  if (typeof args.site_id === "string") return args.site_id;
  if (typeof args.source === "string" || typeof args.destination === "string")
    return [args.source, args.destination].filter(Boolean).join(" → ");
  if (typeof args.query === "string") return `“${args.query}”`;
  return undefined;
}

export function toolsFromSteps(steps: ToolStep[] | undefined): LiveTool[] {
  return (steps ?? []).map((step, index) => ({
    key: `${step.call_id ?? "k"}-${index}`,
    callId: step.call_id,
    tool: step.tool,
    label: step.tool,
    status: step.status,
    summary: step.summary,
    target: targetOf(step.arguments as Record<string, unknown>),
    evidence: (step.evidence_ids ?? []).map((id) => ({ evidence_id: id, summary: "" })),
  }));
}

function applyView(view: ConversationView): Partial<State> {
  const attached: Record<string, string> = {};
  for (const item of view.investigations) if (item.attached_diagnosis_id) attached[item.investigation_id] = item.attached_diagnosis_id;
  return { conversationId: view.conversation_id, messages: view.messages, context: view.context, modelAvailable: view.model_available, attached };
}

export function useConversation(incident: Incident, mode: "auto" | "rule_based") {
  const queryClient = useQueryClient();
  const incidentId = incident.incident_id;
  const [state, setState] = useState<State>(EMPTY);
  const stateRef = useRef(state);
  const abortRef = useRef<AbortController | null>(null);
  const seqRef = useRef(0);

  const update = useCallback((patch: Partial<State> | ((current: State) => Partial<State>)) => {
    setState((current) => {
      const next = { ...current, ...(typeof patch === "function" ? patch(current) : patch) };
      stateRef.current = next;
      return next;
    });
  }, []);

  const updateLive = useCallback(
    (change: (live: LiveTurn) => Partial<LiveTurn>) => update((current) => (current.live ? { live: { ...current.live, ...change(current.live) } } : {})),
    [update],
  );

  const updateInvestigation = useCallback(
    (change: (investigation: LiveInvestigation) => Partial<LiveInvestigation>) =>
      updateLive((live) => (live.investigation ? { investigation: { ...live.investigation, ...change(live.investigation) } } : {})),
    [updateLive],
  );

  /** Applies one server event. Returns true when the turn being followed has finished. */
  const handle = useCallback(
    (event: ConversationEvent, followTurn: string | null): boolean => {
      seqRef.current = Math.max(seqRef.current, event.seq);
      if (followTurn && event.turn_id && event.turn_id !== followTurn) return false;
      const data = event.data as Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
      switch (event.event) {
        case "turn.started": {
          const message = data.message as ConversationMessage;
          update((current) => ({
            messages: [...current.messages.filter((m) => !m.message_id.startsWith("local-") && m.message_id !== message.message_id), message],
            live: { ...(current.live ?? { typing: false, text: "", confirmations: [], cancelling: false, executesTools: false }), turnId: event.turn_id },
          }));
          return false;
        }
        case "intent.classified":
          updateLive(() => ({ intent: data.intent, executesTools: Boolean(data.executes_tools) }));
          return false;
        case "assistant.typing":
          updateLive(() => ({ typing: data.state === "start" }));
          return false;
        case "assistant.delta":
          updateLive((live) => ({ text: live.text + String(data.text ?? "") }));
          return false;
        case "investigation.started":
          updateLive(() => ({
            investigation: {
              id: data.investigation_id,
              kind: data.kind,
              mode: data.mode,
              model: data.model,
              budgetLimit: data.budget_limit ?? 10,
              status: "running",
              tools: [],
              toolCalls: 0,
            },
          }));
          return false;
        case "tool.started":
          updateInvestigation((inv) => ({
            tools: [
              ...inv.tools,
              {
                key: `${data.call_id}-${inv.tools.length}`,
                callId: data.call_id,
                tool: data.tool,
                label: data.label ?? data.tool,
                status: "running",
                target: targetOf(data.arguments),
                evidence: [],
              },
            ],
          }));
          return false;
        case "tool.completed":
        case "tool.failed":
        case "tool.skipped":
          updateInvestigation((inv) => {
            const finished: LiveTool = {
              key: `${data.call_id}-${inv.tools.length}`,
              callId: data.call_id,
              tool: data.tool,
              label: data.label ?? data.tool,
              status: data.status,
              summary: data.summary,
              evidence: (data.evidence ?? []).map((e: { evidence_id: string; summary: string }) => ({ evidence_id: e.evidence_id, summary: e.summary })),
            };
            const index = inv.tools.findIndex((t) => t.callId === data.call_id && t.status === "running");
            if (index < 0) return { tools: [...inv.tools, finished] };
            const tools = [...inv.tools];
            tools[index] = { ...finished, key: tools[index].key, target: tools[index].target };
            return { tools };
          });
          return false;
        case "knowledge.searched":
          if (data.investigation_id)
            updateInvestigation((inv) => ({
              tools: [
                ...inv.tools,
                {
                  key: `kb-${inv.tools.length}`,
                  callId: null,
                  tool: "search_knowledge",
                  label: "Knowledge search",
                  status: data.status === "guidance_only" ? "executed" : "rejected",
                  target: `“${String(data.query).slice(0, 60)}”`,
                  summary: `${(data.document_ids ?? []).length} guidance documents (unverified)`,
                  evidence: [],
                },
              ],
            }));
          return false;
        case "investigation.progress":
          updateInvestigation(() => ({ toolCalls: data.tool_calls ?? 0 }));
          return false;
        case "evidence.correlated":
          updateInvestigation(() => ({
            correlated: {
              fault_domain: data.fault_domain,
              confidence: data.confidence,
              root_cause: data.root_cause,
              count: (data.evidence ?? []).length,
            },
          }));
          return false;
        case "investigation.completed":
        case "investigation.failed":
        case "investigation.cancelled":
          updateInvestigation(() => ({ status: data.summary?.status ?? (event.event === "investigation.cancelled" ? "cancelled" : "completed") }));
          return false;
        case "human_confirmation.required":
          updateLive((live) => ({ confirmations: [...live.confirmations, data as HumanConfirmation] }));
          return false;
        case "turn.cancelling":
          updateLive(() => ({ cancelling: true }));
          return false;
        case "assistant.message": {
          const message = data.message as ConversationMessage;
          update((current) => {
            const investigation = current.live?.investigation;
            const steps = investigation ? { ...current.steps, [investigation.id]: investigation.tools } : current.steps;
            return { messages: [...current.messages.filter((m) => m.message_id !== message.message_id), message], steps };
          });
          return false;
        }
        case "turn.completed": {
          const result = data.result as TurnResult;
          update((current) => {
            const steps = { ...current.steps };
            if (result.investigation_id && !steps[result.investigation_id]) {
              steps[result.investigation_id] = toolsFromSteps(result.execution.tools);
            }
            return { live: null, context: result.context, steps };
          });
          return true;
        }
        case "turn.failed":
          update({ live: null, error: String(data.error?.message ?? "The assistant could not complete this turn") });
          return true;
        default:
          return false;
      }
    },
    [update, updateLive, updateInvestigation],
  );

  const follow = useCallback(
    async (response: Response, turnId: string | null) => {
      let finished = false;
      let followed = turnId;
      await readEvents<ConversationEvent>(response, (event) => {
        if (!followed && event.event === "turn.started") followed = event.turn_id;
        if (handle(event, followed)) finished = true;
      });
      return { finished, turnId: followed };
    },
    [handle],
  );

  /** Re-syncs from the server: history, context and a turn that may still be running. */
  const sync = useCallback(
    async (conversationId: string) => {
      const view = await api.conversations.get(conversationId);
      seqRef.current = view.last_event_seq;
      update({ ...applyView(view), live: view.active_turn ? { turnId: view.active_turn.turn_id, typing: true, text: "", confirmations: [], cancelling: false, executesTools: true } : null });
      if (view.active_turn) {
        const controller = new AbortController();
        abortRef.current = controller;
        try {
          const response = await api.conversations.events(conversationId, 0, controller.signal);
          await follow(response, view.active_turn.turn_id);
          const fresh = await api.conversations.get(conversationId);
          update({ ...applyView(fresh), live: null });
        } catch (error) {
          if ((error as Error).name !== "AbortError") update({ live: null, error: describeError(error) });
        }
      }
    },
    [follow, update],
  );

  useEffect(() => {
    let cancelled = false;
    const saved = window.sessionStorage.getItem(storageKey(incidentId));
    if (!saved) {
      // Nothing to load: the conversation is created with the first message, so opening the panel runs nothing.
      queueMicrotask(() => !cancelled && update({ ...EMPTY, loading: false }));
      return;
    }
    sync(saved)
      .catch((error) => {
        if (cancelled) return;
        if (isApiError(error) && error.status === 404) {
          window.sessionStorage.removeItem(storageKey(incidentId));
          update({ ...EMPTY, loading: false, notice: "The previous conversation is no longer on the server, so this is a fresh one." });
        } else update({ ...EMPTY, loading: false, error: describeError(error) });
      })
      .finally(() => !cancelled && update({ loading: false }));
    return () => {
      cancelled = true;
      abortRef.current?.abort();
    };
  }, [incidentId, sync, update]);

  const ensureConversation = useCallback(async () => {
    const existing = stateRef.current.conversationId;
    if (existing) return existing;
    const view = await api.conversations.create({ incident_id: incidentId, mode });
    window.sessionStorage.setItem(storageKey(incidentId), view.conversation_id);
    seqRef.current = view.last_event_seq;
    update(applyView(view));
    return view.conversation_id;
  }, [incidentId, mode, update]);

  const submit = useCallback(
    async (body: MessageBody, display: string, retried = false): Promise<void> => {
      if (stateRef.current.live) return;
      const local: ConversationMessage = {
        message_id: `local-${Date.now()}`,
        turn_id: "pending",
        role: "user",
        content: display,
        created_at: new Date().toISOString(),
        status: "completed",
        evidence_refs: [],
        suggested_actions: [],
        human_confirmations: [],
      };
      update((current) => ({
        error: null,
        notice: retried ? current.notice : null,
        messages: [...current.messages, local],
        live: { turnId: null, typing: true, text: "", confirmations: [], cancelling: false, executesTools: false },
      }));
      const controller = new AbortController();
      abortRef.current = controller;
      let conversationId: string | null = null;
      try {
        conversationId = await ensureConversation();
        const response = await api.conversations.stream(conversationId, body, controller.signal);
        let { finished, turnId } = await follow(response, null);
        if (!finished && conversationId) {
          // The stream dropped before the turn ended: replay what was missed and keep following.
          const resumed = await api.conversations.events(conversationId, seqRef.current, controller.signal);
          ({ finished, turnId } = await follow(resumed, turnId));
        }
        if (!finished && conversationId) {
          const view = await api.conversations.get(conversationId);
          update({ ...applyView(view), live: null });
        }
      } catch (error) {
        if ((error as Error).name === "AbortError") return;
        if (isApiError(error) && error.status === 404 && conversationId && !retried) {
          window.sessionStorage.removeItem(storageKey(incidentId));
          update((current) => ({
            conversationId: null,
            messages: current.messages.filter((m) => m.message_id !== local.message_id),
            live: null,
            notice: "The earlier conversation expired on the server, so I started a new one.",
          }));
          return submit(body, display, true);
        }
        update((current) => ({
          live: null,
          messages: current.messages.filter((m) => m.message_id !== local.message_id || !isApiError(error) || error.status !== 409),
          error:
            isApiError(error) && error.code === "TURN_IN_PROGRESS"
              ? "I'm still working on the previous message. Wait for it to finish or stop it."
              : describeError(error),
        }));
      } finally {
        if (abortRef.current === controller) abortRef.current = null;
      }
    },
    [ensureConversation, follow, incidentId, update],
  );

  const send = useCallback((text: string) => submit({ content: text }, text), [submit]);

  const act = useCallback((action: QuickActionBody) => submit({ action }, action.label ?? action.kind), [submit]);

  const cancel = useCallback(async () => {
    const conversationId = stateRef.current.conversationId;
    if (!conversationId || !stateRef.current.live) return;
    updateLive(() => ({ cancelling: true }));
    try {
      await api.conversations.cancel(conversationId);
    } catch (error) {
      update({ error: describeError(error) });
    }
  }, [update, updateLive]);

  const resetContext = useCallback(async () => {
    const conversationId = stateRef.current.conversationId;
    if (!conversationId) return;
    try {
      const context = await api.conversations.resetContext(conversationId);
      update({ context, notice: "I've cleared what you told me in this conversation. The incident link stays." });
    } catch (error) {
      update({ error: describeError(error) });
    }
  }, [update]);

  const newConversation = useCallback(() => {
    if (stateRef.current.live) return;
    abortRef.current?.abort();
    window.sessionStorage.removeItem(storageKey(incidentId));
    update({ ...EMPTY, loading: false });
  }, [incidentId, update]);

  const loadSteps = useCallback(
    async (investigationId: string) => {
      const conversationId = stateRef.current.conversationId;
      if (!conversationId || stateRef.current.steps[investigationId]) return;
      try {
        const investigation = await api.conversations.investigation(conversationId, investigationId);
        update((current) => ({ steps: { ...current.steps, [investigationId]: toolsFromSteps(investigation.steps) } }));
      } catch (error) {
        update({ error: describeError(error) });
      }
    },
    [update],
  );

  /** Human-approved save of a conversation diagnosis to the incident. Throws so the caller can explain a failure. */
  const attach = useCallback(
    async (investigationId: string): Promise<AttachedIncident> => {
      const conversationId = stateRef.current.conversationId;
      if (!conversationId) throw new Error("There's no conversation yet");
      const saved = await api.conversations.attach(conversationId, investigationId, incident.version);
      update((current) => ({ attached: { ...current.attached, [investigationId]: saved.active_diagnosis_id ?? "" } }));
      await refreshIncident(queryClient, incidentId);
      return saved;
    },
    [incident.version, incidentId, queryClient, update],
  );

  return { state, send, act, cancel, resetContext, newConversation, loadSteps, attach, dismissError: () => update({ error: null }) };
}
