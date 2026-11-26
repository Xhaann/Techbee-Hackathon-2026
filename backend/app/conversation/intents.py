"""Deterministic intent classification and targeted-check planning.

The classifier decides *whether* any tool may run. Only three paths lead to tool execution: an explicit diagnosis
request, a check request that names (or clearly implies) a target, and a quick action the user clicked. Greetings,
general conversation, knowledge questions, symptom descriptions and evidence explanations never plan a tool call.
"""
import re

from app.conversation.entities import TopologyIndex, extract, wan_interface_requested
from app.conversation.models import ConversationContext, Entities, Intent, IntentResult, PlannedCall
from app.network.models import DeviceRole

MAX_PLANNED_CALLS = 4

GREETING_PREFIX = re.compile(
    r"^(?:hi+|hello+|hey+|hiya|howdy|yo|greetings|good (?:morning|afternoon|evening|day)|namaste)\b"
    r"(?:\s+(?:there|team|assistant|bot|all|everyone|folks))?[\s!,.:;-]*", re.IGNORECASE)
GREETING_FILLER = re.compile(r"^(?:again|there|all|team|everyone|folks|guys|mate|friend|buddy|assistant|bot|"
                             r"and good (?:morning|afternoon|evening))?[\s!.:)]*(?:how are you(?: doing)?|how's it going)?[\s?!.]*$",
                             re.IGNORECASE)
SMALLTALK = re.compile(r"^(?:how are you(?: doing)?|how's it going|how are things|what's up|sup|how do you do)[\s?!.]*$", re.IGNORECASE)
ACKNOWLEDGE = re.compile(r"^(?:thanks?(?: you)?(?: so much| a lot)?|thx|ty|cheers|great|awesome|perfect|nice|cool|got it|understood|"
                         r"noted|makes sense|ok(?:ay)?|alright|bye|goodbye|see you|that's all|that is all)\b[\s!.,]*(?:thanks?(?: you)?)?[\s!.]*$",
                         re.IGNORECASE)
AFFIRM = re.compile(r"^(?:yes|yep|yeah|yup|sure|ok(?:ay)?|go ahead|do it|please do|run it|proceed|sounds good|go for it|"
                    r"let'?s do it|let'?s go|confirm(?:ed)?|absolutely|y|start it|please)\b", re.IGNORECASE)
NEGATE = re.compile(r"^(?:no|nope|nah|not now|not yet|don'?t|do not|skip|never ?mind|later|hold off|wait)\b", re.IGNORECASE)
CANCEL = re.compile(r"^(?:cancel|stop|abort|halt|kill|terminate)\b|\b(?:cancel|stop|abort|halt) (?:the |this |that )?"
                    r"(?:investigation|diagnosis|check|checks|run|it|that)\b", re.IGNORECASE)
CAPABILITIES = re.compile(r"\b(?:what can you do|what (?:do|can) you help|what do you do|who are you|what are you|how can you help|"
                          r"your capabilities|what (?:tools|checks) (?:do you have|can you run)|how does this work|what can i ask|"
                          r"what are you able to)\b|^help[\s?!.]*$", re.IGNORECASE)
HUMAN_ACTIONS: list[tuple[str, re.Pattern[str]]] = [
    ("remediate", re.compile(r"\b(?:restart|reboot|reload|shut ?down|no shut|bounce|reset|reconfigure|configure|deploy|push|roll ?back|"
                             r"fail ?over|repair|disable|enable|bring (?:it |the [\w-]+ )?(?:up|down)|patch|change the config\w*)\b|"
                             r"^(?:please |can you |could you |go ahead and )?(?:fix|clear)\b|\b(?:can|could|will) you (?:fix|clear|repair)\b",
                             re.IGNORECASE)),
    ("confirm", re.compile(r"\b(?:confirm|approve|accept|record|mark|classify|set)\b.{0,40}\b(?:fault domain|classification|root cause|"
                           r"diagnosis|hypothesis|as (?:wan|routing|dns|dhcp|firewall|switching))\b|^classify\b", re.IGNORECASE)),
    ("save", re.compile(r"\b(?:save|attach|store|add|link)\b.{0,30}\b(?:diagnosis|investigation|results?|findings|it|this|that)\b"
                        r"(?:.{0,30}\b(?:incident|ticket|record)\b)?|^(?:save|attach) (?:it|this|that)\b", re.IGNORECASE)),
    ("escalate", re.compile(r"^(?:please )?(?:escalate|page|notify)\b|\b(?:can|could|should|let'?s|please) (?:you |we )?escalate\b|"
                            r"\bescalate (?:it|this|to)\b|\b(?:raise|open) (?:a |an )?(?:ticket|case) with\b", re.IGNORECASE)),
    ("close", re.compile(r"\b(?:close|resolve)\b.{0,20}\b(?:incident|ticket|it|this)\b", re.IGNORECASE)),
    ("reopen", re.compile(r"\breopen\b", re.IGNORECASE)),
    ("severity", re.compile(r"\b(?:change|set|raise|lower|bump|increase|decrease|update|downgrade|upgrade)\b.{0,20}\bseverity\b", re.IGNORECASE)),
    ("priority", re.compile(r"\b(?:change|set|raise|lower|bump|increase|decrease|update|downgrade|upgrade)\b.{0,20}\bpriority\b", re.IGNORECASE)),
    ("propose", re.compile(r"\b(?:propose|record|log|submit)\b.{0,20}\b(?:resolution|fix)\b", re.IGNORECASE)),
    ("verify", re.compile(r"\bverify\b.{0,20}\b(?:resolution|fix)\b", re.IGNORECASE)),
    ("assign", re.compile(r"\bassign\b.{0,30}\b(?:to|owner|team)\b", re.IGNORECASE)),
]
EXPLAIN = re.compile(r"\b(?:explain|why|how did you|how do you know|what (?:does|did|do) (?:that|this|it|they) mean|what does .{1,30} mean|"
                     r"what (?:is|are) (?:the )?evidence|show (?:me )?(?:the )?evidence|which evidence|supporting evidence|walk me through|"
                     r"reasoning|justify|how confident|why (?:do|did) you think|meaning of|tell me more about|more detail|elaborate)\b",
                     re.IGNORECASE)
EXPLAIN_OBJECT = re.compile(r"\b(?:evidence|findings?|diagnosis|results?|conclusion|hypothesis|root cause|confidence|that|this|it|"
                            r"those|these|them|the (?:fault|path|alternatives?|timeline))\b", re.IGNORECASE)
FULL_DIAGNOSIS = re.compile(
    r"\b(?:diagnose|investigate|troubleshoot|root[- ]?cause (?:it|this|analysis)|(?:find|identify|determine|get|work out) (?:out )?(?:the )?"
    r"(?:root[- ]?cause|cause|problem|issue|fault)|figure (?:it )?out|dig into (?:it|this)|look into (?:it|this|the (?:issue|problem|incident|outage))|"
    r"analy[sz]e (?:it|this|the (?:incident|issue|problem|outage))|(?:run|start|do|perform|kick off|begin|launch|need|want|re-?run)"
    r" (?:a |an |the )?(?:full |complete |new |fresh |another )?(?:diagnos(?:is|tic|e)s?|investigation|root[- ]?cause analysis|analysis)"
    r"(?! of (?:e\d)))\b", re.IGNORECASE)
DEFINITION = re.compile(r"^(?:what(?:'s| is| are| does)|define|explain|tell me about|how (?:do|does|can|should|to|would)|why (?:do|does|would|might|can)|"
                        r"when should|is it (?:normal|possible|safe)|difference between|what'?s the difference)\b", re.IGNORECASE)
KNOWLEDGE = re.compile(r"\b(?:runbooks?|playbooks?|procedures?|best practices?|guides?|documentation|knowledge base|kb|how (?:do i|to|should i) "
                       r"(?:troubleshoot|check|diagnose|verify|fix|handle))\b", re.IGNORECASE)
HOWTO = re.compile(r"^(?:how (?:do|can|should|would|could) (?:i|we|one|you|someone)|how to|what(?:'s| is) the best way to|"
                   r"what steps|which steps)\b", re.IGNORECASE)
STATUS = re.compile(r"\b(?:status|progress|are you (?:done|finished|still)|is it (?:done|finished|running)|where are we|what(?:'s| is) "
                    r"(?:happening|going on)|what have you (?:found|done)|any (?:update|news|progress)|update me|so far|where do we stand)\b",
                    re.IGNORECASE)
INCIDENT_QUERY = re.compile(
    r"\b(?:severity|priority|assigned|owner|who(?:'s| is) (?:working|on|handling)|when (?:was|did)|reported|opened|title|description|"
    r"which sites?|affected (?:sites?|services?|devices?|users|assets)|impact|current diagnosis|root cause|what(?:'s| is) (?:causing|wrong)|"
    r"what happened|summar(?:y|ize|ise)|overview|tell me about (?:the |this )?incident|incident details|about (?:this|the) incident|"
    r"fault domain|escalations?|classification|next steps?|what should (?:i|we) do|recommend\w*|this incident|the incident)\b", re.IGNORECASE)
REQUEST_CUE = re.compile(
    r"(?:^\s*(?:please\s+)?(?:can you\s+|could you\s+|would you\s+|pls\s+)?(?:check|show|look|get|pull|run|verify|inspect|test|tell|what|which|"
    r"is|are|does|do|can|any|how|display|fetch|give|list|see|query|examine|review|ping|trace|traceroute|analy[sz]e|confirm)\b)"
    r"|\?|\b(?:check|show me|verify|inspect|look at|pull up|fetch|analy[sz]e)\b", re.IGNORECASE)
RERUN = re.compile(r"\b(?:again|re-?run|re-?check|refresh|one more time|latest)\b", re.IGNORECASE)
TOPICS: list[tuple[str, re.Pattern[str]]] = [
    ("reachability", re.compile(r"\b(?:reach(?:ability)?|ping|traceroute|trace ?route|path (?:from|to|between)|connectivity (?:from|to|between)|"
                                r"talk to|get to|connect to)\b", re.IGNORECASE)),
    ("firewall", re.compile(r"\b(?:firewall logs?|firewall|denied|deny|denies|blocked|blocking|acl|security polic(?:y|ies))\b", re.IGNORECASE)),
    ("adjacency", re.compile(r"\b(?:ospf|bgp|adjacenc(?:y|ies)|neighbou?rs?|peering|peers?)\b", re.IGNORECASE)),
    ("routing", re.compile(r"\b(?:rout(?:e|es|ing)|routing table|next[- ]hops?|prefix(?:es)?|rib|fib)\b", re.IGNORECASE)),
    ("packet_loss", re.compile(r"\b(?:packet loss|loss|latency|jitter|lossy)\b", re.IGNORECASE)),
    ("errors", re.compile(r"\b(?:crc|interface errors?|input errors?|output errors?|errors on|drops?|discards?)\b", re.IGNORECASE)),
    ("interfaces", re.compile(r"\b(?:interfaces?|ports?|counters?|utili[sz]ation|bandwidth|throughput|stats|statistics)\b", re.IGNORECASE)),
    ("logs", re.compile(r"\b(?:logs?|syslog|log events?)\b", re.IGNORECASE)),
    ("dhcp_dns", re.compile(r"\b(?:dhcp|dns|leases?|name resolution|address pool)\b", re.IGNORECASE)),
    ("dependencies", re.compile(r"\b(?:dependenc(?:y|ies)|upstream|downstream|blast radius|shared (?:devices?|infrastructure)|"
                                r"single points? of failure)\b", re.IGNORECASE)),
    ("topology", re.compile(r"\b(?:topology|inventory|what devices|which devices|devices (?:at|in)|layout|network map)\b", re.IGNORECASE)),
    ("availability", re.compile(r"\b(?:up|down|alive|available|availability|online|offline|health(?:y)?|status|responding|reachable)\b",
                                re.IGNORECASE)),
]
GENERIC_CHECK = re.compile(r"^\s*(?:please\s+)?(?:can you\s+|could you\s+)?(?:check|look at|inspect|examine|test|verify)\b", re.IGNORECASE)
DEVICE_TOPICS = {"routing", "adjacency", "packet_loss", "errors", "interfaces", "logs", "availability"}
INTERFACE_TOPICS = {"packet_loss", "errors"}
SITE_TOPICS = {"dhcp_dns", "topology"}
TOPIC_TOOL = {"routing": "get_routing_state", "adjacency": "analyze_routing_adjacency", "packet_loss": "analyze_packet_loss",
              "errors": "analyze_interface_errors", "interfaces": "get_interface_stats", "logs": "get_device_logs",
              "availability": "check_device_availability", "dhcp_dns": "get_dhcp_dns_status", "topology": "get_topology",
              "dependencies": "analyze_network_dependencies", "reachability": "check_network_reachability",
              "firewall": "get_firewall_logs"}
TOPIC_LABEL = {"routing": "routing state", "adjacency": "routing adjacencies", "packet_loss": "packet loss", "errors": "interface errors",
               "interfaces": "interface statistics", "logs": "device logs", "availability": "device availability",
               "dhcp_dns": "DHCP and DNS status", "topology": "site topology", "dependencies": "network dependencies",
               "reachability": "path reachability", "firewall": "firewall logs"}


def strip_greeting(text: str) -> str:
    return GREETING_PREFIX.sub("", text.strip(), count=1).strip()


def topics_in(text: str) -> list[str]:
    found = [topic for topic, pattern in TOPICS if pattern.search(text)]
    if "routing" in found and "adjacency" in found and not re.search(r"\b(?:routing table|routes?|next[- ]hops?|prefix)\b", text, re.IGNORECASE):
        found.remove("routing")
    if "errors" in found and "logs" in found:
        found.remove("errors")
    if "availability" in found and len(found) > 1:
        found.remove("availability")
    if "interfaces" in found and ("packet_loss" in found or "errors" in found):
        found.remove("interfaces")
    if "firewall" in found and "logs" in found:
        found.remove("logs")
    return found


class Planner:
    """Turns targeted-check topics into concrete tool calls, or names what is missing."""

    def __init__(self, index: TopologyIndex) -> None:
        self.index = index

    def device_for(self, topic: str, entities: Entities, context: ConversationContext) -> str | None:
        if entities.device_ids:
            return entities.device_ids[0]
        if context.focus_device_id and not entities.site_ids:
            return context.focus_device_id
        sites = entities.site_ids or context.site_ids
        if sites and topic in DEVICE_TOPICS:
            return self.index.site_device(sites[0], DeviceRole.WAN_EDGE)
        return None

    def interface_for(self, device_id: str, text: str, entities: Entities) -> tuple[str | None, bool]:
        for raw in entities.interfaces:
            name = self.index.normalize_interface(device_id, raw)
            if name:
                return name, False
        wan = self.index.wan_interface(device_id)
        if wan and (wan_interface_requested(text) or not entities.interfaces):
            return wan, not wan_interface_requested(text)
        return None, False

    def reachability(self, text: str, entities: Entities, context: ConversationContext) -> tuple[dict | None, list[str]]:
        endpoints: list[tuple[int, str]] = []
        for device in entities.device_ids:
            match = re.search(re.escape(device), text, re.IGNORECASE)
            endpoints.append((match.start() if match else 10_000, device))
        for address in entities.ip_addresses:
            endpoints.append((text.find(address), address.split("/")[0]))
        endpoints.sort()
        source = destination = None
        from_match = re.search(r"\bfrom\s+(\S+)", text, re.IGNORECASE)
        to_match = re.search(r"\b(?:to|reach|and)\s+(\S+)", text, re.IGNORECASE)
        for _, value in endpoints:
            if from_match and value.lower() in from_match.group(1).lower().strip("?,.") and source is None:
                source = value
            elif to_match and value.lower() in to_match.group(1).lower().strip("?,.") and destination is None:
                destination = value
        remaining = [value for _, value in endpoints if value not in (source, destination)]
        if source is None and len(endpoints) >= 2 and remaining:
            source = remaining.pop(0)
        if destination is None and remaining:
            destination = remaining.pop(0)
        sites = entities.site_ids or context.site_ids
        if source is None and sites:
            source = self.index.site_device(sites[0], DeviceRole.ACCESS_SWITCH)
        if destination is None:
            for service in entities.services or context.services:
                destination = self.index.service_target(service)
                if destination:
                    break
        missing = [name for name, value in (("source", source), ("destination", destination)) if value is None]
        return ({"source": source, "destination": destination} if not missing else None), missing

    def firewall(self, entities: Entities, context: ConversationContext) -> dict:
        arguments: dict = {}
        addresses = list(entities.ip_addresses)
        sites = entities.site_ids or context.site_ids
        if addresses:
            arguments["destination" if sites else "source"] = addresses[0]
        if sites and "source" not in arguments:
            network = self.index.site_network(sites[0])
            if network:
                arguments["source"] = network
        if len(addresses) > 1 and "destination" not in arguments:
            arguments["destination"] = addresses[1]
        return arguments

    def plan(self, text: str, topics: list[str], entities: Entities,
             context: ConversationContext) -> tuple[list[PlannedCall], list[str], str | None]:
        calls: list[PlannedCall] = []
        missing: list[str] = []
        focus = None
        for topic in topics:
            tool = TOPIC_TOOL[topic]
            label = TOPIC_LABEL[topic]
            if topic == "reachability":
                arguments, gaps = self.reachability(text, entities, context)
                if arguments is None:
                    missing += [f"reachability:{gap}" for gap in gaps]
                    continue
                calls.append(PlannedCall(tool=tool, arguments=arguments,
                                         reason=f"Check the layer-3 path from {arguments['source']} to {arguments['destination']}"))
                continue
            if topic == "firewall":
                arguments = self.firewall(entities, context)
                scope = " and ".join(f"{key} {value}" for key, value in arguments.items()) or "all recorded traffic"
                calls.append(PlannedCall(tool=tool, arguments=arguments, reason=f"Read firewall events for {scope}"))
                continue
            if topic in SITE_TOPICS or (topic == "dependencies" and not entities.device_ids):
                sites = entities.site_ids or context.site_ids
                if not sites:
                    missing.append(f"{topic}:site")
                    continue
                calls.append(PlannedCall(tool=tool, arguments={"site_id": sites[0]}, reason=f"Read the {label} for {sites[0]}"))
                continue
            device = self.device_for(topic, entities, context)
            if device is None:
                missing.append(f"{topic}:device")
                continue
            focus = device
            if topic == "dependencies":
                calls.append(PlannedCall(tool=tool, arguments={"device_id": device}, reason=f"Map dependencies around {device}"))
                continue
            arguments = {"device_id": device}
            reason = f"Read the {label} of {device}"
            if topic in INTERFACE_TOPICS or (topic == "interfaces" and entities.interfaces):
                interface, assumed = self.interface_for(device, text, entities)
                if interface is None and topic in INTERFACE_TOPICS:
                    missing.append(f"{topic}:interface:{device}")
                    continue
                if interface:
                    arguments["interface"] = interface
                    reason = f"Analyse {label} on {device} {interface}" + (" (its only WAN interface)" if assumed else "")
            if topic == "routing" and entities.ip_addresses:
                arguments["prefix"] = entities.ip_addresses[0]
            if topic == "logs" and re.search(r"\b(?:errors? only|only errors?|critical)\b", text, re.IGNORECASE):
                arguments["min_severity"] = "error"
            calls.append(PlannedCall(tool=tool, arguments=arguments, reason=reason))
        unique = list({(c.tool, str(sorted(c.arguments.items()))): c for c in calls}.values())
        return unique[:MAX_PLANNED_CALLS], missing, focus


def human_action_in(text: str) -> str | None:
    for action, pattern in HUMAN_ACTIONS:
        if pattern.search(text):
            if action == "remediate" and re.search(r"\b(?:how (?:do|to|should|can) (?:i|we)|what would|runbook|playbook)\b", text, re.IGNORECASE):
                return None
            return action
    return None


def classify(text: str, context: ConversationContext, index: TopologyIndex) -> IntentResult:
    raw = " ".join(text.split())
    body = strip_greeting(raw)
    entities = extract(body or raw, index)

    def result(intent: Intent, confidence: str = "high", **extra) -> IntentResult:
        return IntentResult(intent=intent, confidence=confidence, source=extra.pop("source", "rules"), entities=entities, **extra)

    if not body:
        return result(Intent.GREETING) if raw else result(Intent.GENERAL, "low")
    if body != raw and GREETING_FILLER.match(body):
        return result(Intent.GREETING)
    if CANCEL.search(body):
        return result(Intent.CANCELLATION)
    if context.pending_action is not None:
        if AFFIRM.search(body) and len(body.split()) <= 8 and not FULL_DIAGNOSIS.search(body):
            return result(Intent.CONFIRMATION, source="pending_action")
        if NEGATE.search(body) and len(body.split()) <= 8:
            return result(Intent.DECLINE, source="pending_action")
    if SMALLTALK.match(body):
        return result(Intent.GREETING)
    if ACKNOWLEDGE.match(body):
        return result(Intent.GENERAL)
    if CAPABILITIES.search(body):
        return result(Intent.CAPABILITIES)
    action = human_action_in(body)
    if action:
        return result(Intent.HUMAN_ACTION, human_action=action)
    if entities.evidence_ids or (EXPLAIN.search(body) and EXPLAIN_OBJECT.search(body)
                                 and not (DEFINITION.search(body) and not EXPLAIN_OBJECT.search(body))
                                 and not FULL_DIAGNOSIS.search(body) and not entities.device_ids):
        return result(Intent.EVIDENCE_EXPLANATION)
    if HOWTO.search(body):
        return result(Intent.KNOWLEDGE)
    if FULL_DIAGNOSIS.search(body):
        return result(Intent.FULL_DIAGNOSIS, rerun=bool(RERUN.search(body)))

    topics = topics_in(body)
    has_target = bool(entities.device_ids or entities.site_ids or entities.interfaces or entities.ip_addresses)
    definition = DEFINITION.search(body) and not has_target
    if not definition and REQUEST_CUE.search(body):
        candidate = [t for t in topics if t != "availability" or entities.device_ids]
        if candidate and (has_target or context.focus_device_id or context.site_ids):
            calls, missing, _ = Planner(index).plan(body, candidate, entities, context)
            if calls or missing:
                return result(Intent.TARGETED_DIAGNOSTIC, topics=candidate, planned_calls=calls, missing=missing,
                              rerun=bool(RERUN.search(body)))
        if entities.device_ids and GENERIC_CHECK.search(body):
            calls, missing, _ = Planner(index).plan(body, ["availability"], entities, context)
            return result(Intent.TARGETED_DIAGNOSTIC, "medium", topics=["availability"], planned_calls=calls, missing=missing,
                          rerun=bool(RERUN.search(body)))
    if KNOWLEDGE.search(body) or (definition and (topics or re.search(r"\b(?:ospf|bgp|vlan|802\.1x|dhcp|dns|wan|mpls|nat|acl|subnet|"
                                                                      r"latency|jitter|crc|mtu|sla)\b", body, re.IGNORECASE))):
        return result(Intent.KNOWLEDGE)
    if STATUS.search(body) and not entities.device_ids:
        return result(Intent.STATUS)
    if INCIDENT_QUERY.search(body) and not entities.symptoms:
        return result(Intent.INCIDENT_QUERY)
    if entities.symptoms or (entities.services and re.search(r"\b(?:problem|issue|trouble|complain\w*|broken|not working|fail\w*)\b",
                                                               body, re.IGNORECASE)):
        return result(Intent.SYMPTOM_REPORT)
    pending = context.pending_clarification
    if pending is not None:
        supplies = bool(entities.scope or entities.services or entities.site_ids or entities.timeframe or entities.device_ids
                        or entities.interfaces or entities.ip_addresses)
        if supplies or len(body.split()) <= 12:
            return result(Intent.CLARIFICATION, "medium", source="pending_clarification", topics=pending.topics)
    if entities.scope or entities.timeframe:
        return result(Intent.CLARIFICATION, "medium")
    if definition:
        return result(Intent.KNOWLEDGE, "medium")
    if INCIDENT_QUERY.search(body):
        return result(Intent.INCIDENT_QUERY, "medium")
    return result(Intent.GENERAL, "low")
