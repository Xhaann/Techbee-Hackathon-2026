"""Deterministic intent classification and targeted-check planning.

The classifier decides *whether* any tool may run. Only three paths lead to tool execution: an explicit diagnosis
request, a check request that names (or clearly implies) a target, and a quick action the user clicked. Greetings,
general conversation, knowledge questions, symptom descriptions and evidence explanations never plan a tool call.
"""
import re

from app.conversation.assist import looks_like_output
from app.conversation.entities import TopologyIndex, extract, wan_interface_requested
from app.conversation.protocol_intents import protocol_request, scan_requested
from app.conversation.models import ConversationContext, Entities, Intent, IntentResult, PlannedCall
from app.network.models import DeviceRole

MAX_PLANNED_CALLS = 4
I = re.IGNORECASE
EMAIL = re.compile(r"\b(?:write|draft|compose|prepare|create|send|need|give me|make)\b.{0,40}\b(?:e-?mails?|mail|message|note|letter)\b|"
                   r"\b(?:e-?mail|message|note|letter)\b.{0,20}\b(?:to|for) (?:the |our )?(?:customers?|clients?|users|end users|stakeholders?|"
                   r"business|management|leadership)\b|\bcustomer (?:e-?mail|communication|comms|notification|message)\b", I)
UPDATE = re.compile(r"\b(?:status|incident|customer|stakeholder|service|progress|comms?) update\b|\bupdate (?:for|to) (?:the |our )?"
                    r"(?:customers?|clients?|users|stakeholders?|business|management|leadership|status page)\b|\bstatus page\b|"
                    r"\b(?:draft|write|prepare|post) (?:an? |the )?(?:incident )?update\b", I)
TROUBLESHOOT = re.compile(r"\bstep[- ]by[- ]step\b|\btroubleshooting (?:steps|guide|plan|procedure|checklist|instructions)\b|"
                          r"\bwalk me through (?:troubleshooting|the (?:steps|troubleshooting|checks)|how to (?:troubleshoot|check|verify))|"
                          r"\bhow (?:do|should|can|would) (?:i|we) (?:troubleshoot|debug|verify|investigate)(?: (?:this|it|that|the issue|the problem))?\b|"
                          r"\bwhat (?:steps|should i check|do i check|checks should i run)\b|\bgive me (?:the |a )?(?:steps|checklist|plan|runbook)\b|"
                          r"\btroubleshoot (?:this|it|that) (?:myself|manually|by hand)\b|\bhow to troubleshoot\b", I)
COMMANDS = re.compile(r"\b(?:what|which) (?:cli |show |read-only )?commands?\b|\bcommands? (?:to|for|i can|should i) (?:run|check|use|verify|see)\b|"
                      r"\b(?:give|show|list|tell|send) (?:me )?(?:the |some )?(?:read-only |cli |show )?commands?\b|\bcli commands?\b", I)
DETAIL = re.compile(r"^(?:(?:can you |could you |please )?(?:tell me more|more details?|more info(?:rmation)?|details|the details|full details|"
                    r"elaborate|expand(?: on (?:that|it))?|go deeper|explain more|show (?:me )?(?:the )?(?:full )?details|full (?:report|explanation|answer)|"
                    r"in detail|the long version|details please))[\s?!.]*$", I)
CONTINUE = re.compile(r"^(?:continue|next|next step|what'?s next|what now|now what|keep going|carry on|go on|and then|then what|"
                      r"move on|next one|(?:ok|okay|done|that'?s done|did that),? (?:next|continue|what'?s next|now what))[\s?!.]*$", I)
STEP_FAILED = re.compile(r"\b(?:step \d+|that|it|the command|this command|the check|that command)\b.{0,30}\b(?:fail(?:ed|s)?|didn'?t work|did not work|"
                         r"doesn'?t work|errored|gave (?:me )?an error|throws an error|isn'?t working|not working)\b|"
                         r"\b(?:got|getting|it says|returns?|shows?) (?:an? )?(?:error|% ?invalid|invalid input|permission denied)\b", I)
SPECIALIST = re.compile(r"\b(?P<agent>routing|security|firewall|dns|dhcp|transport|wan|platform) (?:agent|specialist|expert)\b|"
                        r"\bspecialists?'? (?:view|views|opinion|take|review|verdicts?)\b|\bwhat do (?:the )?specialists (?:think|say)\b", I)
MULTI_AGENT = re.compile(r"\bmulti-?agent\b|\b(?:all|every) (?:of )?(?:the )?(?:specialists|agents)\b|\b(?:get|ask|have) the specialists\b|"
                         r"\bteam (?:investigation|diagnosis)\b|\bsecond opinion\b", I)
TECHNICAL = re.compile(r"^(?:(?:can you |could you |please )?(?:show|give|send)(?: me)? )?(?:the |all the |more )?(?:full )?(?:technical|tech|raw)"
                       r" (?:details?|version|view|data|evidence|breakdown|info(?:rmation)?)(?: please)?[\s?!.]*$", I)
WHAT_HAPPENED = re.compile(r"^(?:so |ok(?:ay)?,? )?(?:what(?:'s| has)? happened|what went wrong|what'?s the (?:story|situation)|catch me up|"
                           r"(?:give me )?(?:a |the )?(?:quick |short )?(?:summary|recap|overview)|summari[sz]e(?: (?:it|this|the incident))?)"
                           r"(?: (?:here|so far|with (?:this|it|the incident)|on (?:this|the) incident))?[\s?!.]*$", I)
BROAD = re.compile(r"\b(?:every|all)(?: (?:single|the|of the))? (?:logs?|devices?|routers?|switches?|firewalls?|interfaces?|sites?|checks?|"
                   r"tools?|links?)\b|\b(?:everything|every single thing)\b|\b(?:entire|whole) network\b", I)
WHY = re.compile(r"^(?:why|why so|how so|how come|how do you know|what makes you (?:say|think) (?:that|so)|why is that|"
                 r"what'?s the evidence|based on what|are you sure)[\s?!.]*$", I)
SAME_FOR = re.compile(r"^(?:and |what about |how about |same (?:for|at|on) |do the same (?:for|at|on) |also (?:for|at|on) |now (?:for|do) )", I)
INTERNAL = re.compile(r"\b(?:internal|team|management|stakeholders?|engineers?|leadership|exec\w*|noc|colleagues?)\b", I)
FORMAL = re.compile(r"\b(?:formal|professional|polite)\b", I)
FRIENDLY = re.compile(r"\b(?:friendly|casual|warm|informal|less formal)\b", I)
STEP_NUMBER = re.compile(r"\bstep (\d{1,2})\b", I)
AGENT_NAME = {"routing": "routing", "security": "security", "firewall": "security", "dns": "dns_dhcp", "dhcp": "dns_dhcp",
              "transport": "transport", "wan": "transport", "platform": "transport"}

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
    r"fault domain|escalations?|classification|next steps?|what should (?:i|we) do|recommend\w*|this incident|the incident|"
    r"root (?:issue|problem)|(?:main|real|actual|underlying) (?:issue|problem|cause)|what(?:'s| is) the (?:problem|issue|cause)|"
    r"(?:is|has) (?:this|it|that|the (?:diagnosis|cause|root cause|hypothesis|finding|fault|problem))(?: been)? (?:confirmed|verified)|"
    r"confirmed yet|anyone confirmed)\b", re.IGNORECASE)
REQUEST_CUE = re.compile(
    r"(?:^\s*(?:please\s+)?(?:can you\s+|could you\s+|would you\s+|pls\s+)?(?:check|show|look|get|pull|run|verify|inspect|test|tell|what|which|"
    r"is|are|does|do|can|any|how|display|fetch|give|list|see|query|examine|review|ping|trace|traceroute|analy[sz]e|confirm)\b)"
    r"|\?|\b(?:check|show me|verify|inspect|look at|pull up|fetch|analy[sz]e)\b", re.IGNORECASE)
RERUN = re.compile(r"\b(?:again|re-?run|re-?check|refresh|one more time|latest)\b", re.IGNORECASE)
TOPICS: list[tuple[str, re.Pattern[str]]] = [
    ("journey", re.compile(r"\b(?:packet journey|trace (?:a |the )?packets?|hop[- ]by[- ]hop|journey of|follow (?:a |the )?packet)\b",
                           re.IGNORECASE)),
    ("health_score", re.compile(r"\b(?:health ?scores?|network health|site health|how healthy|health of (?:the )?(?:network|site|sites)|"
                                r"healthiest|least healthy|overall health)\b", re.IGNORECASE)),
    ("drift", re.compile(r"\b(?:config(?:uration)? drift|drift(?:ed)?|golden config\w*|out of compliance|config(?:uration)? compliance|"
                         r"differs? from (?:the )?(?:golden|baseline|standard))\b", re.IGNORECASE)),
    # Explicit traffic-analysis requests only: "which application is down?" stays a symptom report, as before.
    ("traffic", re.compile(r"\b(?:traffic flows?|netflow|ipfix|flow records?|top talkers?|traffic (?:mix|matrix|analysis|breakdown)|"
                           r"application mix|who is using (?:the |our )?bandwidth|bandwidth hogs?)\b", re.IGNORECASE)),
    ("capacity", re.compile(r"\b(?:capacity|forecast\w*|congestion (?:risk|forecast|prediction)|will (?:it|the \w+(?: \w+)?) (?:congest|saturate)|"
                            r"saturat\w*|headroom|run out of bandwidth|utili[sz]ation trend|growth trend)\b", re.IGNORECASE)),
    ("path_health", re.compile(r"\b(?:path health|end[- ]to[- ]end|whole path|every link|each link|along the path|links? on the path)\b",
                               re.IGNORECASE)),
    ("timeline", re.compile(r"\b(?:timeline|what happened|event history|outage history|flapp?\w*|came back|recovered|earlier today|"
                            r"went down and|history of)\b", re.IGNORECASE)),
    ("changes", re.compile(r"\b(?:what changed|who changed|anything changed|any changes|recent changes?|config(?:uration)? changes?|"
                           r"change history|change log|changes on|changes at|helper[- ]address)\b", re.IGNORECASE)),
    ("reachability", re.compile(r"\b(?:reach(?:ability)?|ping|traceroute|trace ?route|path (?:from|to|between)|connectivity (?:from|to|between)|"
                                r"talk to|get to|connect to)\b", re.IGNORECASE)),
    ("firewall", re.compile(r"\b(?:firewall logs?|firewall|denied|deny|denies|blocked|blocking|acl|security polic(?:y|ies))\b", re.IGNORECASE)),
    ("adjacency", re.compile(r"\b(?:ospf|bgp|adjacenc(?:y|ies)|neighbou?rs?|peering|peers?)\b", re.IGNORECASE)),
    ("routing", re.compile(r"\b(?:rout(?:e|es|ing)|routing table|next[- ]hops?|prefix(?:es)?|rib|fib)\b", re.IGNORECASE)),
    ("packet_loss", re.compile(r"\b(?:packet loss|loss|latency|jitter|lossy|(?:dropping|dropped|losing|lost) packets|"
                               r"packets? (?:are |being )?(?:dropped|dropping|lost))\b", re.IGNORECASE)),
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
HYPOTHESIS_DOMAINS: list[tuple[str, re.Pattern[str]]] = [
    ("firewall", re.compile(r"\b(?:the )?(?:firewall|acl|security polic(?:y|ies)|fw)\b", re.IGNORECASE)),
    ("dns", re.compile(r"\b(?:dns|name resolution|resolver)\b", re.IGNORECASE)),
    ("dhcp", re.compile(r"\b(?:dhcp|ip address(?:ing)?|address pool)\b", re.IGNORECASE)),
    ("vlan_authentication", re.compile(r"\b(?:802\.1x|dot1x|radius|authentication|nac)\b", re.IGNORECASE)),
    ("routing", re.compile(r"\b(?:routing|ospf|bgp|routes?|adjacenc(?:y|ies))\b", re.IGNORECASE)),
    ("wan_isp", re.compile(r"\b(?:wan|isp|carrier|circuit|provider)\b", re.IGNORECASE)),
    ("shared_infrastructure", re.compile(r"\b(?:core|shared (?:device|infrastructure|upstream))\b", re.IGNORECASE)),
    ("network_device_failure", re.compile(r"\b(?:hardware|device failure|router (?:failure|died|crashed)|power)\b", re.IGNORECASE)),
    ("interface_link", re.compile(r"\b(?:cable|fib(?:re|er)|optic\w*|interface|physical link|link)\b", re.IGNORECASE)),
    ("switching", re.compile(r"\b(?:switch(?:ing)?|vlan|stp|spanning tree)\b", re.IGNORECASE)),
]
HYPOTHESIS = re.compile(
    r"^(?:so\s+|but\s+|and\s+)?(?:(?:is|was|could|would|might|can)\s+(?:it|this|that|the (?:problem|issue|cause))\s+(?:be\s+)?"
    r"(?:caused by\s+|due to\s+|because of\s+)?(?:the\s+|a\s+|an\s+)?(?:\w+\s+){0,2}?"
    r"|what about\s+(?:the\s+)?|how about\s+(?:the\s+)?|(?:are you sure|sure)\s+it'?s\s+not\s+(?:the\s+)?"
    r"|(?:could|might|can)\s+(?:the\s+)?(?=\w+(?:\s+\w+)?\s+be\s+(?:the\s+)?(?:cause|problem|issue|culprit))"
    r"|(?:is|are)\s+(?:the\s+)?(?=\w+(?:\s+\w+)?\s+(?:the\s+)?(?:cause|problem|issue|culprit|to blame)))", re.IGNORECASE)
FOLLOW_UP_CHECK = re.compile(r"\b(?:check|look|do|run|try)(?: (?:that|it|the same))? (?:there|that one|them|those)(?: too| as well)?\b|"
                             r"\b(?:same|that) (?:check|thing) (?:for|at|on)\b|\b(?:there|for (?:them|it)) (?:too|as well)\b", re.IGNORECASE)
USER_REPORT = re.compile(r"\b(?:users?|staff|people|employees|they|everyone|nobody|complain\w*|report\w*)\b", re.IGNORECASE)
GENERIC_CHECK = re.compile(r"^\s*(?:please\s+)?(?:can you\s+|could you\s+)?(?:check|look at|inspect|examine|test|verify)\b", re.IGNORECASE)
DEVICE_TOPICS = {"routing", "adjacency", "packet_loss", "errors", "interfaces", "logs", "availability"}
INTERFACE_TOPICS = {"packet_loss", "errors"}
SITE_TOPICS = {"dhcp_dns", "topology"}
NETWORK_WIDE_TOPICS = {"health_score", "drift", "capacity", "traffic"}  # answerable for the whole network without a target
TOPIC_TOOL = {"routing": "get_routing_state", "adjacency": "analyze_routing_adjacency", "packet_loss": "analyze_packet_loss",
              "errors": "analyze_interface_errors", "interfaces": "get_interface_stats", "logs": "get_device_logs",
              "availability": "check_device_availability", "dhcp_dns": "get_dhcp_dns_status", "topology": "get_topology",
              "dependencies": "analyze_network_dependencies", "reachability": "check_network_reachability",
              "firewall": "get_firewall_logs", "path_health": "analyze_path_health", "timeline": "get_event_timeline",
              "changes": "get_change_history", "health_score": "get_network_health", "drift": "get_config_drift",
              "traffic": "analyze_traffic_flows", "journey": "trace_packet", "capacity": "forecast_capacity"}
TOPIC_LABEL = {"routing": "routing state", "adjacency": "routing adjacencies", "packet_loss": "packet loss", "errors": "interface errors",
               "interfaces": "interface statistics", "logs": "device logs", "availability": "device availability",
               "dhcp_dns": "DHCP and DNS status", "topology": "site topology", "dependencies": "network dependencies",
               "reachability": "path reachability", "firewall": "firewall logs", "path_health": "path health",
               "timeline": "event timeline", "changes": "change history", "health_score": "health scores",
               "drift": "configuration drift", "traffic": "traffic flows", "journey": "packet journey", "capacity": "capacity forecast"}
SERVICE_PORTS = {"application": ("tcp", 443), "dns": ("udp", 53), "dhcp": ("udp", 67), "authentication": ("udp", 1812),
                 "internet": ("tcp", 443)}
PORT = re.compile(r"\b(?:port|tcp|udp)[ /:]?(\d{1,5})\b", re.IGNORECASE)


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
    if "path_health" in found:
        found = [topic for topic in found if topic not in ("reachability", "packet_loss", "errors", "interfaces")]
    if ("timeline" in found or "changes" in found) and "availability" in found:
        found.remove("availability")
    if "journey" in found:
        found = [topic for topic in found if topic not in ("reachability", "path_health", "firewall", "interfaces")]
    if "health_score" in found:
        found = [topic for topic in found if topic not in ("availability", "path_health")]
    if "drift" in found and "changes" in found:
        found.remove("changes")
    if "traffic" in found and "interfaces" in found:
        found.remove("interfaces")
    if "capacity" in found:
        found = [topic for topic in found if topic not in ("interfaces", "packet_loss")]
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
        if "source" in arguments and "destination" not in arguments:
            # The flow users care about: from the site to the service they named (internal applications by default).
            services = list(entities.services or context.services) + ["application"]
            target = next((self.index.service_target(service) for service in services if self.index.service_target(service)), None)
            device = self.index.devices.get(target) if target else None
            if device is not None:
                arguments["destination"] = str(device.management_ip)
        return arguments

    def plan(self, text: str, topics: list[str], entities: Entities,
             context: ConversationContext) -> tuple[list[PlannedCall], list[str], str | None]:
        calls: list[PlannedCall] = []
        missing: list[str] = []
        focus = None
        for topic in topics:
            tool = TOPIC_TOOL[topic]
            label = TOPIC_LABEL[topic]
            if topic in ("timeline", "changes"):
                device = entities.device_ids[0] if entities.device_ids else (
                    context.focus_device_id if context.focus_device_id and not entities.site_ids else None)
                sites = entities.site_ids or context.site_ids
                arguments = {"device_id": device} if device else {"site_id": sites[0]} if sites else ({} if topic == "changes" else None)
                if arguments is None:
                    missing.append(f"{topic}:site")
                    continue
                scope = arguments.get("device_id") or arguments.get("site_id") or "the whole network"
                calls.append(PlannedCall(tool=tool, arguments=arguments, reason=f"Read the {label} for {scope}"))
                continue
            if topic in ("health_score", "drift", "capacity", "traffic"):
                device = entities.device_ids[0] if entities.device_ids and topic in ("health_score", "drift") else None
                sites = entities.site_ids or context.site_ids
                arguments = {"device_id": device} if device else ({"site_id": sites[0]} if sites else {})
                if topic == "traffic":
                    service = next((s for s in entities.services or context.services if s in SERVICE_PORTS), None)
                    arguments = {k: v for k, v in (("site_id", sites[0] if sites else None), ("service", service)) if v}
                scope = arguments.get("device_id") or arguments.get("site_id") or "the whole network"
                calls.append(PlannedCall(tool=tool, arguments=arguments, reason=f"Read the {label} for {scope}"))
                continue
            if topic == "journey":
                arguments, gaps = self.reachability(text, entities, context)
                if arguments is None:
                    missing += [f"reachability:{gap}" for gap in gaps]
                    continue
                service = next((s for s in entities.services or context.services if s in SERVICE_PORTS), "application")
                protocol, port = SERVICE_PORTS[service]
                if match := PORT.search(text):
                    port = int(match.group(1)) if 0 < int(match.group(1)) <= 65535 else port
                if re.search(r"\budp\b", text, re.IGNORECASE):
                    protocol = "udp"
                elif re.search(r"\btcp\b", text, re.IGNORECASE):
                    protocol = "tcp"
                arguments |= {"protocol": protocol, "port": port}
                calls.append(PlannedCall(tool=tool, arguments=arguments, reason=f"Trace a {protocol}/{port} packet from "
                                         f"{arguments['source']} to {arguments['destination']} hop by hop"))
                continue
            if topic in ("reachability", "path_health"):
                arguments, gaps = self.reachability(text, entities, context)
                if arguments is None:
                    missing += [f"reachability:{gap}" for gap in gaps]
                    continue
                verb = "Check every link on the path" if topic == "path_health" else "Check the layer-3 path"
                calls.append(PlannedCall(tool=tool, arguments=arguments,
                                         reason=f"{verb} from {arguments['source']} to {arguments['destination']}"))
                continue
            if topic == "firewall":
                arguments = self.firewall(entities, context)
                if not arguments:
                    missing.append("firewall:site")
                    continue
                scope = " to ".join(str(arguments[key]) for key in ("source", "destination") if key in arguments)
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


def hypothesis_in(text: str) -> str | None:
    """The fault domain a user is asking about ("is it the firewall?", "could DNS be the cause?"), if any."""
    if not HYPOTHESIS.search(text) or re.search(r"\b(?:check|show|run|analy[sz]e|pull)\b", text, re.IGNORECASE):
        return None
    return next((domain for domain, pattern in HYPOTHESIS_DOMAINS if pattern.search(text)), None)


def tone_of(text: str) -> str | None:
    return "formal" if FORMAL.search(text) else "friendly" if FRIENDLY.search(text) else None


def step_number(text: str, context: ConversationContext) -> int | None:
    match = STEP_NUMBER.search(text)
    if match:
        return int(match.group(1))
    if context.guide:
        return max(1, context.guide.get("current", 0))
    return None


def supplies_context(entities: Entities, text: str) -> bool:
    """A short reply that mostly names where or what ("New York and Singapore", "the ERP at Bengaluru")."""
    named = entities.site_ids or entities.device_ids or entities.services or entities.unaffected_site_ids
    return bool(named) and len(text.split()) <= 12


def classify(text: str, context: ConversationContext, index: TopologyIndex) -> IntentResult:
    raw = " ".join(text.split())
    body = strip_greeting(raw)
    entities = extract(body or raw, index)

    def result(intent: Intent, confidence: str = "high", **extra) -> IntentResult:
        return IntentResult(intent=intent, confidence=confidence, source=extra.pop("source", "rules"), entities=entities, **extra)

    if not body:
        return result(Intent.GREETING) if raw else result(Intent.GENERAL, "low")
    if looks_like_output(text):
        # Pasted device output is data to read, never instructions; it is checked before anything else.
        return result(Intent.STEP_FAILED if STEP_FAILED.search(text) and context.guide else Intent.OUTPUT_INTERPRETATION,
                      step=step_number(text, context))
    if body != raw and GREETING_FILLER.match(body):
        return result(Intent.GREETING)
    if CANCEL.search(body):
        return result(Intent.CANCELLATION)
    if context.pending_action is not None:
        if (AFFIRM.search(body) or CONTINUE.match(body)) and len(body.split()) <= 8 and not FULL_DIAGNOSIS.search(body):
            return result(Intent.CONFIRMATION, source="pending_action")
        if NEGATE.search(body) and len(body.split()) <= 8:
            return result(Intent.DECLINE, source="pending_action")
    if DETAIL.match(body) or TECHNICAL.match(body):
        return result(Intent.DETAIL)
    if WHY.match(body):
        return result(Intent.EVIDENCE_EXPLANATION)
    if CONTINUE.match(body):
        return result(Intent.CONTINUE)
    if STEP_FAILED.search(body) and (context.guide or STEP_NUMBER.search(body)):
        return result(Intent.STEP_FAILED, step=step_number(body, context))
    if EMAIL.search(body) and not re.search(r"\bupdate\b", body, re.I) or (EMAIL.search(body) and re.search(r"\be-?mail\b", body, re.I)):
        return result(Intent.CUSTOMER_EMAIL, audience="internal" if INTERNAL.search(body) else "customer", tone=tone_of(body))
    if UPDATE.search(body):
        return result(Intent.CUSTOMER_UPDATE, audience="internal" if INTERNAL.search(body) else "customer", tone=tone_of(body))
    if context.last_intent in ("customer_email", "customer_update") and (FORMAL.search(body) or FRIENDLY.search(body)
                                                                         or re.search(r"\b(?:shorter|internal|for the team)\b", body, re.I)):
        return result(Intent(context.last_intent), audience="internal" if INTERNAL.search(body) else None, tone=tone_of(body))
    if MULTI_AGENT.search(body):
        return result(Intent.MULTI_AGENT, rerun=bool(RERUN.search(body)))
    specialist = SPECIALIST.search(body)
    if specialist:
        return result(Intent.SPECIALIST_REVIEW, specialist=AGENT_NAME.get((specialist.group("agent") or "").lower()))
    if SMALLTALK.match(body):
        return result(Intent.GREETING)
    if ACKNOWLEDGE.match(body):
        return result(Intent.GENERAL)
    if CAPABILITIES.search(body):
        return result(Intent.CAPABILITIES)
    action = human_action_in(body)
    if action and not (TROUBLESHOOT.search(body) or COMMANDS.search(body)):
        return result(Intent.HUMAN_ACTION, human_action=action)
    grounded = bool(context.incident_id or context.site_ids or context.last_investigation_id or entities.site_ids or entities.device_ids)
    if TROUBLESHOOT.search(body) and grounded:
        return result(Intent.TROUBLESHOOTING)
    if COMMANDS.search(body) and (grounded or entities.device_ids):
        return result(Intent.COMMANDS)
    if scan_requested(body):
        return result(Intent.PROTOCOL_CHECK, protocols=["traffic"], scan_refused=True)
    protocols = protocol_request(body)
    if protocols:
        return result(Intent.PROTOCOL_CHECK, protocols=protocols, rerun=bool(RERUN.search(body)))
    hypothesis = hypothesis_in(body)
    if hypothesis and not entities.device_ids:
        return result(Intent.HYPOTHESIS_CHECK, topics=[hypothesis], hypothesis=hypothesis)
    if entities.evidence_ids or (EXPLAIN.search(body) and EXPLAIN_OBJECT.search(body)
                                 and not (DEFINITION.search(body) and not EXPLAIN_OBJECT.search(body))
                                 and not FULL_DIAGNOSIS.search(body) and not entities.device_ids):
        return result(Intent.EVIDENCE_EXPLANATION)
    if HOWTO.search(body):
        return result(Intent.KNOWLEDGE)
    if FULL_DIAGNOSIS.search(body):
        return result(Intent.FULL_DIAGNOSIS, rerun=bool(RERUN.search(body)))

    if context.incident_id and WHAT_HAPPENED.match(body) and not (entities.device_ids or entities.site_ids):
        return result(Intent.INCIDENT_QUERY)
    topics = topics_in(body)
    has_target = bool(entities.device_ids or entities.site_ids or entities.interfaces or entities.ip_addresses)
    if BROAD.search(body) and (REQUEST_CUE.search(body) or GENERIC_CHECK.search(body)):
        broad_topics = [t for t in topics if t != "availability"] or (["availability"] if "availability" in topics else [])
        if broad_topics:
            return result(Intent.TARGETED_DIAGNOSTIC, "medium", topics=broad_topics[:1], broad=True)
    if SAME_FOR.match(body) and has_target and not topics:
        if context.last_intent == "troubleshooting":
            return result(Intent.TROUBLESHOOTING, source="rules")
        if context.last_intent == "commands":
            return result(Intent.COMMANDS)
        if context.last_topics and context.last_intent == "targeted_diagnostic":
            calls, missing, _ = Planner(index).plan(body, list(context.last_topics), entities, context)
            if calls or missing:
                return result(Intent.TARGETED_DIAGNOSTIC, topics=list(context.last_topics), planned_calls=calls, missing=missing)
    if not topics and context.last_topics and has_target and (FOLLOW_UP_CHECK.search(body) or GENERIC_CHECK.search(body)):
        topics = list(context.last_topics)
    definition = DEFINITION.search(body) and not has_target
    if not definition and REQUEST_CUE.search(body):
        candidate = [t for t in topics if t != "availability" or entities.device_ids]
        if candidate and (has_target or context.focus_device_id or context.site_ids or set(candidate) & NETWORK_WIDE_TOPICS):
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
    if supplies_context(entities, body):
        return result(Intent.CLARIFICATION, "medium", source="rules")
    if definition:
        return result(Intent.KNOWLEDGE, "medium")
    if INCIDENT_QUERY.search(body):
        return result(Intent.INCIDENT_QUERY, "medium")
    return result(Intent.GENERAL, "low")
