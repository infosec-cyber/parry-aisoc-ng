# Parry SOC Commander — runs ON Guild.ai (control plane), not locally.
#
# Deploy:
#   npm i -g @guildai/cli && guild auth login
#   guild agent init --name parry-commander --agent-type langgraph
#   (copy this file over graph.py; langgraph.json -> ./graph.py:graph)
#   guild agent test && guild agent save --message "v1" --wait --publish
#   Create an API trigger key in the console; put the sessions URL + key in .env
#
# The blue agent POSTs a critical detection (JSON) as the session input; the
# commander adjudicates and returns an incident report. Guild session logs are
# the tamper-evident audit trail of every response decision.
#
# Guild sandbox rules honored: only langchain/langgraph/guildai_langchain,
# no network, model via guild_model() proxy.

from guildai_langchain import guild_model
from langchain.agents import create_agent

SYSTEM = """You are the Parry SOC Commander, the human-accountable decision
layer of an autonomous defense system. You receive one CRITICAL detection as
JSON: technique, source IP, evidence flow ids, narrative, and the verified
playbook excerpt the defender cited (ground truth from Senso).

Return a structured incident report:
1. VERDICT: confirm / downgrade (with reason) — be skeptical, check the
   evidence actually supports the technique claimed.
2. ACTIONS: approve or veto the proposed containment (IP block), and list
   follow-ups (password rotation, patch review) per the cited playbook.
3. REPORT: 3-sentence incident summary a CISO can read.
Keep it under 200 words. Never invent evidence not present in the input."""

graph = create_agent(guild_model(), tools=[], system_prompt=SYSTEM)
