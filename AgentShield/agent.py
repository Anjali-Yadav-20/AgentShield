"""
agent.py
Local AI-agent abstraction protected by AgentShield.

Pipeline enforced here:
    USER -> AGENT -> AGENTSHIELD SECURITY GATE -> POLICY ENGINE -> SAFE TOOL -> RESULT

The agent NEVER executes operating-system commands and NEVER lets tool
content bypass the security engine. Ollama (if available) is used only
for optional natural-language explanation, never for authorization
decisions.
"""

import json
import urllib.request

from security_engine import PolicyEngine
from database import log_event

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3.2:3b"

# A tiny local sandbox used by the safe simulated tools (no real filesystem risk).
_SANDBOX = {
    "public_notes.txt": "Team meeting notes: project demo on Friday.",
    "sensitive_internal.txt": "Quarterly salary review draft (CONFIDENTIAL).",
}
_KNOWLEDGE_BASE = [
    "AgentShield enforces trust boundaries between agents and tools.",
    "Prompt injection is a top risk for LLM-integrated applications.",
    "Least privilege limits what a compromised agent can do.",
]


def is_ollama_available() -> bool:
    try:
        req = urllib.request.Request(
            "http://localhost:11434/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=1.5):
            return True
    except Exception:
        return False


def ask_ollama(prompt: str) -> str:
    """Best-effort call to a local Ollama model. Never raises on failure."""
    try:
        payload = json.dumps({
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
        }).encode("utf-8")
        req = urllib.request.Request(
            OLLAMA_URL, data=payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("response", "").strip()
    except Exception:
        return "Ollama unavailable — deterministic security engine is active."


class LocalAgent:
    """A small local agent that only acts through the AgentShield gate."""

    def __init__(self):
        self.shield = PolicyEngine()

    # -- tool implementations (safe, simulated, non-destructive) ---------
    def _run_tool(self, tool_name: str, request_text: str) -> str:
        if tool_name == "read_public_file":
            return _SANDBOX.get("public_notes.txt", "(file not found)")
        if tool_name == "read_sensitive_file":
            return _SANDBOX.get("sensitive_internal.txt", "(file not found)")
        if tool_name == "create_report":
            return f"[report created] Summary of request: {request_text[:80]}"
        if tool_name == "search_local_knowledge":
            hits = [k for k in _KNOWLEDGE_BASE if any(
                w.lower() in k.lower() for w in request_text.split())]
            return "\n".join(hits) if hits else "No matching local knowledge found."
        if tool_name == "execute_safe_demo_action":
            return "[demo action executed safely — no system changes made]"
        return "(unrecognized tool)"

    def handle_request(self, user_instruction: str, external_content: str = "",
                        external_source: str = "EXTERNAL_DOCUMENT",
                        tool_name: str = "", use_llm: bool = False,
                        scenario_name: str = "") -> dict:
        """
        Main agent entry point.
        1) Inspect the trusted user instruction.
        2) Inspect any untrusted external content SEPARATELY.
        3) If a tool is requested, route it through the security gate.
        4) Never let external content elevate its own trust.
        """
        user_inspection = self.shield.inspect_content(user_instruction, "USER")
        ext_inspection = None
        if external_content:
            ext_inspection = self.shield.inspect_content(external_content, external_source)

        combined_action = user_inspection["final_action"]
        if ext_inspection and ext_inspection["final_action"] in ("BLOCK", "REVIEW"):
            # External content risk can only ever restrict, never grant trust.
            if ext_inspection["final_action"] == "BLOCK":
                combined_action = "BLOCK"
            elif combined_action == "ALLOW":
                combined_action = "REVIEW"

        tool_result = None
        if tool_name:
            source_for_tool = "USER"
            text_for_tool = user_instruction
            # If the tool request text actually originates from untrusted content
            # (e.g. the document told the agent to run a tool), evaluate it as such.
            if ext_inspection and ext_inspection["injection"]["detected"]:
                source_for_tool = external_source
                text_for_tool = external_content
            tool_eval = self.shield.evaluate_tool_request(tool_name, text_for_tool, source_for_tool)
            decision = tool_eval["tool_decision"]
            output = self._run_tool(tool_name, user_instruction) if decision == "ALLOW" else \
                f"Action '{tool_name}' was {decision} by AgentShield: {tool_eval['tool_reason']}"
            tool_result = {
                "tool_name": tool_name,
                "decision": decision,
                "reason": tool_eval["tool_reason"],
                "output": output,
            }
            log_event(source_for_tool, "TOOL_REQUEST", ext_inspection["injection"]["risk_score"]
                      if source_for_tool != "USER" else user_inspection["injection"]["risk_score"],
                      ext_inspection["injection"]["severity"] if source_for_tool != "USER"
                      else user_inspection["injection"]["severity"],
                      decision, tool_eval["tool_reason"], tool_name, scenario_name)
        else:
            log_event("USER", "CONTENT_INSPECTION", user_inspection["injection"]["risk_score"],
                       user_inspection["injection"]["severity"], combined_action,
                       "; ".join(user_inspection["injection"]["reasons"][:2]), "", scenario_name)
            if ext_inspection:
                log_event(external_source, "EXTERNAL_CONTENT_INSPECTION",
                           ext_inspection["injection"]["risk_score"],
                           ext_inspection["injection"]["severity"], ext_inspection["final_action"],
                           "; ".join(ext_inspection["injection"]["reasons"][:2]), "", scenario_name)

        explanation = None
        if use_llm:
            prompt = (f"In one short sentence, explain to a non-technical user why an AI "
                      f"security gate might take the action '{combined_action}' for a request "
                      f"with risk indicators: {user_inspection['injection']['reasons'][:2]}.")
            explanation = ask_ollama(prompt)

        return {
            "user_inspection": user_inspection,
            "external_inspection": ext_inspection,
            "final_action": combined_action,
            "tool_result": tool_result,
            "llm_explanation": explanation,
        }
