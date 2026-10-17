"""
security_engine.py
AgentShield core security engine.

Implements:
  - PromptInjectionDetector : heuristic, weighted, multi-category detector
  - TrustAnalyzer           : classifies content source trust levels
  - SensitiveDataGuard      : detects sensitive data patterns
  - ToolAuthorizationEngine : evaluates tool/action requests against policy
  - PolicyEngine            : ties everything together into ALLOW/BLOCK/REVIEW

Design principle: untrusted content must NEVER automatically become a
trusted instruction. All decisions are deterministic and rule-based -
no black-box "trust me" logic.
"""

import json
import os
import re

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
POLICY_PATH = os.path.join(BASE_DIR, "policies.json")

# --------------------------------------------------------------------------
# Trust levels (higher = more trusted)
# --------------------------------------------------------------------------
TRUST_LEVELS = {
    "SYSTEM": 100,
    "USER": 80,
    "TRUSTED_TOOL": 60,
    "WEB_CONTENT": 20,
    "EXTERNAL_DOCUMENT": 20,
    "UNKNOWN": 10,
}

SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _load_policies():
    """Load policies.json; fall back to safe built-in defaults if missing/broken."""
    default = {
        "risk_thresholds": {"LOW": 0, "MEDIUM": 25, "HIGH": 45, "CRITICAL": 70},
        "tool_risk": {
            "read_public_file": "LOW",
            "create_report": "LOW",
            "search_local_knowledge": "LOW",
            "read_sensitive_file": "HIGH",
            "execute_safe_demo_action": "MEDIUM",
            "arbitrary_command_execution": "BLOCKED",
        },
        "untrusted_sources": ["EXTERNAL_DOCUMENT", "WEB_CONTENT", "UNKNOWN"],
    }
    try:
        with open(POLICY_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        for k, v in default.items():
            data.setdefault(k, v)
        return data
    except (FileNotFoundError, json.JSONDecodeError):
        return default


POLICIES = _load_policies()


# --------------------------------------------------------------------------
# A. Prompt Injection Detector
# --------------------------------------------------------------------------
class PromptInjectionDetector:
    """
    Multi-category weighted heuristic detector. Each category contributes a
    weighted score if matched; the total score maps to a severity band and
    a recommended action. No single keyword decides the outcome.
    """

    # category -> (weight, [compiled regex patterns])
    CATEGORIES = {
        "instruction_override": (40, [
            r"\bignore (all |any |the )?(previous|prior|above|earlier) instructions?\b",
            r"\bdisregard (all |the )?(previous|prior|above) (instructions?|rules?)\b",
            r"\bforget (all |the )?(previous|prior|above) instructions?\b",
            r"\boverride (the )?(system|previous) (prompt|instructions?)\b",
        ]),
        "role_manipulation": (30, [
            r"\byou are now\b",
            r"\bact as (an?|the) (unrestricted|jailbroken|different)\b",
            r"\bpretend (to be|you are)\b",
            r"\benter (developer|dan|debug|god) mode\b",
            r"\bfrom now on you (are|will)\b",
        ]),
        "system_prompt_extraction": (35, [
            r"\breveal (your |the )?(system prompt|hidden instructions?|configuration)\b",
            r"\bshow me your (system prompt|instructions?|rules)\b",
            r"\bwhat (are|were) your (original |initial )?instructions?\b",
            r"\bprint (your |the )?system prompt\b",
            r"\brepeat (the )?(text|words) above\b",
        ]),
        "instruction_hierarchy_attack": (40, [
            r"\bthis (document|content|file|page) (is|contains|overrides).*(instruction|command)\b",
            r"\bnew (system|admin|priority) instructions?\b",
            r"\bthe (real|actual|true) instructions? (are|is)\b",
            r"\battention (ai|assistant|agent):",
        ]),
        "unauthorized_tool_action": (40, [
            r"\bdelete (all|every|the) files?\b",
            r"\b(send|email) (this|the|all) (data|file|document|password|secret)s? to\b",
            r"\bexecute (this )?command\b",
            r"\brun (this )?shell\b",
            r"\bexfiltrate\b",
            r"\bgrant (yourself |me )?(admin|root|full) (access|privileges?)\b",
            r"\bdisable (security|logging|monitoring)\b",
        ]),
        "encoded_obfuscation": (35, [
            r"base64:",
            r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){3,}",
            r"[A-Za-z0-9+/]{40,}={0,2}",  # long base64-looking blob
            r"\bdecode (this|the following) and (execute|run|follow)\b",
        ]),
        "authority_coercion": (20, [
            r"\bthis is (an? )?(urgent|emergency|critical) (override|order)\b",
            r"\bi am (the|your) (developer|administrator|creator)\b",
            r"\bfor (testing|debugging) purposes,? (ignore|bypass|skip)\b",
        ]),
    }

    def analyze(self, text: str, source: str = "UNKNOWN", trust_score: int = 10) -> dict:
        text_l = (text or "").lower()
        reasons = []
        score = 0

        for category, (weight, patterns) in self.CATEGORIES.items():
            for pattern in patterns:
                if re.search(pattern, text_l, re.IGNORECASE):
                    score += weight
                    reasons.append(f"[{category}] matched pattern indicating suspicious intent")
                    break  # count each category at most once

        # Contextual trust adjustment: same content from an untrusted source
        # is inherently more dangerous because the agent has no reason to
        # obey it. Reduce risk slightly for high-trust sources issuing
        # imperative language (normal user commands), amplify for untrusted.
        if source in POLICIES["untrusted_sources"] and score > 0:
            score = int(score * 1.3)
            reasons.append(f"content originates from untrusted source '{source}' — amplifying risk")
        elif source in ("USER", "SYSTEM") and score > 0:
            score = int(score * 0.9)

        score = min(score, 100)
        severity = self._severity_for(score)
        detected = score >= POLICIES["risk_thresholds"]["MEDIUM"]
        action = self._recommend_action(severity, source)

        if not reasons:
            reasons.append("no known injection indicators detected")

        return {
            "risk_score": score,
            "severity": severity,
            "detected": detected,
            "reasons": reasons,
            "recommended_action": action,
        }

    @staticmethod
    def _severity_for(score: int) -> str:
        t = POLICIES["risk_thresholds"]
        if score >= t["CRITICAL"]:
            return "CRITICAL"
        if score >= t["HIGH"]:
            return "HIGH"
        if score >= t["MEDIUM"]:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _recommend_action(severity: str, source: str) -> str:
        if severity == "CRITICAL":
            return "BLOCK"
        if severity == "HIGH":
            # Trusted first-party sources get a human-review step rather than
            # an automatic block, since the user retains the right to confirm
            # intent; untrusted content is fail-closed and blocked outright.
            return "REVIEW" if source in ("USER", "SYSTEM") else "BLOCK"
        if severity == "MEDIUM":
            return "REVIEW"
        return "ALLOW"


# --------------------------------------------------------------------------
# B. Trust Analyzer
# --------------------------------------------------------------------------
class TrustAnalyzer:
    """Classifies and scores the trust level of a content source."""

    VALID_SOURCES = list(TRUST_LEVELS.keys())

    def classify(self, source: str) -> dict:
        source = (source or "UNKNOWN").upper()
        if source not in TRUST_LEVELS:
            source = "UNKNOWN"
        trust_score = TRUST_LEVELS[source]
        is_untrusted = source in POLICIES["untrusted_sources"]
        return {
            "source": source,
            "trust_score": trust_score,
            "is_untrusted": is_untrusted,
            "can_issue_instructions": source in ("SYSTEM", "USER"),
        }


# --------------------------------------------------------------------------
# C. Sensitive Data Guard
# --------------------------------------------------------------------------
class SensitiveDataGuard:
    """Detects common sensitive-data patterns in text (synthetic/demo only)."""

    PATTERNS = {
        "EMAIL": (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "MEDIUM"),
        "PHONE_NUMBER": (r"\b(?:\+?\d{1,3}[-.\s]?)?\d{10}\b", "MEDIUM"),
        "API_KEY": (r"\b(?:sk|api|key|pk)-[A-Za-z0-9]{16,}\b", "HIGH"),
        "GENERIC_SECRET": (r"\b(?:password|passwd|secret|token)\s*[:=]\s*\S+", "HIGH"),
        "PRIVATE_KEY_BLOCK": (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "CRITICAL"),
        "CREDIT_CARD_LIKE": (r"\b(?:\d[ -]*?){13,16}\b", "HIGH"),
    }

    def scan(self, text: str) -> list:
        text = text or ""
        findings = []
        for label, (pattern, severity) in self.PATTERNS.items():
            for match in re.finditer(pattern, text):
                start = max(0, match.start() - 15)
                end = min(len(text), match.end() + 15)
                findings.append({
                    "type": label,
                    "context": f"...{text[start:end].strip()}...",
                    "severity": severity,
                    "redaction_recommended": True,
                })
        return findings


# --------------------------------------------------------------------------
# D. Tool Authorization Engine
# --------------------------------------------------------------------------
class ToolAuthorizationEngine:
    """Evaluates whether a requested tool/action may run, given risk + trust."""

    SAFE_TOOLS = {
        "read_public_file": "Reads a non-sensitive demo file from the sandbox.",
        "read_sensitive_file": "Reads a demo file marked sensitive (restricted).",
        "create_report": "Creates a text report inside the sandbox output folder.",
        "search_local_knowledge": "Searches a small local demo knowledge base.",
        "execute_safe_demo_action": "Performs a harmless, logged demo action.",
    }

    def evaluate(self, tool_name: str, source: str, injection_result: dict) -> dict:
        tool_risk = POLICIES["tool_risk"].get(tool_name, "BLOCKED")

        if tool_name not in self.SAFE_TOOLS:
            return {
                "decision": "BLOCK",
                "reason": f"'{tool_name}' is not a recognized authorized tool "
                          f"(no arbitrary command execution is permitted).",
                "tool_risk": "BLOCKED",
            }

        if tool_risk == "BLOCKED":
            return {"decision": "BLOCK", "reason": "Tool is permanently blocked by policy.",
                    "tool_risk": tool_risk}

        # Fail closed if the request itself looks like an injection attempt.
        if injection_result["recommended_action"] == "BLOCK":
            return {
                "decision": "BLOCK",
                "reason": "Request blocked: underlying content was flagged as a "
                           f"prompt-injection attempt ({injection_result['severity']}).",
                "tool_risk": tool_risk,
            }

        if tool_risk == "HIGH":
            if source not in ("USER", "SYSTEM"):
                return {
                    "decision": "BLOCK",
                    "reason": "High-risk tool requested by/derived from an untrusted "
                               "source. Sensitive access requires a directly trusted "
                               "user instruction.",
                    "tool_risk": tool_risk,
                }
            return {
                "decision": "REVIEW",
                "reason": "High-risk tool requires explicit user confirmation before execution.",
                "tool_risk": tool_risk,
            }

        if tool_risk == "MEDIUM":
            if injection_result["recommended_action"] == "REVIEW":
                return {"decision": "REVIEW",
                        "reason": "Medium-risk action requires additional validation.",
                        "tool_risk": tool_risk}
            return {"decision": "ALLOW", "reason": "Medium-risk action validated successfully.",
                    "tool_risk": tool_risk}

        # LOW risk
        return {"decision": "ALLOW", "reason": "Low-risk tool permitted under least-privilege policy.",
                "tool_risk": tool_risk}


# --------------------------------------------------------------------------
# E. Policy Engine (orchestrator)
# --------------------------------------------------------------------------
class PolicyEngine:
    """
    Top-level orchestrator implementing the pipeline:
    INPUT -> SECURITY ANALYSIS -> RISK ASSESSMENT -> POLICY DECISION ->
    ALLOW/BLOCK/REVIEW -> SAFE ACTION -> AUDIT LOG
    """

    def __init__(self):
        self.injection_detector = PromptInjectionDetector()
        self.trust_analyzer = TrustAnalyzer()
        self.data_guard = SensitiveDataGuard()
        self.tool_auth = ToolAuthorizationEngine()

    def inspect_content(self, text: str, source: str) -> dict:
        """Full inspection pipeline for a piece of content (no tool call)."""
        trust = self.trust_analyzer.classify(source)
        injection = self.injection_detector.analyze(text, trust["source"], trust["trust_score"])
        sensitive = self.data_guard.scan(text)

        final_action = injection["recommended_action"]
        if sensitive and any(f["severity"] in ("HIGH", "CRITICAL") for f in sensitive):
            if final_action == "ALLOW":
                final_action = "REVIEW"

        return {
            "trust": trust,
            "injection": injection,
            "sensitive_data": sensitive,
            "final_action": final_action,
        }

    def evaluate_tool_request(self, tool_name: str, request_text: str, source: str) -> dict:
        """Full pipeline for an agent tool/action request."""
        inspection = self.inspect_content(request_text, source)
        tool_result = self.tool_auth.evaluate(tool_name, inspection["trust"]["source"],
                                               inspection["injection"])
        return {
            "inspection": inspection,
            "tool_decision": tool_result["decision"],
            "tool_reason": tool_result["reason"],
            "tool_risk": tool_result["tool_risk"],
        }
