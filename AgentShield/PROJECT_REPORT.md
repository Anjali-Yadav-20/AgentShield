# PROJECT REPORT: AgentShield

**Local AI-Agent Security & Prompt-Injection Defense Framework**

---

## 1. Abstract

AgentShield is a local, desktop-based cybersecurity framework that protects
an AI agent from prompt injection, unauthorized tool usage, and
sensitive-data exposure. It enforces trust-aware, deterministic security
policies between the agent and its tools, ensuring that untrusted content
(documents, web pages, tool output) can never automatically become a
trusted instruction. The project includes a controlled attack simulation
lab that runs benign, safe attack scenarios through the real security
engine and reports dynamically calculated detection and blocking
statistics.

## 2. Introduction

As AI agents are increasingly given the ability to read external content
and call tools, a new class of attack has emerged: prompt injection, where
malicious instructions are hidden inside content the agent processes. This
project builds a small but genuine security engine — not a chatbot wrapper
— to demonstrate practical defenses against this class of attack, using
concepts from classical computer security (trust boundaries, least
privilege, defense in depth) applied to LLM-integrated systems.

## 3. Problem Statement

An AI agent that blindly trusts every piece of text it reads is vulnerable
to indirect prompt injection: a malicious document, web page, or tool
result can instruct the agent to ignore its real instructions, reveal
secrets, or perform unauthorized actions. There is no reliable way to
"turn off" this risk in a raw LLM call — it must be mitigated architecturally,
outside the model, at the point where content and tool access are handled.

## 4. Existing System

Most educational and hobby AI-agent projects connect a language model
directly to tools with no intermediate authorization layer, and no
distinction between trusted user instructions and untrusted external
content. Basic chatbot or dashboard projects typically have no security
engine at all — the "security" is often just an API key.

## 5. Proposed System

AgentShield introduces a security gateway between the agent and its tools:

1. All content is classified by trust source before it is processed.
2. All content is scanned by a weighted, multi-category prompt-injection
   detector, producing a risk score, severity, and recommended action.
3. Sensitive data (emails, phone numbers, API keys, secrets) is separately
   flagged.
4. Tool/action requests are evaluated by a least-privilege policy engine
   that can ALLOW, REVIEW (require confirmation), or BLOCK.
5. Every decision is written to a local SQLite audit log.
6. A controlled attack simulation lab exercises the real engine against 14
   benign attack scenarios and calculates detection/blocking statistics
   dynamically — never hardcoded.

## 6. Objectives

- Build a genuine rule-based security engine, not a UI-only demo.
- Demonstrate clear separation of trusted instructions from untrusted
  content.
- Enforce least-privilege tool authorization with no arbitrary command
  execution.
- Provide measurable, reproducible evaluation of detection effectiveness.
- Remain fully functional without any paid/cloud AI service.

## 7. System Architecture

```
INPUT -> SECURITY ANALYSIS -> RISK ASSESSMENT -> POLICY DECISION ->
ALLOW / BLOCK / REVIEW -> SAFE ACTION -> AUDIT LOG
```

Layers:

- **Presentation layer** (`ui.py`): PySide6 desktop UI, five tabs, no
  business logic.
- **Agent layer** (`agent.py`): receives requests, calls the security gate
  before any tool executes, never runs raw OS commands.
- **Security engine layer** (`security_engine.py`): injection detector,
  trust analyzer, sensitive-data guard, tool authorization engine, policy
  engine (orchestrator).
- **Simulation layer** (`simulator.py`): runs predefined benign scenarios
  through the real agent/engine.
- **Persistence layer** (`database.py`): SQLite audit log only.

## 8. Module Description

| Module | Responsibility |
|---|---|
| `security_engine.py` | Prompt-injection detection, trust classification, sensitive-data scanning, tool authorization, policy orchestration |
| `agent.py` | Local agent abstraction; routes every tool call through the security gate; optional Ollama explanation |
| `simulator.py` | Loads and runs attack scenarios through the real engine; computes evaluation statistics |
| `database.py` | SQLite schema, event logging, retrieval, clearing |
| `ui.py` | PySide6 desktop interface: Security Test, Attack Lab, Tool Guard, Security Events, About |
| `main.py` | Entry point; initializes the database and launches the UI |

## 9. Security Methodology

### 9.1 Prompt Injection Detector

A rule-based detector with seven weighted categories: instruction override,
role manipulation, system-prompt extraction, instruction-hierarchy attacks,
unauthorized tool/action requests, encoded/obfuscated instructions, and
authority coercion. Each category contributes a weight if matched; the
total is scaled by the content's trust source (untrusted sources amplify
risk, trusted sources are scaled down slightly) and mapped to a severity
band (LOW/MEDIUM/HIGH/CRITICAL) and a recommended action.

### 9.2 Trust Analyzer

Every piece of content is classified into one of six trust levels
(SYSTEM, USER, TRUSTED_TOOL, WEB_CONTENT, EXTERNAL_DOCUMENT, UNKNOWN), each
with a numeric trust score. Only USER and SYSTEM content is treated as
capable of issuing instructions.

### 9.3 Sensitive Data Guard

Regex-based detection of emails, phone numbers, API-key-like strings,
generic secrets/passwords, private-key blocks, and credit-card-like
numbers, each returning type, context, severity, and a redaction
recommendation.

### 9.4 Tool Authorization Engine

Five safe simulated tools with a fixed risk tier (LOW/MEDIUM/HIGH) plus one
permanently BLOCKED placeholder (`arbitrary_command_execution`) to
demonstrate that no arbitrary OS command execution is ever permitted.
Decisions fail closed: an unrecognized tool, a blocked tool, or a
tool request tied to flagged content is blocked.

### 9.5 Policy Engine

Orchestrates the above into a single pipeline (`inspect_content`,
`evaluate_tool_request`) used identically by the UI, the agent, and the
simulator, so every entry point is evaluated by the same rules.

## 10. Attack Simulation Methodology

`attack_scenarios.json` defines 14 benign scenarios covering direct
injection, indirect document injection, instruction override, system-prompt
extraction, role manipulation, tool abuse, sensitive-file access,
data exfiltration, encoded instructions, dangerous action requests,
external-content instruction conflicts, unauthorized privilege requests,
and two benign baseline cases. Each scenario is executed through the real
`LocalAgent`/`PolicyEngine` — no scenario result is precomputed or
hardcoded. No real malware, exploitation, or destructive commands are
involved anywhere in the project.

## 11. Database Design

A single SQLite table, `security_events`, records: timestamp, source,
event type, risk score, severity, decision, reason, tool requested, and
scenario name (where applicable). It exists solely for security auditing,
not as a general data store.

## 12. Testing

- Each core module was executed independently to confirm the security
  pipeline produces sensible, non-hardcoded outputs (risk scores, severity,
  ALLOW/BLOCK/REVIEW decisions).
- All 14 attack scenarios were run end-to-end through the real engine.
- JSON configuration files (`policies.json`, `attack_scenarios.json`) were
  validated for correctness.
- Ollama-unavailable behavior was verified to fail gracefully without
  crashing the application.
- The application's non-GUI entry path was verified to detect a missing
  PySide6 installation and exit cleanly with an instructive message rather
  than crashing.

## 13. Evaluation Method

The Attack Lab computes, from the actual run results: total scenarios,
detected count, blocked count, reviewed count, allowed count, false
positives (benign scenarios incorrectly restricted), false negatives
(attack scenarios incorrectly allowed), detection rate, blocking rate, and
policy-match accuracy against the scenario's expected result. All figures
are calculated at run time from the real engine's output — they are never
hardcoded or pre-written into the UI.

## 14. Limitations

- The detector is heuristic and pattern-based; sophisticated or novel
  phrasing may evade detection (false negatives), and unusual but benign
  phrasing may be over-flagged (false positives).
- This project does not claim to solve prompt injection completely — this
  is an open research problem industry-wide, and no rule-based or model-based
  system currently provides a complete solution.
- Simulated tools operate on an in-memory sandbox rather than a real
  filesystem, by deliberate design, to keep the project safe or academic use.
- Ollama integration is optional and cosmetic (explanatory text only); it
  is never part of the authorization decision path.

## 15. Future Scope

- Combine the rule-based detector with a lightweight local classifier
  trained on labeled injection/non-injection examples for improved recall.
- Add configurable, UI-editable policy thresholds per deployment.
- Extend the Sensitive Data Guard with contextual/NLP-based detection to
  reduce regex false positives.
- Add structured export of the audit log for compliance reporting.

## 16. Conclusion

AgentShield demonstrates that a compact (~900 line), fully local, rule-based
security framework can meaningfully reduce the risk of prompt injection and
unauthorized tool use in an AI-agent system, without relying on any cloud
service. Its core value is architectural: it proves that a trust boundary
placed between untrusted content and tool execution — enforced
deterministically rather than left to model judgment — is both practical
and demonstrable for a BCA-level cybersecurity project.
