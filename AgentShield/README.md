# AgentShield

**Local AI-Agent Security & Prompt-Injection Defense Framework**

A BCA 3rd-year cybersecurity minor project. AgentShield is a local desktop
security gateway that sits between an AI agent and its tools, enforcing
trust-aware, deterministic security policies so that untrusted content can
never automatically become a trusted instruction.

---

## 1. Problem Statement

AI agents that read external content (documents, web pages, tool outputs)
and can call tools are vulnerable to **prompt injection**: text crafted to
make the agent ignore its real instructions, leak information, or trigger
unauthorized actions. Most simple chatbot demos trust everything they read.
AgentShield demonstrates a defensible architecture that does not.

## 2. Objectives

- Detect direct and indirect prompt injection using a weighted, multi-category
  heuristic engine (not a single keyword match).
- Classify every piece of content by trust level (USER, SYSTEM, TRUSTED_TOOL,
  EXTERNAL_DOCUMENT, WEB_CONTENT, UNKNOWN).
- Authorize tool/action requests through a least-privilege policy engine.
- Detect sensitive data (emails, phone numbers, API keys, secrets) before it
  can leak.
- Provide a controlled attack simulation lab with dynamically computed
  detection/blocking statistics.
- Log every security decision to a local SQLite audit trail.

## 3. Architecture

```
USER
  |
  v
AGENT (agent.py)
  |
  v
AGENTSHIELD SECURITY GATE (security_engine.py)
  |  - Prompt Injection Detector
  |  - Trust Analyzer
  |  - Sensitive Data Guard
  v
POLICY ENGINE
  |
  v
SAFE SIMULATED TOOL
  |
  v
RESULT  ->  AUDIT LOG (database.py / SQLite)
```

Untrusted external content is inspected **separately** from the trusted
user instruction. External content risk can only ever restrict the final
decision (REVIEW/BLOCK) — it can never grant itself trust or elevate into
an executable instruction.

## 4. Features

- **Security Test tab** — analyze a user instruction plus optional untrusted
  content from a chosen source, see risk score, severity, reasons, decision.
- **Attack Lab tab** — run 14 predefined benign attack scenarios (or all at
  once) through the real engine; statistics are calculated, never hardcoded.
- **Tool Guard tab** — evaluate a simulated tool request (e.g.
  `read_sensitive_file`) and see ALLOW/BLOCK/REVIEW with a reason.
- **Security Events tab** — browse the SQLite audit log of every decision.
- **About tab** — project summary, principles, and live Ollama status.

## 5. Technology Stack

- Python 3.13+
- PySide6 (desktop GUI — not a web app)
- SQLite (audit logging only, not a CRUD app)
- Ollama + `llama3.2:3b` (optional, local-only natural-language explanations)

No Flask, Django, Streamlit, React, Electron, or cloud APIs are used.

## 6. Installation

```bash
cd AgentShield
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## 7. Ollama Setup (optional)

AgentShield's core security engine works fully **without** Ollama. Ollama
only adds an optional plain-language explanation of a decision.

```bash
# Install Ollama from https://ollama.com, then:
ollama pull llama3.2:3b
ollama serve
```

If Ollama is not running, the app shows: *"Ollama unavailable — deterministic
security engine is active."* and continues to work normally.

## 8. Running

```bash
python main.py
```

## 9. Running the Attack Simulation

Open the **Attack Lab** tab and click **Run All Scenarios**. AgentShield
will execute all 14 benign scenarios through the real `PolicyEngine` and
`LocalAgent`, then display dynamically calculated:

- Total scenarios, Detected, Blocked, Reviewed, Allowed
- Detection Rate, Blocking Rate, Policy Match Accuracy
- False positives / false negatives

## 10. Screenshots

_(Add screenshots here when demonstrating to faculty)_

- `screenshots/security_test.png`
- `screenshots/attack_lab.png`
- `screenshots/tool_guard.png`
- `screenshots/security_events.png`

## 11. Limitations

- Detection is **heuristic and rule-based**; it can produce false positives
  and false negatives. It does **not** claim to solve prompt injection
  completely — no system can.
- The simulated tools operate on an in-memory sandbox, not the real file
  system, by design (safety requirement for an academic project).
- Ollama integration is optional and used only for explanatory text, never
  for security decisions.

## 12. Future Scope

- Expand the regex/weighted rule set with a small ML classifier trained on
  labeled injection examples.
- Add per-user policy profiles and configurable thresholds via the UI.
- Extend sensitive-data detection with contextual NLP rather than regex only.
- Add encrypted audit-log export for compliance reporting.

## 13. Project Structure

```
AgentShield/
├── main.py                Entry point
├── security_engine.py     Core security engine (detector, trust, policy, tools)
├── agent.py                Local AI agent abstraction (gated tool access)
├── simulator.py             Attack simulation lab
├── database.py               SQLite audit logging
├── ui.py                       PySide6 desktop UI
├── policies.json                Deterministic policy configuration
├── attack_scenarios.json         14 benign attack scenarios
├── requirements.txt
├── README.md
└── PROJECT_REPORT.md
```
