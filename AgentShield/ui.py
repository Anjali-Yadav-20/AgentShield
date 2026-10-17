"""
ui.py
PySide6 desktop interface for AgentShield.

The UI is a thin operating console for the security engine - all real
decisions happen in security_engine.py / agent.py / simulator.py.
"""

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QLabel, QTextEdit, QPushButton, QComboBox, QListWidget, QTableWidget,
    QTableWidgetItem, QGroupBox, QMessageBox, QLineEdit, QHeaderView,
)

from agent import LocalAgent, is_ollama_available
from database import get_recent_events, clear_events
from simulator import load_scenarios, run_all_scenarios, run_scenario

SEVERITY_COLORS = {
    "LOW": "#2ecc71", "MEDIUM": "#f1c40f", "HIGH": "#e67e22",
    "CRITICAL": "#e74c3c", "N/A": "#95a5a6",
}
DECISION_COLORS = {"ALLOW": "#2ecc71", "REVIEW": "#f1c40f", "BLOCK": "#e74c3c"}


def _badge(text: str, color: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setStyleSheet(
        f"background:{color}; color:#0b0f14; font-weight:bold; padding:4px 10px; "
        f"border-radius:6px;")
    return lbl


class SecurityTestTab(QWidget):
    def __init__(self, agent: LocalAgent):
        super().__init__()
        self.agent = agent
        layout = QVBoxLayout(self)

        layout.addWidget(QLabel("<b>Trusted User Instruction</b>"))
        self.user_input = QTextEdit()
        self.user_input.setPlaceholderText("e.g. Summarize this document for me.")
        layout.addWidget(self.user_input)

        layout.addWidget(QLabel("<b>External / Untrusted Content (optional)</b>"))
        self.ext_input = QTextEdit()
        self.ext_input.setPlaceholderText("Paste content from a document, webpage, or tool output...")
        layout.addWidget(self.ext_input)

        row = QHBoxLayout()
        row.addWidget(QLabel("Source classification:"))
        self.source_box = QComboBox()
        self.source_box.addItems(
            ["EXTERNAL_DOCUMENT", "WEB_CONTENT", "USER", "TRUSTED_TOOL", "UNKNOWN"])
        row.addWidget(self.source_box)
        self.analyze_btn = QPushButton("Analyze")
        self.analyze_btn.clicked.connect(self.run_analysis)
        row.addWidget(self.analyze_btn)
        row.addStretch()
        layout.addLayout(row)

        result_box = QGroupBox("Result")
        rlayout = QVBoxLayout(result_box)
        self.badge_row = QHBoxLayout()
        rlayout.addLayout(self.badge_row)
        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        rlayout.addWidget(self.result_text)
        layout.addWidget(result_box)

    def run_analysis(self):
        user_text = self.user_input.toPlainText().strip()
        ext_text = self.ext_input.toPlainText().strip()
        source = self.source_box.currentText()
        if not user_text and not ext_text:
            QMessageBox.warning(self, "Input required", "Enter a user instruction or external content.")
            return

        result = self.agent.handle_request(
            user_instruction=user_text or "(no user instruction provided)",
            external_content=ext_text, external_source=source, use_llm=False)

        while self.badge_row.count():
            item = self.badge_row.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        action = result["final_action"]
        self.badge_row.addWidget(_badge(f"DECISION: {action}", DECISION_COLORS.get(action, "#888")))
        ui_sev = result["user_inspection"]["injection"]["severity"]
        self.badge_row.addWidget(_badge(f"USER SEVERITY: {ui_sev}", SEVERITY_COLORS.get(ui_sev, "#888")))
        self.badge_row.addStretch()

        lines = ["=== USER INSTRUCTION ANALYSIS ===",
                 f"Risk score: {result['user_inspection']['injection']['risk_score']}",
                 f"Severity: {ui_sev}",
                 "Reasons: " + "; ".join(result["user_inspection"]["injection"]["reasons"])]

        if result["external_inspection"]:
            ei = result["external_inspection"]
            lines += ["", "=== EXTERNAL CONTENT ANALYSIS ===",
                      f"Source: {ei['trust']['source']}  (trust score {ei['trust']['trust_score']})",
                      f"Risk score: {ei['injection']['risk_score']}",
                      f"Severity: {ei['injection']['severity']}",
                      "Reasons: " + "; ".join(ei["injection"]["reasons"])]
            if ei["sensitive_data"]:
                lines.append("Sensitive data found: " +
                              ", ".join(f"{f['type']}({f['severity']})" for f in ei["sensitive_data"]))

        lines += ["", f"FINAL DECISION: {action}",
                  "Note: external content can never elevate its own trust into an instruction."]
        self.result_text.setPlainText("\n".join(lines))


class AttackLabTab(QWidget):
    def __init__(self, agent: LocalAgent):
        super().__init__()
        self.agent = agent
        self.scenarios = load_scenarios()
        layout = QVBoxLayout(self)

        layout.addWidget(QLabel("<b>Attack Simulation Lab</b> (runs through the real security engine)"))
        self.scenario_list = QListWidget()
        for s in self.scenarios:
            self.scenario_list.addItem(f"{s['name']}  [{s['category']}]")
        layout.addWidget(self.scenario_list)

        row = QHBoxLayout()
        self.run_one_btn = QPushButton("Run Selected Scenario")
        self.run_one_btn.clicked.connect(self.run_selected)
        self.run_all_btn = QPushButton("Run All Scenarios")
        self.run_all_btn.clicked.connect(self.run_all)
        row.addWidget(self.run_one_btn)
        row.addWidget(self.run_all_btn)
        row.addStretch()
        layout.addLayout(row)

        self.stats_label = QLabel("No results yet.")
        self.stats_label.setStyleSheet("font-family:monospace;")
        layout.addWidget(self.stats_label)

        self.results_table = QTableWidget(0, 5)
        self.results_table.setHorizontalHeaderLabels(
            ["Scenario", "Category", "Expected", "Actual", "Match"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.results_table)

    def run_selected(self):
        idx = self.scenario_list.currentRow()
        if idx < 0:
            QMessageBox.information(self, "Select a scenario", "Choose a scenario from the list first.")
            return
        result = run_scenario(self.agent, self.scenarios[idx])
        self._populate_table([result])
        self.stats_label.setText(f"Ran 1 scenario: {result['name']} -> {result['actual_result']}")

    def run_all(self):
        out = run_all_scenarios(self.agent, self.scenarios)
        self._populate_table(out["results"])
        s = out["stats"]
        self.stats_label.setText(
            "ATTACK SIMULATION RESULTS\n"
            f"Total Scenarios: {s['total_scenarios']}   Detected: {s['detected']}   "
            f"Blocked: {s['blocked']}   Reviewed: {s['reviewed']}   Allowed: {s['allowed']}\n"
            f"Detection Rate: {s['detection_rate']}%   Blocking Rate: {s['blocking_rate']}%   "
            f"Policy Match Accuracy: {s['policy_match_accuracy']}%   "
            f"False Positives: {s['false_positives']}   False Negatives: {s['false_negatives']}")

    def _populate_table(self, results):
        self.results_table.setRowCount(len(results))
        for row, r in enumerate(results):
            vals = [r["name"], r["category"], r["expected_result"], r["actual_result"],
                    "YES" if r["matched_expectation"] else "NO"]
            for col, v in enumerate(vals):
                item = QTableWidgetItem(str(v))
                if col == 3:
                    item.setBackground(QColor(DECISION_COLORS.get(v, "#888")))
                self.results_table.setItem(row, col, item)


class ToolGuardTab(QWidget):
    def __init__(self, agent: LocalAgent):
        super().__init__()
        self.agent = agent
        layout = QVBoxLayout(self)

        layout.addWidget(QLabel("<b>Tool Authorization Guard</b>"))
        row = QHBoxLayout()
        row.addWidget(QLabel("Simulated tool:"))
        self.tool_box = QComboBox()
        self.tool_box.addItems(
            ["read_public_file", "create_report", "search_local_knowledge",
             "read_sensitive_file", "execute_safe_demo_action", "arbitrary_command_execution"])
        row.addWidget(self.tool_box)
        layout.addLayout(row)

        layout.addWidget(QLabel("Request text (source is treated as the trusted user):"))
        self.request_input = QLineEdit()
        self.request_input.setPlaceholderText("e.g. Please read the sensitive salary file.")
        layout.addWidget(self.request_input)

        self.eval_btn = QPushButton("Evaluate")
        self.eval_btn.clicked.connect(self.evaluate)
        layout.addWidget(self.eval_btn)

        self.badge_row = QHBoxLayout()
        layout.addLayout(self.badge_row)
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        layout.addWidget(self.output)

    def evaluate(self):
        tool_name = self.tool_box.currentText()
        text = self.request_input.text().strip() or f"Requesting tool {tool_name}"
        result = self.agent.handle_request(
            user_instruction=text, tool_name=tool_name, use_llm=False)
        tr = result["tool_result"]

        while self.badge_row.count():
            item = self.badge_row.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self.badge_row.addWidget(_badge(tr["decision"], DECISION_COLORS.get(tr["decision"], "#888")))
        self.badge_row.addStretch()

        self.output.setPlainText(
            f"Tool: {tool_name}\nDecision: {tr['decision']}\nReason: {tr['reason']}\n\nOutput:\n{tr['output']}")


class SecurityEventsTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("<b>Security Audit Log</b> (SQLite-backed)"))

        row = QHBoxLayout()
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh)
        self.clear_btn = QPushButton("Clear Events")
        self.clear_btn.clicked.connect(self.clear)
        row.addWidget(self.refresh_btn)
        row.addWidget(self.clear_btn)
        row.addStretch()
        layout.addLayout(row)

        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(
            ["Timestamp", "Source", "Event Type", "Severity", "Decision", "Reason", "Scenario"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.table)
        self.refresh()

    def refresh(self):
        events = get_recent_events(100)
        self.table.setRowCount(len(events))
        for row, e in enumerate(events):
            vals = [e["timestamp"], e["source"], e["event_type"], e["severity"],
                    e["decision"], e["reason"], e["scenario_name"]]
            for col, v in enumerate(vals):
                item = QTableWidgetItem(str(v) if v is not None else "")
                if col == 4:
                    item.setBackground(QColor(DECISION_COLORS.get(v, "#2b2b2b")))
                self.table.setItem(row, col, item)

    def clear(self):
        clear_events()
        self.refresh()


class AboutTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        ollama_status = "AVAILABLE" if is_ollama_available() else \
            "UNAVAILABLE — deterministic security engine is active."
        text = f"""
<h2>AgentShield</h2>
<p><i>Local AI-Agent Security &amp; Prompt-Injection Defense Framework</i></p>
<p><b>Objective:</b> Protect a local AI agent from prompt injection, unauthorized
tool use, and sensitive-data exposure by enforcing trust-aware, deterministic
security policies between the agent and its tools.</p>
<p><b>Technology:</b> Python 3, PySide6, SQLite, optional Ollama (llama3.2:3b).</p>
<p><b>Security principles demonstrated:</b></p>
<ul>
<li>Least privilege - tools run at the minimum risk tier required</li>
<li>Trust boundaries - user / system / external content are never conflated</li>
<li>Defense in depth - injection detection + trust analysis + tool policy + data guard</li>
<li>Deterministic policy enforcement - decisions come from rules, not vibes</li>
<li>Untrusted-content isolation - external text can never self-elevate to an instruction</li>
<li>Fail-safe defaults - unknown or high-risk actions fail closed</li>
<li>Audit logging - every decision is written to the local SQLite log</li>
</ul>
<p><b>Ollama status:</b> {ollama_status}</p>
<p style="color:#e67e22;"><b>Honesty note:</b> Detection is heuristic and rule-based.
It can produce false positives and false negatives and does not claim to solve
prompt injection completely.</p>
"""
        lbl = QLabel(text)
        lbl.setWordWrap(True)
        lbl.setTextFormat(Qt.RichText)
        layout.addWidget(lbl)
        layout.addStretch()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AgentShield — Local AI-Agent Security Framework")
        self.resize(1000, 720)
        self.agent = LocalAgent()

        tabs = QTabWidget()
        tabs.addTab(SecurityTestTab(self.agent), "Security Test")
        tabs.addTab(AttackLabTab(self.agent), "Attack Lab")
        tabs.addTab(ToolGuardTab(self.agent), "Tool Guard")
        tabs.addTab(SecurityEventsTab(), "Security Events")
        tabs.addTab(AboutTab(), "About")
        self.setCentralWidget(tabs)


def run_app():
    app = QApplication.instance() or QApplication([])
    app.setStyle("Fusion")
    window = MainWindow()
    window.show()
    app.exec()
