"""
simulator.py
Controlled attack simulation lab.

All scenarios are benign simulations (no real malware, no real exploitation)
and are run through the REAL AgentShield PolicyEngine / LocalAgent - results
are never hardcoded.
"""

import json
import os

from database import log_event

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCENARIOS_PATH = os.path.join(BASE_DIR, "attack_scenarios.json")


def load_scenarios() -> list:
    try:
        with open(SCENARIOS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def run_scenario(agent, scenario: dict) -> dict:
    """Run a single scenario through the real agent/security engine."""
    result = agent.handle_request(
        user_instruction=scenario.get("trusted_user_request", ""),
        external_content=scenario.get("untrusted_content", ""),
        external_source=scenario.get("untrusted_source", "EXTERNAL_DOCUMENT"),
        tool_name=scenario.get("attempted_tool", ""),
        use_llm=False,
        scenario_name=scenario.get("name", ""),
    )

    actual_action = result["final_action"]
    if result["tool_result"]:
        actual_action = result["tool_result"]["decision"]

    expected = scenario.get("expected_result", "")
    matched = (actual_action == expected)

    detected = result["user_inspection"]["injection"]["detected"]
    if result["external_inspection"]:
        detected = detected or result["external_inspection"]["injection"]["detected"]

    log_event("SIMULATOR", "SCENARIO_RUN", 0, "N/A", actual_action,
              f"expected={expected}, actual={actual_action}", "", scenario.get("name", ""))

    return {
        "name": scenario.get("name", ""),
        "category": scenario.get("category", ""),
        "expected_result": expected,
        "actual_result": actual_action,
        "matched_expectation": matched,
        "detected": detected,
        "details": result,
    }


def run_all_scenarios(agent, scenarios=None) -> dict:
    """Run every scenario and compute evaluation statistics dynamically."""
    scenarios = scenarios if scenarios is not None else load_scenarios()
    results = [run_scenario(agent, s) for s in scenarios]

    total = len(results)
    detected = sum(1 for r in results if r["detected"])
    blocked = sum(1 for r in results if r["actual_result"] == "BLOCK")
    allowed = sum(1 for r in results if r["actual_result"] == "ALLOW")
    reviewed = sum(1 for r in results if r["actual_result"] == "REVIEW")

    # False positives: benign scenario (expected ALLOW) that was blocked/reviewed.
    false_positives = sum(
        1 for r in results if r["expected_result"] == "ALLOW" and r["actual_result"] != "ALLOW"
    )
    # False negatives: attack scenario (expected BLOCK/REVIEW) that was allowed.
    false_negatives = sum(
        1 for r in results if r["expected_result"] in ("BLOCK", "REVIEW") and r["actual_result"] == "ALLOW"
    )

    detection_rate = round((detected / total) * 100, 1) if total else 0.0
    blocking_rate = round((blocked / total) * 100, 1) if total else 0.0
    accuracy = round(
        (sum(1 for r in results if r["matched_expectation"]) / total) * 100, 1
    ) if total else 0.0

    return {
        "results": results,
        "stats": {
            "total_scenarios": total,
            "detected": detected,
            "blocked": blocked,
            "reviewed": reviewed,
            "allowed": allowed,
            "false_positives": false_positives,
            "false_negatives": false_negatives,
            "detection_rate": detection_rate,
            "blocking_rate": blocking_rate,
            "policy_match_accuracy": accuracy,
        },
    }
