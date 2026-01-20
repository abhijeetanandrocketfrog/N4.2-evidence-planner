import json
from planner.evidence_planner import run_evidence_planner
from utils.scenario_rules import load_scenario_rules, expand_parent_scenarios
from utils.helper import build_unique_eb_data
import time

member_id = "FAKE-1145539115_MIGUEL_TED_ANGLER"

scenarios_input = {
    "scenarios": [1.1, 1.2]
}

atomic_questions_input = {
  "Atomic_Questions": [
    {
      "eb_filters": [
        "EB01: Co-Payment",
        "EB01: Deductible",
        "EB02: Individual",
        "EB02: Individual and Children",
        "EB02: Individual and Spouse",
        "EB02: Individual Only",
        "EB03: Dental Care"
      ],
      "extracted_terms": [
        "copay",
        "deductible",
        "gyn"
      ]
    }
  ]
}

# ----------------------------
# Load Scenario Rules
# ----------------------------
start_time = time.perf_counter()

scenario_rules = load_scenario_rules()

raw_scenarios = scenarios_input["scenarios"]

expanded_scenarios = expand_parent_scenarios(
    raw_scenarios,
    scenario_rules
)

# ----------------------------
# Run Evidence Planner (multi-scenario)
# ----------------------------
evidence = run_evidence_planner(
    member_id=member_id,
    atomic_questions=atomic_questions_input["Atomic_Questions"],
    scenarios=scenarios_input["scenarios"],
    scenario_rules=scenario_rules
)

end_time = time.perf_counter()
time_taken = end_time - start_time

print(f"Time Taken : {time_taken:.6f} seconds")

# ----------------------------
# Final Output
# ----------------------------
output = {
    "member_id": member_id,
    "evidence": evidence
}

# ----------------------------
# Store Output
# ----------------------------
output_path = "outputs/output.json"

with open(output_path, "w") as f:
    json.dump(output, f, indent=2, default=str)

build_unique_eb_data(
    input_path="outputs/output.json",
    output_path="outputs/eb_data.json"
)

print(f"Evidence planner output stored at {output_path}")
