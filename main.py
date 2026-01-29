import json
from planner.evidence_planner import run_evidence_planner
from utils.scenario_rules import load_scenario_rules, expand_parent_scenarios
from utils.helper import build_unique_eb_data
import time

member_id = "FAKE-1430569713_GRETA_TOMMY_SQUAWFISH"

scenarios_input = {
    "scenarios": [2.1]
}

atomic_questions_input = {
  "Atomic_Questions": [
  {
    "eb_filters": [
      "EB01: Co-Payment",
      "EB02: Individual",
      "EB02: Individual and Children",
      "EB02: Individual and Spouse",
      "EB02: Individual Only",
      "EB03: Health Benefit Plan Coverage",
      "EB12: In-Plan-Network"
    ],
    "extracted_terms": [
      "copay",
      "i",
      "gyn",
      "in-network"
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
print(expanded_scenarios)
# ----------------------------
# Run Evidence Planner (multi-scenario)
# ----------------------------
evidence = run_evidence_planner(
    member_id=member_id,
    atomic_questions=atomic_questions_input["Atomic_Questions"],
    scenarios=expanded_scenarios,
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
