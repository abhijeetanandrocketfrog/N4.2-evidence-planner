import json

SCENARIO_RULES_PATH = "config/evidence_planner.json"

def load_scenario_rules():
    with open(SCENARIO_RULES_PATH, "r") as f:
        return json.load(f)

def get_mandatory_eb(scenario_rules, scenario_id):
    scenario_cfg = scenario_rules.get(str(scenario_id), {})
    return scenario_cfg.get("mandatory_eb", {})

def get_fallback_rules(scenario_rules, scenario_id):
    scenario_cfg = scenario_rules.get(str(scenario_id), {})
    return scenario_cfg.get("fallback", {})

def expand_parent_scenarios(scenarios, scenario_rules):
    """
    Expands parent scenarios (e.g. 1) into all sub-scenarios
    (e.g. 1.1, 1.2, ...) based on scenario_rules keys.
    """

    expanded = set()

    for scenario in scenarios:
        # If scenario is an integer (parent like 1)
        if isinstance(scenario, int):
            prefix = f"{scenario}."

            # Find all sub-scenarios starting with "1."
            for key in scenario_rules.keys():
                if key.startswith(prefix):
                    expanded.add(float(key))

        else:
            # Already a sub-scenario (e.g. 1.2)
            expanded.add(float(scenario))

    return sorted(expanded)
