import json

SCENARIO_RULES_PATH = "config/evidence_planner.json"

def load_scenario_rules():
    with open(SCENARIO_RULES_PATH, "r") as f:
        return json.load(f)

def get_mandatory(scenario_rules, scenario_id):
    scenario_cfg = scenario_rules.get(str(scenario_id), {})
    return scenario_cfg.get("mandatory", {})

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


def load_plan_level_fallback_blocks(cursor, member_id, fallback_rules):
    """
    Generic plan-level fallback based on scenario_rules JSON.
    Looks for EB blocks where EB03 matches fallback rules
    and required segments are present.
    """

    eb03_values = fallback_rules.get("EB03", [])
    if not eb03_values:
        return []

    placeholders = ", ".join(["%s"] * len(eb03_values))

    query = f"""
        SELECT data
        FROM eb_blocks_v3
        WHERE member_id = %s
          AND data->>'EB03' IN ({placeholders});
    """

    params = [member_id] + eb03_values
    cursor.execute(query, params)
    rows = cursor.fetchall()

    result = []
    for (data,) in rows:
        if not data:
            continue

        # Check for presence of plan segments dynamically
        has_ref = bool(data.get("REF"))
        has_dtp = bool(data.get("DTP"))

        if has_ref or has_dtp:
            result.append(data)

    return result

def collect_service_segments_for_eb03(cursor, member_id, eb03_value, segments):
    """
    Used for service-scope scenarios where mandatory = SEGMENTS.
    Fetch blocks for that EB03 and return ones having required segments.
    """

    query = """
        SELECT data
        FROM eb_blocks_v3
        WHERE member_id = %s
          AND data->>'EB03' = %s;
    """

    cursor.execute(query, [member_id, eb03_value])
    rows = cursor.fetchall()

    result = []

    for (data,) in rows:
        if not data:
            continue

        # keep block if it has ANY of required segments
        if any(data.get(seg) for seg in segments):
            result.append(data)

    return result
