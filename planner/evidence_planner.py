from utils.db import get_db_connection
from utils.scenario_rules import get_mandatory_eb, get_fallback_rules
from utils.ps_loader import load_active_ps_benefits
from utils.sql_loader import load_sql


# ----------------------------
# Helper: extract EB03 values
# ----------------------------
def extract_eb03_values(atomic_questions):
    eb03_values = set()
    for aq in atomic_questions:
        for f in aq.get("eb_filters", []):
            if f.startswith("EB03:"):
                eb03_values.add(f.replace("EB03:", "").strip())
    return eb03_values


# ----------------------------
# Helper: build query for one scenario
# ----------------------------

def collect_rows_for_scenario(
    member_id,
    eb03_values,
    atomic_questions,
    scenario_id,
    scenario_rules
):
    # ----------------------------
    # Mandatory EB rules
    # ----------------------------
    mandatory_eb = get_mandatory_eb(scenario_rules, scenario_id)
    eb01_values = mandatory_eb.get("EB01", [])

    if not eb03_values or not eb01_values:
        return None, []

    # ----------------------------
    # Build FTS inputs
    # ----------------------------
    eb03_terms = [
        f.replace("EB03:", "").strip()
        for aq in atomic_questions
        for f in aq.get("eb_filters", [])
        if f.startswith("EB03:")
    ]

    extracted_terms = [
        t
        for aq in atomic_questions
        for t in aq.get("extracted_terms", [])
    ]

    q_eb03_fts = " OR ".join(eb03_terms)
    q_extracted_fts = " OR ".join(extracted_terms)

    # ----------------------------
    # Build placeholders
    # ----------------------------
    eb03_placeholders = ", ".join(["%s"] * len(eb03_values))
    eb01_placeholders = ", ".join(["%s"] * len(eb01_values))

    # ----------------------------
    # Load & render SQL
    # ----------------------------
    sql_template = load_sql()

    query = sql_template.format(
        eb03_placeholders=eb03_placeholders,
        eb01_placeholders=eb01_placeholders
    )

    # ----------------------------
    # PARAM
    # ----------------------------
    params = []
    # 1: structured_match EB03
    params.extend(eb03_values)
    # 2: structured_match EB01
    params.extend(eb01_values)
    # 3: fts_eb03_score query
    params.append(q_eb03_fts)
    # 4: fts_extracted_score query
    params.append(q_extracted_fts)
    # 5: member_id
    params.append(member_id)
    # 6: FTS guard EB01
    params.extend(eb01_values)
    # 7: FTS guard EB03
    params.extend(eb03_values)
    
    return query, params

# ----------------------------
# Prior check for the scenario
# ----------------------------
def fetch_prior_check_blocks(cursor, member_id, eb03_values, scenario_rules, scenarios):
    """
    SQL CALL 1:
    Fetch all EB blocks needed for prior_check classification.
    """

    # Collect all EB01 values mentioned in prior_check rules
    eb01_values = set()
    for scenario_id in scenarios:
        rules = scenario_rules[str(scenario_id)].get("prior_check", {}).get("rules", [])
        for rule in rules:
            for field, vals in rule.get("conditions", {}).items():
                if field == "EB01":
                    eb01_values.update(vals)

    if not eb01_values:
        return {}

    eb03_placeholders = ", ".join(["%s"] * len(eb03_values))
    eb01_placeholders = ", ".join(["%s"] * len(eb01_values))

    query = f"""
        SELECT data
        FROM eb_blocks_v3
        WHERE member_id = %s
          AND data->>'EB03' IN ({eb03_placeholders})
          AND data->>'EB01' IN ({eb01_placeholders});
    """

    params = [member_id]
    params.extend(eb03_values)
    params.extend(eb01_values)

    cursor.execute(query, params)
    rows = cursor.fetchall()

    # Group blocks by EB03
    prior_map = {eb03: [] for eb03 in eb03_values}
    for (data,) in rows:
        eb03 = data.get("EB03")
        if eb03 in prior_map:
            prior_map[eb03].append(data)

    return prior_map


def evaluate_prior_check(blocks, prior_check):
    """
    Determines whether mandatory EB logic should run for an EB03,
    while preserving all prior-check blocks.
    """
    rules = prior_check.get("rules", [])

    active_rules = [
        rule for rule in rules
        if rule.get("state") == "active"
    ]

    has_active = False

    for block in blocks:
        for rule in active_rules:
            if all(
                block.get(field) in allowed
                for field, allowed in rule.get("conditions", {}).items()
            ):
                has_active = True
                break
        if has_active:
            break

    return {
        "has_active": has_active,
        "prior_blocks": blocks
    }


# ----------------------------
# Main planner: multi-scenario, grouped by EB03
# ----------------------------
def block_matches_fallback(block, fallback_rules):
    """
    A block matches fallback ONLY if it satisfies ALL fallback constraints.
    """
    for eb_key, allowed_values in fallback_rules.items():
        # Missing key OR value not allowed → reject
        if block.get(eb_key) not in allowed_values:
            return False
    return True

def run_evidence_planner(member_id, atomic_questions, scenarios, scenario_rules):
    eb03_values = extract_eb03_values(atomic_questions)
    if not eb03_values or not scenarios:
        return []

    conn = get_db_connection()
    cursor = conn.cursor()

    # --------------------------------------------------
    # SQL CALL 1: PRIOR CHECK BLOCKS
    # --------------------------------------------------
    prior_blocks_map = fetch_prior_check_blocks(
        cursor,
        member_id,
        eb03_values,
        scenario_rules,
        scenarios
    )

    # --------------------------------------------------
    # Evaluate prior_check PER EB03 across ALL scenarios
    # --------------------------------------------------
    eb03_status_map = {}

    for eb03 in eb03_values:
        blocks = prior_blocks_map.get(eb03, [])

        has_active = False
        for scenario_id in scenarios:
            prior_check = scenario_rules[str(scenario_id)]["prior_check"]
            result = evaluate_prior_check(blocks, prior_check)
            if result["has_active"]:
                has_active = True
                break

        eb03_status_map[eb03] = {
            "has_active": has_active,
            "prior_blocks": blocks
        }

    # --------------------------------------------------
    # Prepare evidence map
    # --------------------------------------------------
    evidence_map = {
        eb03: {
            "rows": [],
            "seen_ids": set(),
            "scenario_hits": set()
        }
        for eb03 in eb03_values
    }

    # --------------------------------------------------
    # ALWAYS store prior-check blocks (no filtering)
    # --------------------------------------------------
    for eb03, status in eb03_status_map.items():
        for block in status["prior_blocks"]:
            block_id = block.get("id")
            if block_id is None or block_id not in evidence_map[eb03]["seen_ids"]:
                evidence_map[eb03]["rows"].append(block)
                if block_id is not None:
                    evidence_map[eb03]["seen_ids"].add(block_id)

    # --------------------------------------------------
    # SQL CALL 2: MANDATORY EB (only if EB03 is active OR no prior blocks)
    # --------------------------------------------------
    for scenario_id in scenarios:
        active_eb03s = [
            eb03
            for eb03, status in eb03_status_map.items()
            if status["has_active"] or not status["prior_blocks"]
        ]

        if not active_eb03s:
            continue

        query, params = collect_rows_for_scenario(
            member_id,
            active_eb03s,
            atomic_questions,
            scenario_id,
            scenario_rules
        )

        cursor.execute(query, params)

        # print("\n================ EXECUTING SQL ================\n")
        # rendered_query = cursor.mogrify(query, params).decode("utf-8")
        # print(rendered_query)
        # print("\n==============================================\n")


        rows = cursor.fetchall()
        column_names = [desc[0] for desc in cursor.description]

        mandatory_eb = get_mandatory_eb(scenario_rules, scenario_id)
        allowed_eb01 = set(mandatory_eb.get("EB01", []))

        for row in rows:
            row_dict = dict(zip(column_names, row))
            data_payload = row_dict.get("data")
            if not data_payload:
                continue

            eb03 = data_payload.get("EB03")
            if eb03 not in active_eb03s:
                continue

            block_id = data_payload.get("id")

            if block_id is None or block_id not in evidence_map[eb03]["seen_ids"]:
                evidence_map[eb03]["rows"].append(data_payload)
                if block_id is not None:
                    evidence_map[eb03]["seen_ids"].add(block_id)

            if data_payload.get("EB01") in allowed_eb01:
                evidence_map[eb03]["scenario_hits"].add(scenario_id)

    cursor.close()
    conn.close()

    # --------------------------------------------------
    # FALLBACK (only when mandatory EB did NOT hit)
    # --------------------------------------------------
    ps_blocks = load_active_ps_benefits(member_id)

    if ps_blocks:
        for eb03, data in evidence_map.items():
            status = eb03_status_map.get(eb03)

            # No active coverage AND prior blocks exist → no fallback
            if not status["has_active"] and status["prior_blocks"]:
                continue

            for scenario_id in scenarios:
                if scenario_id in data["scenario_hits"]:
                    continue

                fallback_rules = get_fallback_rules(scenario_rules, scenario_id)
                if not fallback_rules:
                    continue

                for block in ps_blocks:
                    if not block_matches_fallback(block, fallback_rules):
                        continue

                    block_id = block.get("id")
                    if block_id is None or block_id not in data["seen_ids"]:
                        data["rows"].append(block)
                        if block_id is not None:
                            data["seen_ids"].add(block_id)

    # --------------------------------------------------
    # Final output
    # --------------------------------------------------
    return [
        {"eb03": eb03, "rows": data["rows"]}
        for eb03, data in evidence_map.items()
    ]
