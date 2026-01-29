from utils.db import get_db_connection
from utils.scenario_rules import get_mandatory, get_fallback_rules, load_plan_level_fallback_blocks
from utils.ps_loader import load_active_ps_benefits, load_patient_space_segments
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

def collect_plan_level_rows(member_id, scenario_id, scenario_rules):
    mandatory = get_mandatory(scenario_rules, scenario_id)
    segments = mandatory.get("SEGMENTS", [])

    if not segments:
        return None

    ps_data = load_patient_space_segments(member_id, segments)
    return ps_data


def collect_service_level_rows(
    member_id,
    eb03_values,
    atomic_questions,
    scenario_id,
    scenario_rules
):
    mandatory = get_mandatory(scenario_rules, scenario_id)
    eb01_values = mandatory.get("EB01", [])

    if not eb03_values or not eb01_values:
        return None

    # -------- FTS terms --------
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

    # -------- SQL --------
    eb03_placeholders = ", ".join(["%s"] * len(eb03_values))
    eb01_placeholders = ", ".join(["%s"] * len(eb01_values))

    sql_template = load_sql()

    query = sql_template.format(
        eb03_placeholders=eb03_placeholders,
        eb01_placeholders=eb01_placeholders
    )

    params = []
    params.extend(eb03_values)
    params.extend(eb01_values)
    params.append(q_eb03_fts)
    params.append(q_extracted_fts)
    params.append(member_id)
    params.extend(eb01_values)
    params.extend(eb03_values)

    return query, params

def collect_rows_for_scenario(
    member_id,
    eb03_values,
    atomic_questions,
    scenario_id,
    scenario_rules
):
    scenario_rule = scenario_rules[str(scenario_id)]

    if scenario_rule.get("scope") == "plan":
        ps_data = collect_plan_level_rows(
            member_id,
            scenario_id,
            scenario_rules
        )
        return "PLAN_LEVEL", ps_data

    return collect_service_level_rows(
        member_id,
        eb03_values,
        atomic_questions,
        scenario_id,
        scenario_rules
    )



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
    rules = prior_check.get("rules", [])

    active_rules = [
        rule for rule in rules
        if rule.get("state") == "active"
    ]

    inactive_rules = [
        rule for rule in rules
        if rule.get("state") in ("inactive", "non_covered")
    ]

    explicit_active = False
    explicit_inactive = False

    for block in blocks:
        for rule in active_rules:
            if all(
                block.get(field) in allowed
                for field, allowed in rule.get("conditions", {}).items()
            ):
                explicit_active = True
                break

        for rule in inactive_rules:
            if all(
                block.get(field) in allowed
                for field, allowed in rule.get("conditions", {}).items()
            ):
                explicit_inactive = True

    # If no explicit inactive/non-covered AND no explicit active,
    # treat as ACTIVE
    has_active = explicit_active or not explicit_inactive

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
    # --------------------------------------------------
    # Find Plan Level Scenarios
    # --------------------------------------------------
    PLAN_LEVEL_SCENARIOS = {
        float(sid)
        for sid, rule in scenario_rules.items()
        if rule.get("scope") == "plan"
    }
    print("PLAN -", PLAN_LEVEL_SCENARIOS)
    eb03_values = extract_eb03_values(atomic_questions)
    if not eb03_values or not scenarios:
        return {}

    # Phase 1: Scope extraction (currently EB03)
    scope_keys = list(eb03_values)

    if any(s in PLAN_LEVEL_SCENARIOS for s in scenarios):
        scope_keys.append("PLAN_LEVEL")

    conn = get_db_connection()
    cursor = conn.cursor()

    # --------------------------------------------------
    # Collect query terms for annotation
    # --------------------------------------------------
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
    # Evaluate "has_active" PER EB03 (across scenarios)
    # --------------------------------------------------
    scope_status_map = {}

    for scope_key in scope_keys:
        if scope_key == "PLAN_LEVEL":
            scope_status_map[scope_key] = {
                "has_active": True,
                "prior_blocks": []
            }
            continue

        blocks = prior_blocks_map.get(scope_key, [])
        has_active = False

        for scenario_id in scenarios:
            prior_check = scenario_rules[str(scenario_id)]["prior_check"]
            if evaluate_prior_check(blocks, prior_check)["has_active"]:
                has_active = True
                break

        scope_status_map[scope_key] = {
            "has_active": has_active,
            "prior_blocks": blocks
        }

    # --------------------------------------------------
    # PRIMARY evidence (EB03 scoped)
    # --------------------------------------------------
    primary_map = {
        scope_key: {
            "rows": [],
            "seen_ids": set(),
            "scenario_hits": set()
        }
        for scope_key in scope_keys
    }

    # Always include prior-check blocks in primary evidence
    for scope_key, status in scope_status_map.items():
        for block in status["prior_blocks"]:
            block_id = block.get("id")
            if block_id is None or block_id not in primary_map[scope_key]["seen_ids"]:
                primary_map[scope_key]["rows"].append(block)
                if block_id is not None:
                    primary_map[scope_key]["seen_ids"].add(block_id)


    # --------------------------------------------------
    # SQL CALL 2: Mandatory EB (ONLY if has_active or no prior data)
    # --------------------------------------------------
    for scenario_id in scenarios:
        eligible_scope_keys = [
            scope_key for scope_key, status in scope_status_map.items()
            if status["has_active"] or not status["prior_blocks"]
        ]

        if not eligible_scope_keys:
            continue

        service_scope_keys = [k for k in eligible_scope_keys if k != "PLAN_LEVEL"]

        result = collect_rows_for_scenario(
            member_id,
            service_scope_keys,
            atomic_questions,
            scenario_id,
            scenario_rules
        )

        # PLAN LEVEL result
        if result and result[0] == "PLAN_LEVEL":
            ps_data = result[1]

            # ADD THIS CHECK
            if ps_data:   # only if REF/DTP actually found
                primary_map["PLAN_LEVEL"]["rows"].append(ps_data)
                primary_map["PLAN_LEVEL"]["scenario_hits"].add(scenario_id)

            continue
        query, params = result
        if query == "PLAN_LEVEL" or not query:
            continue

        cursor.execute(query, params)


        # print("\n================ EXECUTING SQL ================\n")
        # rendered_query = cursor.mogrify(query, params).decode("utf-8")
        # print(rendered_query)
        # print("\n==============================================\n")


        rows = cursor.fetchall()
        column_names = [desc[0] for desc in cursor.description]

        mandatory = get_mandatory(scenario_rules, scenario_id)
        allowed_eb01 = set(mandatory.get("EB01", []))

        for row in rows:
            row_dict = dict(zip(column_names, row))
            data = row_dict.get("data")
            if not data:
                continue

            scope_key = data.get("EB03")
            if scope_key not in primary_map:
                continue

            block_id = data.get("id")

            if block_id is None or block_id not in primary_map[scope_key]["seen_ids"]:
                primary_map[scope_key]["rows"].append(data)
                if block_id is not None:
                    primary_map[scope_key]["seen_ids"].add(block_id)

            if data.get("EB01") in allowed_eb01:
                primary_map[scope_key]["scenario_hits"].add(scenario_id)

    cursor.close()
    conn.close()

    # --------------------------------------------------
    # FALLBACK (ONLY if mandatory EB not satisfied)
    # --------------------------------------------------
    # ---------------- PLAN LEVEL FALLBACK (separate from service fallback) ----------------
    if "PLAN_LEVEL" in primary_map:
        for scenario_id in scenarios:
            if scenario_id not in PLAN_LEVEL_SCENARIOS:
                continue
            
            if scenario_id in primary_map["PLAN_LEVEL"]["scenario_hits"]:
                continue
            
            fallback_rules = get_fallback_rules(scenario_rules, scenario_id)
            if not fallback_rules:
                continue

            conn = get_db_connection()
            cursor = conn.cursor()

            plan_blocks = load_plan_level_fallback_blocks(
                cursor,
                member_id,
                fallback_rules
            )

            for block in plan_blocks:
                block_id = block.get("id")
                if block_id is None or block_id not in primary_map["PLAN_LEVEL"]["seen_ids"]:
                    primary_map["PLAN_LEVEL"]["rows"].append(block)
                    if block_id is not None:
                        primary_map["PLAN_LEVEL"]["seen_ids"].add(block_id)

            cursor.close()
            conn.close()
    ps_blocks = load_active_ps_benefits(member_id)

    if ps_blocks:
        for scope_key, data in primary_map.items():
            status = scope_status_map.get(
                scope_key,
                {"has_active": True, "prior_blocks": []}
            )
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
    # SECONDARY evidence (MSG / FTS only, GLOBAL)
    # --------------------------------------------------
    
    secondary_rows = []
    seen_secondary_ids = set()

    for scenario_id in scenarios:
        # Skip PLAN_LEVEL for secondary (no FTS, no EB search)
        if "PLAN_LEVEL" in scope_keys:
            scope_keys_without_plan = [k for k in scope_keys if k != "PLAN_LEVEL"]
        else:
            scope_keys_without_plan = scope_keys
        result = collect_rows_for_scenario(
            member_id,
            scope_keys_without_plan,
            atomic_questions,
            scenario_id,
            scenario_rules
        )

        if not result or result[0] == "PLAN_LEVEL":
            continue

        query, params = result
        cursor = get_db_connection().cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        column_names = [desc[0] for desc in cursor.description]

        for row in rows:
            row_dict = dict(zip(column_names, row))
            data = row_dict.get("data")
            if not data:
                continue

            block_id = data.get("id")
            if block_id in seen_secondary_ids:
                continue

            scope_key = data.get("EB03")
            if scope_key in primary_map and block_id in primary_map[scope_key]["seen_ids"]:
                continue  # already primary

            secondary_rows.append(data)
            if block_id is not None:
                seen_secondary_ids.add(block_id)

        cursor.close()

    # --------------------------------------------------
    # FINAL OUTPUT
    # --------------------------------------------------
    return {
        "primary_evidence": [
            {
                "scope": scope_key,
                "rows": data["rows"]
            }
            for scope_key, data in primary_map.items()

        ],
        "secondary_evidence": {
            "rows": secondary_rows,
            "matched_terms": {
                "eb03_terms": eb03_terms,
                "extracted_terms": extracted_terms
            }
        }
    }
