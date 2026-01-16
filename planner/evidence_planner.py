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
    params.extend(eb03_values)
    params.extend(eb01_values)
    params.append(q_eb03_fts)
    params.append(q_extracted_fts)
    params.append(member_id)

    return query, params

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

    evidence_map = {
        eb03: {
            "rows": [],
            "seen_ids": set(),
            "scenario_hits": set()
        }
        for eb03 in eb03_values
    }

    # ----------------------------
    # PRIMARY: DB retrieval
    # ----------------------------
    for scenario_id in scenarios:
        query, params = collect_rows_for_scenario(
            member_id,
            eb03_values,
            atomic_questions,
            scenario_id,
            scenario_rules
        )

        rendered_query = cursor.mogrify(query, params).decode("utf-8")
        print("\n--- EXECUTING SQL ---")
        print(rendered_query)
        print("---------------------\n")
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        column_names = [desc[0] for desc in cursor.description]


        # scenario-specific EB01 requirement
        mandatory_eb = get_mandatory_eb(scenario_rules, scenario_id)
        allowed_eb01 = set(mandatory_eb.get("EB01", []))

        for row in rows:
            row_dict = dict(zip(column_names, row))
            data_payload = row_dict.get("data")
            if not data_payload:
                continue

            eb03 = data_payload.get("EB03")
            if eb03 not in evidence_map:
                continue

            block_id = data_payload.get("id")

            # Dedup by block id
            if block_id is None or block_id not in evidence_map[eb03]["seen_ids"]:
                evidence_map[eb03]["rows"].append(data_payload)
                if block_id is not None:
                    evidence_map[eb03]["seen_ids"].add(block_id)

            # mark scenario hit ONLY if EB01 matches scenario
            if data_payload.get("EB01") in allowed_eb01:
                evidence_map[eb03]["scenario_hits"].add(scenario_id)

    cursor.close()
    conn.close()

    # ----------------------------
    # FALLBACK: scenario-aware (unchanged)
    # ----------------------------
    ps_blocks = load_active_ps_benefits(member_id)

    if ps_blocks:
        for eb03, data in evidence_map.items():
            for scenario_id in scenarios:

                # If this scenario already met → skip fallback
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

    return [
        {
            "eb03": eb03,
            "rows": data["rows"]
        }
        for eb03, data in evidence_map.items()
    ]
