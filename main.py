from core.evidence_engine import EvidenceEngine
from utils.helper import (
    get_db_connection,
    parse_atomic_questions,
    pretty_print,
    dump_unique_eb_blocks,
    expand_scenarios
)
import json
import yaml


def main():
    member_id = "FAKE-0595433777_KRIS_OLIVIA_AYU"
    scenarios = ["2.2", "3.1"]

    atomic_questions_input = {
    "Atomic_Questions": [
        {
            "eb_filters": [
            "EB01: Deductible",
            "EB02: Individual",
            "EB02: Individual and Children",
            "EB02: Individual and Spouse",
            "EB02: Individual Only",
            "EB03: Hospital",
            "EB03: Hospital - Outpatient",
            "EB03: Hospital - Inpatient",
            ],
            "extracted_terms": [
            ]
        }
    ]
    }


    eb03_terms, extracted_terms = parse_atomic_questions(atomic_questions_input)

    conn = get_db_connection()

    with open("config/config.yaml") as f:
        config = yaml.safe_load(f)
    with open(config["paths"]["dsl"]) as f:
        dsl = json.load(f)

    engine = EvidenceEngine(
        conn,
        config["paths"]["dsl"],
        config["paths"]["fts_sql"]
    )

    scenarios = expand_scenarios(scenarios, dsl)
    result = engine.run(
        member_id,
        scenarios,
        eb03_terms,
        extracted_terms
    )

    pretty_print(result)
    dump_unique_eb_blocks(result)


if __name__ == "__main__":
    main()
