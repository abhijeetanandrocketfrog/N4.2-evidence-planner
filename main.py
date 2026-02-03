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
    member_id = "FAKE-0034517234_ARIANNA_JACOB_WEEVER"
    scenarios = ["1"]

    atomic_questions_input = {
    "Atomic_Questions": [
        {
            "eb_filters": [
            "EB01: Limitations",
            "EB02: Individual",
            "EB02: Individual and Children",
            "EB02: Individual and Spouse",
            "EB02: Individual Only",
            "EB03: Occupational Therapy",
            "EB03: Physical Therapy",
            "EB03: Psychotherapy",
            "EB03: Speech Therapy",
            "EB06: Calendar Year",
            "EB06: Contract",
            "EB06: Service Year",
            "EB06: Year to Date",
            "EB06: Years"
            ],
            "extracted_terms": [
            "total amount i would be responsible for covering all pt sessions",
            "i",
            "pt sessions",
            "plan year"
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
