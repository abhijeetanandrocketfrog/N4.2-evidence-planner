from core.evidence_engine import EvidenceEngine
from utils.helper import (
    get_db_connection,
    parse_atomic_questions,
    pretty_print,
    dump_unique_eb_blocks,
)
import yaml


def main():
    member_id = "FAKE-1243781181_ALEX_ELIZABETH_BUTTERFISH"
    scenarios = ["1.2"]

    atomic_questions_input = {
    "Atomic_Questions": [
        {
            "eb_filters": [
            "EB01: Deductible",
            "EB02: Individual",
            "EB02: Individual and Children",
            "EB02: Individual and Spouse",
            "EB02: Individual Only",
            "EB03: Audiology Exam",
            "EB03: Consultation",
            "EB03: Diagnostic Lab",
            "EB03: Diagnostic Medical",
            "EB03: Independent Medical Evaluation",
            "EB03: Infertility",
            "EB03: Invasive Procedures",
            "EB03: Oncology",
            "EB03: Pathology",
            "EB03: Physical Therapy",
            "EB03: Professional (Physician)",
            "EB03: Pulmonary",
            "EB03: Screening laboratory",
            "EB03: Surgical Benefits - Professional (Physician)"
            ],
            "extracted_terms": [
            "deductible",
            "my",
            "pcp",
            "specialist",
            "genetic testing"
            ]
        }
    ]
    }


    eb03_terms, extracted_terms = parse_atomic_questions(atomic_questions_input)

    conn = get_db_connection()

    with open("config/config.yaml") as f:
        config = yaml.safe_load(f)

    engine = EvidenceEngine(
        conn,
        config["paths"]["dsl"],
        config["paths"]["fts_sql"]
    )

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
