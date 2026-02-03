import json
import yaml
import psycopg2


# ---------------- DB CONNECTION ----------------
def get_db_connection(config_path="config/config.yaml"):
    with open(config_path) as f:
        cfg = yaml.safe_load(f)

    db = cfg["database"]

    conn = psycopg2.connect(
        host=db["host"],
        dbname=db["dbname"],
        user=db["user"],
        password=db["password"],
        port=db["port"],
    )
    return conn


# ---------------- ATOMIC PARSER ----------------
def parse_atomic_questions(aq_input):
    eb03_terms = []
    extracted_terms = []

    aq = aq_input["Atomic_Questions"][0]

    for item in aq["eb_filters"]:
        if item.startswith("EB03:"):
            eb03_terms.append(item.split("EB03:")[1].strip())

    extracted_terms = aq.get("extracted_terms", [])

    return eb03_terms, extracted_terms


# ---------------- PRETTY PRINT ----------------
def pretty_print(result_dict):
    print("\n" + "=" * 80)
    print("EVIDENCE PLANNER RESULT")
    print("=" * 80)

    for scenario, data in result_dict.items():
        print(f"\nScenario: {scenario}")

        if "blocks" in data:
            blocks = data["blocks"]
            print(f"   Total Blocks Returned: {len(blocks)}")
            for i, block in enumerate(blocks, 1):
                print("\n" + "-" * 60)
                print(f" Block #{i}")
                print("-" * 60)
                print(json.dumps(block, indent=2))
        else:
            for eb03, blocks in data.items():
                if eb03 == "fts":
                    continue

                print(f"\nEB03: {eb03}")
                print(f"   Structured Blocks: {len(blocks)}")

                for i, block in enumerate(blocks, 1):
                    print("\n" + "-" * 60)
                    print(f" Block #{i}")
                    print("-" * 60)
                    print(json.dumps(block, indent=2))

            if "fts" in data:
                fts_blocks = data["fts"]
                print(f"\nScenario {scenario} | FTS Matching")
                for i, block in enumerate(fts_blocks, 1):
                    print("\n" + "-" * 60)
                    print(f" FTS Block #{i}")
                    print("-" * 60)
                    print(json.dumps(block, indent=2))

        print("\n" + "=" * 80)


# ---------------- DUMP UNIQUE BLOCKS ----------------
# def dump_unique_eb_blocks(result_dict, path="output/eb_blocks.json"):
#     unique = {}

#     for scenario, data in result_dict.items():
#         if "blocks" in data:
#             for b in data["blocks"]:
#                 unique[b["id"]] = b
#         else:
#             for key, blocks in data.items():
#                 if key == "fts":
#                     for b in blocks:
#                         unique[b["id"]] = b
#                 else:
#                     for b in blocks:
#                         unique[b["id"]] = b

#     with open(path, "w") as f:
#         json.dump(list(unique.values()), f, indent=2)

#     print(f"\nDumped {len(unique)} unique EB blocks to {path}")

def dump_unique_eb_blocks(result_dict, path="output/eb_blocks.json"):
    import json

    unique = {}

    def get_key(block):
        # EB blocks → use id
        if isinstance(block, dict) and "id" in block:
            return f"eb_{block['id']}"
        # HL / other blocks → hash by content
        return "hl_" + json.dumps(block, sort_keys=True)

    for scenario, data in result_dict.items():

        # ---------------- PLAN LEVEL ----------------
        if "blocks" in data:
            for b in data["blocks"]:
                unique[get_key(b)] = b

        # ---------------- SERVICE LEVEL ----------------
        else:
            for key, blocks in data.items():
                for b in blocks:
                    unique[get_key(b)] = b

    with open(path, "w") as f:
        json.dump(list(unique.values()), f, indent=2)

    print(f"\nDumped {len(unique)} unique blocks to {path}")


def expand_scenarios(scenarios, dsl):
    """
    Expands parent scenarios like '1' into all its sub-scenarios
    using the DSL definition.
    """
    expanded = set()

    for sc in scenarios:
        # If already sub-scenario (contains dot), keep as is
        if "." in sc:
            expanded.add(sc)
            continue

        # Expand parent scenario
        prefix = sc + "."
        for dsl_sc in dsl["scenarios"].keys():
            if dsl_sc.startswith(prefix):
                expanded.add(dsl_sc)

    return sorted(expanded)
