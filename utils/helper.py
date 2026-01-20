import json
import hashlib


def build_unique_eb_data(input_path, output_path):
    """
    Reads output.json (current planner format) and writes a deduplicated
    eb_data.json containing ALL unique EB blocks
    (primary + secondary).
    """

    with open(input_path, "r") as f:
        data = json.load(f)

    evidence = data.get("evidence", {})

    primary_evidence = evidence.get("primary_evidence", [])
    secondary_rows = evidence.get("secondary_evidence", {}).get("rows", [])

    unique_blocks = []
    seen_ids = set()
    seen_hashes = set()

    # --------------------------------------------------
    # PRIMARY evidence
    # --------------------------------------------------
    primary_row_count = sum(
        len(group.get("rows", []))
        for group in primary_evidence
    )

    print(f"[DEBUG] Primary evidence rows: {primary_row_count}")

    for group in primary_evidence:
        for row in group.get("rows", []):
            block_id = row.get("id")

            if block_id is not None:
                if block_id in seen_ids:
                    continue
                seen_ids.add(block_id)
                unique_blocks.append(row)
            else:
                row_hash = hashlib.md5(
                    json.dumps(row, sort_keys=True).encode()
                ).hexdigest()

                if row_hash in seen_hashes:
                    continue

                seen_hashes.add(row_hash)
                unique_blocks.append(row)

    # --------------------------------------------------
    # SECONDARY evidence (MSG / FTS)
    # --------------------------------------------------
    print(f"[DEBUG] Secondary evidence rows: {len(secondary_rows)}")

    for row in secondary_rows:
        block_id = row.get("id")

        if block_id is not None:
            if block_id in seen_ids:
                continue
            seen_ids.add(block_id)
            unique_blocks.append(row)
        else:
            row_hash = hashlib.md5(
                json.dumps(row, sort_keys=True).encode()
            ).hexdigest()

            if row_hash in seen_hashes:
                continue

            seen_hashes.add(row_hash)
            unique_blocks.append(row)

    # --------------------------------------------------
    # Final stats
    # --------------------------------------------------
    print(f"Distinct EB blocks found: {len(unique_blocks)}")

    # --------------------------------------------------
    # Write final EB data
    # --------------------------------------------------
    with open(output_path, "w") as f:
        json.dump(unique_blocks, f, indent=2, default=str)
