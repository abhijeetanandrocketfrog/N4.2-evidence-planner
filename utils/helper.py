import json
import hashlib

def build_unique_eb_data(input_path, output_path):
    """
    Reads output.json and writes a deduplicated eb_data.json
    containing all unique EB blocks.
    """

    with open(input_path, "r") as f:
        data = json.load(f)

    evidence = data.get("evidence", [])

    unique_blocks = []
    seen_ids = set()
    seen_hashes = set()

    for group in evidence:
        for row in group.get("rows", []):
            block_id = row.get("id")

            # Primary dedup: by ID
            if block_id is not None:
                if block_id in seen_ids:
                    continue
                seen_ids.add(block_id)
                unique_blocks.append(row)
            else:
                # Fallback dedup: by content hash
                row_hash = hashlib.md5(
                    json.dumps(row, sort_keys=True).encode()
                ).hexdigest()

                if row_hash in seen_hashes:
                    continue

                seen_hashes.add(row_hash)
                unique_blocks.append(row)

    # Print distinct EB block count
    print(f"Distinct EB blocks found: {len(unique_blocks)}")

    # Write JSON (unchanged behavior)
    with open(output_path, "w") as f:
        json.dump(unique_blocks, f, indent=2, default=str)
