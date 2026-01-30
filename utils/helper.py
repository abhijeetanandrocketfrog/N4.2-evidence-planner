import json
import hashlib


def clean_block(block):
    block.pop("_structured_match", None)
    block.pop("_fts_score", None)
    return block

def get_plan_block_signature(row):
    """
    Create a stable signature for PLAN_LEVEL blocks based only
    on REF and DTP segments (order-independent).
    """
    ref = row.get("REF", [])
    dtp = row.get("DTP", [])

    ref_sig = sorted(json.dumps(r, sort_keys=True) for r in ref)
    dtp_sig = sorted(json.dumps(d, sort_keys=True) for d in dtp)

    return hashlib.md5(
        json.dumps({"REF": ref_sig, "DTP": dtp_sig}).encode()
    ).hexdigest()


def get_row_hash(row):
    """
    Generic row hash.
    Uses special signature for PLAN blocks,
    normal hash for EB blocks without id.
    """
    if "REF" in row or "DTP" in row:
        return get_plan_block_signature(row)

    return hashlib.md5(
        json.dumps(row, sort_keys=True).encode()
    ).hexdigest()


def build_unique_eb_data(input_path, output_path):
    """
    Reads output.json (planner format) and writes a deduplicated
    eb_data.json containing ALL unique EB/PLAN blocks
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
    for group in primary_evidence:
        for row in group.get("rows", []):
            block_id = row.get("id")

            if block_id is not None:
                if block_id in seen_ids:
                    continue
                seen_ids.add(block_id)
                unique_blocks.append(clean_block(row.copy()))
            else:
                row_hash = get_row_hash(row)
                if row_hash in seen_hashes:
                    continue
                seen_hashes.add(row_hash)
                unique_blocks.append(clean_block(row.copy()))

    print(f"[DEBUG] Primary evidence processed")

    # --------------------------------------------------
    # SECONDARY evidence
    # --------------------------------------------------
    print(f"[DEBUG] Secondary evidence blocks: {len(secondary_rows)}")

    for row in secondary_rows:
        block_id = row.get("id")

        if block_id is not None:
            if block_id in seen_ids:
                continue
            seen_ids.add(block_id)
            unique_blocks.append(clean_block(row.copy()))
        else:
            row_hash = get_row_hash(row)
            if row_hash in seen_hashes:
                continue
            seen_hashes.add(row_hash)
            unique_blocks.append(clean_block(row.copy()))

    # --------------------------------------------------
    # Final stats
    # --------------------------------------------------
    print(f"Distinct EB/PLAN blocks found: {len(unique_blocks)}")

    # --------------------------------------------------
    # Write final EB data
    # --------------------------------------------------
    with open(output_path, "w") as f:
        json.dump(unique_blocks, f, indent=2, default=str)