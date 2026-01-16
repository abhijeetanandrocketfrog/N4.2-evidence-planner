import json
import os

PS_FOLDER = "/home/abhijeet_anand/Workspace/Patient Space/output"

def load_active_ps_benefits(member_id):
    """
    Loads all raw_eligibility_benefit blocks from ACTIVE plans
    in the member's PS file.
    """
    ps_file = os.path.join(PS_FOLDER, f"{member_id}_ps.json")

    if not os.path.exists(ps_file):
        return []

    with open(ps_file, "r") as f:
        plans = json.load(f)

    active_blocks = []

    for plan in plans:
        if plan.get("status") != "ACTIVE":
            continue

        reb = plan.get("raw_eligibility_benefit", [])
        active_blocks.extend(reb)

    return active_blocks
