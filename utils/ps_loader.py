import json
import os
from utils.db import get_db_connection

PS_FOLDER = "/home/abhijeet_anand/Workspace/N1-patient-space/output"

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


def load_patient_space_segments(member_id, segments):
    conn = get_db_connection()
    cursor = conn.cursor()

    query = """
        SELECT patient_space
        FROM patient_space_v01
        WHERE member_id = %s
    """

    cursor.execute(query, (member_id,))
    row = cursor.fetchone()

    cursor.close()
    conn.close()

    if not row:
        return {}

    data = row[0]  # JSON column
    nm1 = data.get("NM1", {})

    return {
        seg: nm1.get(seg)
        for seg in segments
        if seg in nm1
    }