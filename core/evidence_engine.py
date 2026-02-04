import json
import textwrap
from typing import List, Set


class EvidenceEngine:
    def __init__(self, db_conn, dsl_path: str, fts_sql_path: str):
        self.conn = db_conn

        with open(dsl_path, "r") as f:
            self.dsl = json.load(f)

        self.common_blocks = self.dsl["common_blocks"]
        self.scenarios = self.dsl["scenarios"]

        with open(fts_sql_path, "r") as f:
            self.fts_query = f.read()


    # =========================================================
    # PUBLIC ENTRY
    # =========================================================
    def run(self, member_id: str, scenarios: List[str],
            eb03_terms: List[str], extracted_terms: List[str]):

        self.fts_eb03_terms = eb03_terms
        self.extracted_terms = extracted_terms

        required_eb03s = self._compute_required_eb03s(scenarios, eb03_terms)
        eb_blocks = self._fetch_eb_blocks(member_id, required_eb03s)

        results = {}

        for scenario in scenarios:
            scenario_def = self.scenarios[scenario]
            scope = scenario_def.get("scope")

            results[scenario] = {}

            print(f"\n================ Scenario {scenario} ================")

            # ------------------------------------------------------
            # PLAN ACTIVE CHECK — RUN ONCE PER SCENARIO
            # ------------------------------------------------------
            plan_status, plan_blocks = self._run_prior_check(
                "plan_active_check", None, eb_blocks
            )

            print(f"[Prior Check: plan_active_check] -> {plan_status}")

            # If plan is inactive / non-covered → no need to run EB03 logic
            if plan_status in ["Inactive", "Non-Covered"]:
                if scope == "plan":
                    results[scenario]["blocks"] = plan_blocks
                else:
                    for eb03 in eb03_terms:
                        results[scenario][eb03] = plan_blocks
                continue

            # ---------------- PLAN LEVEL ----------------
            if scope == "plan":
                print(f"\n----- Scenario {scenario} (Plan Level) -----")
                blocks = self._execute_scenario(
                    scenario, None, eb_blocks, member_id
                )
                results[scenario]["blocks"] = blocks

            # ---------------- SERVICE LEVEL ----------------
            elif scope == "service":
                for eb03 in eb03_terms:
                    print(f"\n----- Scenario {scenario} | EB03: {eb03} -----")

                    blocks = self._execute_scenario(
                        scenario, eb03, eb_blocks, member_id
                    )

                    results[scenario][eb03] = blocks

                # FTS runs once per scenario
                fts_blocks = self._run_fts_for_scenario(member_id, scenario)
                results[scenario]["fts"] = fts_blocks

        return results


    # =========================================================
    # EB03 UNIVERSE
    # =========================================================
    def _compute_required_eb03s(self, scenarios, eb03_terms):
        eb03s = set(eb03_terms)

        fetch_all = False

        for sc in scenarios:
            for step in self.scenarios[sc]["flow"]:

                # ----------------------------
                # PRIOR CHECK EB03 NEEDS
                # ----------------------------
                if "prior_check" in step:
                    check_name = step["prior_check"]
                    check_def = self.common_blocks.get(check_name, {})

                    if check_def.get("check") == "plan_status":
                        eb03s.add(check_def["match"]["EB03"])

                    if check_def.get("check") == "service_status":
                        eb03s.update(eb03_terms)

                # ----------------------------
                # retrieve EB03
                # ----------------------------
                if step.get("type") == "retrieve":
                    if step.get("EB03") == "any":
                        fetch_all = True
                    elif step.get("EB03") not in ["input", None]:
                        eb03s.add(step["EB03"])

                # ----------------------------
                # fallback EB03
                # ----------------------------
                fb = step.get("fallback", {})
                if fb.get("EB03") == "any":
                    fetch_all = True
                elif fb.get("EB03") not in ["input", None]:
                    eb03s.add(fb["EB03"])

        if fetch_all:
            return None

        return eb03s


    # =========================================================
    # EB01 UNIVERSE
    # =========================================================
    def _compute_required_eb01s(self, scenarios: List[str]) -> Set[str]:
        eb01s = set()

        for check in ["plan_active_check", "service_active_check"]:
            for status in ["Active", "Inactive", "Non-Covered"]:
                eb01s.update(
                    self.common_blocks[check][status]["EB01"]
                )

        for sc in scenarios:
            for step in self.scenarios[sc]["flow"]:
                if step.get("EB01"):
                    eb01s.add(step["EB01"])

        return eb01s

    # =========================================================
    # Prior Check
    # =========================================================
    def _run_prior_check(self, check_name, eb03, eb_blocks):
        check_def = self.common_blocks[check_name]

        if check_def["check"] == "plan_status":
            target_eb03 = check_def["match"]["EB03"]
            filtered = [b for b in eb_blocks if b.get("EB03") == target_eb03]
            return self._check_status(check_def, filtered)

        if check_def["check"] == "service_status":
            filtered = [b for b in eb_blocks if b.get("EB03") == eb03]
            return self._check_status(check_def, filtered)

    def _get_service_status_blocks(self, eb03, eb_blocks):
        check_def = self.common_blocks["service_active_check"]

        active_set = set(check_def["Active"]["EB01"])
        inactive_set = set(check_def["Inactive"]["EB01"])
        noncovered_set = set(check_def["Non-Covered"]["EB01"])

        relevant = []

        for b in eb_blocks:
            if b.get("EB03") != eb03:
                continue

            eb01 = b.get("EB01")

            if eb01 in active_set or eb01 in inactive_set or eb01 in noncovered_set:
                relevant.append(b)

        return relevant


    # =========================================================
    # SCENARIO EXECUTION
    # =========================================================
    def _execute_scenario(self, scenario_key, eb03, eb_blocks, member_id):
        scenario = self.scenarios[scenario_key]
        evidence = []

        # ---------------------------------------
        # Add service status evidence only if service scope
        # ---------------------------------------
        if scenario.get("scope") == "service":
            service_blocks = self._get_service_status_blocks(eb03, eb_blocks)
            print(f"[Service Status Evidence] Found {len(service_blocks)} blocks")
            evidence.extend(service_blocks)

        # ---------------------------------------
        # Run scenario flow for ALL scopes
        # ---------------------------------------
        for step in scenario["flow"]:

            # -------- PRIOR CHECKS --------
            if "prior_check" in step:

                # Skip plan_active_check here (already done in run())
                if step["prior_check"] == "plan_active_check":
                    continue

                status, blocks = self._run_prior_check(
                    step["prior_check"],
                    eb03,
                    eb_blocks
                )

                print(f"[Prior Check: {step['prior_check']}] -> {status}")
                evidence.extend(blocks)

                if status in ["Inactive", "Non-Covered"]:
                    return evidence

            # -------- HL LOOKUP --------
            elif step.get("type") == "hl_lookup":
                found, missing = self._hl_lookup(member_id, step.get("segments", []))

                if found:
                    evidence.append(found)

                # Only run fallback if something is missing
                if missing and "fallback" in step:
                    print("[HL Partial] Missing segments → triggering fallback")
                    fb = step["fallback"]
                    fb_blocks = self._retrieve(fb, eb03, eb_blocks, member_id)
                    evidence.extend(fb_blocks)


            # -------- RETRIEVE --------
            elif step.get("type") == "retrieve":
                blocks = self._retrieve(step, eb03, eb_blocks, member_id)
                print(f"[Structured Retrieve] Found {len(blocks)} blocks")

                evidence.extend(blocks)
                if blocks:
                    return evidence

                # -------- FALLBACK / REDIRECT --------
                if "fallback" in step:
                    fb = step["fallback"]

                    if fb.get("redirect"):
                        print(f"[Redirect] -> Scenario {fb['redirect']}")
                        return self._execute_scenario(
                            fb["redirect"], eb03, eb_blocks, member_id
                        )

                    if fb.get("type") == "retrieve":
                        fb_blocks = self._retrieve(fb, eb03, eb_blocks, member_id)
                        print(f"[Fallback Structured Retrieve] Found {len(fb_blocks)} blocks")

                        evidence.extend(fb_blocks)

                        return evidence

        return evidence

    # =========================================================
    # STATUS CHECK USING DSL
    # =========================================================
    def _check_status(self, check_def, blocks):
        if not blocks:
            return "Unknown", []

        for status in ["Active", "Inactive", "Non-Covered"]:
            allowed = set(check_def.get(status, {}).get("EB01", []))
            matched = [b for b in blocks if b.get("EB01") in allowed]
            if matched:
                return status, matched

        return "Unknown", []

    # =========================================================
    # RETRIEVE
    # =========================================================
    def _retrieve(self, step, eb03, eb_blocks, member_id):
        target_eb03 = eb03 if step.get("EB03") == "input" else step.get("EB03")
        target_eb01 = step.get("EB01")
        segments = step.get("segments", [])

        structured = []
        for block in eb_blocks:
            if target_eb03 != "any":
                if block.get("EB03", "").strip() != target_eb03.strip():
                    continue

            if target_eb01 and block.get("EB01") != target_eb01:
                continue

            if segments and not any(seg in block for seg in segments):
                continue

            structured.append(block)

        return structured


    # =========================================================
    # FETCH EB Blocks
    # =========================================================
    def _fetch_eb_blocks(self, member_id: str, eb03s: Set[str] | None):
        if eb03s is None:
            query = textwrap.dedent("""
                SELECT data
                FROM eb_blocks_v5
                WHERE member_id = %s;
            """)
            params = (member_id,)
        else:
            query = textwrap.dedent("""
                SELECT data
                FROM eb_blocks_v5
                WHERE member_id = %s
                AND data->>'EB03' = ANY(%s);
            """)
            params = (member_id, list(eb03s))

        with self.conn.cursor() as cur:
            self._log_sql(cur, query, params)
            cur.execute(query, params)
            rows = cur.fetchall()

        return [row[0] for row in rows]


    # =========================================================
    # HL 3/4 Lookup
    # =========================================================
    def _hl_lookup(self, member_id, segments):
        query = textwrap.dedent("""
            SELECT patient_space
            FROM patient_space_v01
            WHERE member_id = %s;
        """)

        with self.conn.cursor() as cur:
            self._log_sql(cur, query, (member_id,))
            cur.execute(query, (member_id,))
            rows = cur.fetchall()

        found = {}
        missing = set(segments)

        for row in rows:
            ps = row[0]
            nm1 = ps.get("NM1", {})

            for seg in segments:
                if seg in nm1:
                    found[seg] = nm1[seg]
                    missing.discard(seg)

        print(f"[HL Lookup] Found segments: {list(found.keys())}")
        print(f"[HL Lookup] Missing segments: {list(missing)}")

        return found, list(missing)

    # =========================================================
    # FTS Retrieve
    # =========================================================
    def _run_fts_for_scenario(self, member_id, scenario):
        eb01_list = list(self._compute_required_eb01s([scenario]))
        eb03_list = list(self.fts_eb03_terms)

        params = {
            "eb03_query": " OR ".join(self.fts_eb03_terms),
            "extracted_query": " OR ".join(self.extracted_terms),
            "member_id": member_id,
            "eb01_list": eb01_list,
            "eb03_list": eb03_list,
        }

        with self.conn.cursor() as cur:
            self._log_sql(cur, self.fts_query, params)
            cur.execute(self.fts_query, params)
            rows = cur.fetchall()

        print(f"\n----- Scenario {scenario} | FTS Retrieve -----")
        print(f"[FTS Retrieve] Found {len(rows)} blocks")

        return [row[0] for row in rows]

    # =========================================================
    # SQL Query Logging
    # =========================================================
    def _log_sql(self, cur, query, params):
        try:
            rendered = cur.mogrify(query, params).decode()
            print("\n"+"-"*80)
            print("[SQL EXECUTED]")
            print(rendered)
            print("-"*80)
        except Exception as e:
            print(f"[SQL LOG ERROR] {e}")

