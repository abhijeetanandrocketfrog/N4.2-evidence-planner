WITH base AS (
    SELECT
        b.data,
        ts_rank_cd(
            to_tsvector('english', coalesce(b.msg_text, '')),
            websearch_to_tsquery(
                'english',
                regexp_replace(%(eb03_query)s, '\s+', ' OR ', 'g')
            )
        ) AS fts_eb03_score,

        ts_rank_cd(
            to_tsvector('english', coalesce(b.msg_text, '')),
            websearch_to_tsquery(
                'english',
                regexp_replace(%(extracted_query)s, '\s+', ' OR ', 'g')
            )
        ) AS fts_extracted_score

    FROM eb_blocks_v5 b
    WHERE b.member_id = %(member_id)s
)
SELECT data
FROM base
WHERE
    (fts_eb03_score >= 0.1 OR fts_extracted_score >= 0.1)
    AND (
        data->>'EB01' = ANY(%(eb01_list)s)
        OR data->>'EB03' = ANY(%(eb03_list)s)
    );
