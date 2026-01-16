WITH base AS (
    SELECT
        b.*,
        (
            b.data->>'EB03' IN ({eb03_placeholders})
            AND b.data->>'EB01' IN ({eb01_placeholders})
        ) AS structured_match,

        ts_rank_cd(
            to_tsvector('english', coalesce(b.msg_text, '')),
            websearch_to_tsquery(
                'english',
                regexp_replace(%s, '\s+', ' OR ', 'g')
            )
        ) AS fts_eb03_score,

        ts_rank_cd(
            to_tsvector('english', coalesce(b.msg_text, '')),
            websearch_to_tsquery(
                'english',
                regexp_replace(%s, '\s+', ' OR ', 'g')
            )
        ) AS fts_extracted_score
    FROM eb_blocks_v3 b
    WHERE b.member_id = %s
)
SELECT *
FROM base
WHERE structured_match
   OR fts_eb03_score > 0.5
   OR fts_extracted_score > 0.5
ORDER BY
    structured_match DESC,
    fts_eb03_score DESC,
    fts_extracted_score DESC,
    inserted_at DESC,
    id ASC;
