-- Copyright 2026 The radiusward Authors
-- SPDX-License-Identifier: Apache-2.0
--
-- Example queries on the exported accounting (docs/operations/export.md):
--   docker compose -f deploy/compose/compose.yaml exec postgres psql -U radiusward radius -f /sql/examples.sql

\echo '-- sessions online per NAS'
SELECT nas_id, count(*) AS online
FROM accounting_session WHERE stopped_at IS NULL GROUP BY nas_id ORDER BY online DESC;

\echo '-- top users by traffic (closed and open sessions)'
SELECT user_name, count(*) AS sessions, sum(input_octets + output_octets) AS bytes
FROM accounting_session GROUP BY user_name ORDER BY bytes DESC LIMIT 10;

\echo '-- sessions closed today, by cause'
SELECT CASE close_cause WHEN 1 THEN 'stop' WHEN 2 THEN 'nas restart' WHEN 3 THEN 'idle timeout' ELSE 'other' END AS cause,
       count(*)
FROM accounting_session WHERE stopped_at >= date_trunc('day', now()) GROUP BY 1;

\echo '-- the FreeRADIUS view (radacct.view=true)'
SELECT acctsessionid, username, acctstarttime, acctstoptime, acctsessiontime, acctinputoctets, acctoutputoctets
FROM radacct ORDER BY acctupdatetime DESC LIMIT 5;

\echo '-- exporter progress'
SELECT sink, position, epoch, updated_at FROM sink_checkpoint;
