-- radiusward PostgreSQL sink, schema version 3: Acct-Multi-Session-Id (RFC 2866 §5.11)
-- links the sessions of one client across access points (roaming) or links (multilink)

ALTER TABLE accounting_session ADD COLUMN acct_multi_session_id text;
ALTER TABLE accounting_event ADD COLUMN acct_multi_session_id text;

-- set once per session, so the index does not stop updates from being HOT
CREATE INDEX accounting_session_multi ON accounting_session (acct_multi_session_id)
    WHERE acct_multi_session_id IS NOT NULL;
