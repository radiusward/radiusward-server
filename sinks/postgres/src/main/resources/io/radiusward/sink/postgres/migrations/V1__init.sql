-- radiusward PostgreSQL sink, schema version 1 (ADR 0018)

-- how far each sink got, fenced by the exporter's lease epoch
CREATE TABLE sink_checkpoint (
    sink        text PRIMARY KEY,
    position    bigint NOT NULL,
    epoch       bigint NOT NULL,
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- one row per session, like FreeRADIUS radacct; updated only by a newer projection_version.
-- No indexes on columns that change with every Interim, so updates can stay HOT.
CREATE TABLE accounting_session (
    session_key         uuid PRIMARY KEY,
    nas_id              integer NOT NULL,
    acct_session_id     text,
    user_name           text,
    calling_station_id  text,
    framed_ip           inet,
    nas_ip              inet,
    state               smallint NOT NULL,
    close_cause         smallint NOT NULL,
    terminate_cause     integer,
    status_type         smallint NOT NULL,
    session_seconds     bigint,
    input_octets        bigint NOT NULL,
    output_octets       bigint NOT NULL,
    started_at          timestamptz,
    last_received_at    timestamptz NOT NULL,
    stopped_at          timestamptz,
    quality_flags       integer NOT NULL DEFAULT 0,
    projection_version  bigint NOT NULL
) WITH (fillfactor = 80);

CREATE INDEX accounting_session_online ON accounting_session (nas_id) WHERE stopped_at IS NULL;
CREATE INDEX accounting_session_user ON accounting_session (user_name);

-- immutable history of applied (and stale) events, mode sessions+events; partitioned by commit day
CREATE TABLE accounting_event (
    commit_day          date NOT NULL,
    event_id            uuid NOT NULL,
    log_position        bigint NOT NULL,
    received_at         timestamptz NOT NULL,
    source_event_at     timestamptz,
    nas_id              integer NOT NULL,
    gateway_id          integer NOT NULL,
    session_key         uuid,
    acct_session_id     text,
    status_type         smallint NOT NULL,
    outcome             smallint NOT NULL,
    session_seconds     bigint,
    input_octets        bigint NOT NULL,
    output_octets       bigint NOT NULL,
    user_name           text,
    framed_ip           inet,
    nas_ip              inet,
    calling_station_id  text,
    terminate_cause     integer,
    quality_flags       integer NOT NULL DEFAULT 0,
    attribute_format    smallint NOT NULL,
    attributes          jsonb,
    raw_attributes      bytea,
    PRIMARY KEY (commit_day, event_id)
) PARTITION BY RANGE (commit_day);

CREATE INDEX accounting_event_session ON accounting_event (session_key, received_at);
CREATE INDEX accounting_event_received ON accounting_event USING brin (received_at);

-- records a sink could not write, never silently skipped
CREATE TABLE quarantine (
    id            bigserial PRIMARY KEY,
    sink          text NOT NULL,
    log_position  bigint NOT NULL,
    reason        text NOT NULL,
    payload       text,
    created_at    timestamptz NOT NULL DEFAULT now()
);
