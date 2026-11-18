-- radiusward PostgreSQL sink, schema version 4: the RADIUS server that received an event is
-- server_id (it was called the gateway)

ALTER TABLE accounting_event RENAME COLUMN gateway_id TO server_id;
