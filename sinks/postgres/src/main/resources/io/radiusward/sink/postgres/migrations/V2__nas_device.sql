-- radiusward PostgreSQL sink, schema version 2: devices behind one NAS entry (ADR 0019)

-- the device's normalised identity (NAS-Identifier, MAC from Called-Station-Id or NAS-IP-Address);
-- NULL when the NAS entry identifies devices by source address only
ALTER TABLE accounting_session ADD COLUMN nas_device text;
ALTER TABLE accounting_event ADD COLUMN nas_device text;
