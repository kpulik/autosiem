-- Forward-only. Applied explicitly by `autosiem migrate`.
--
-- SEC-005: the SHA-256 chain is tamper-evident, not tamper-proof - a writer
-- with database access can edit a row and recompute every later hash. When
-- AUTOSIEM_AUDIT_SECRET is set, each new row carries an HMAC-SHA256 of its
-- chain hash under a key held outside the database. Nullable, because rows
-- written before this migration (or without the key) are unsealed; the hash
-- chain itself is unchanged, so every existing row still verifies.
alter table audit_log add column mac text;
