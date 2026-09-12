CREATE TABLE cache_entries (
    provider TEXT NOT NULL,
    cache_key TEXT NOT NULL,
    payload_version INTEGER NOT NULL CHECK (payload_version >= 0),
    kind TEXT NOT NULL CHECK (kind IN ('ip', 'url', 'hash')),
    outcome TEXT NOT NULL CHECK (outcome IN ('ok', 'not_found')),
    fetched_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    payload BLOB NOT NULL,
    payload_bytes INTEGER NOT NULL CHECK (payload_bytes >= 0),
    PRIMARY KEY (provider, cache_key)
);
CREATE INDEX cache_expiry ON cache_entries (expires_at);
CREATE INDEX cache_fifo ON cache_entries (fetched_at, cache_key, provider);

CREATE TABLE quota_state (
    quota_group TEXT PRIMARY KEY NOT NULL,
    utc_day TEXT NOT NULL,
    daily_consumed INTEGER NOT NULL DEFAULT 0 CHECK (daily_consumed >= 0),
    cooldown_until INTEGER,
    cooldown_unknown INTEGER NOT NULL DEFAULT 0 CHECK (cooldown_unknown IN (0, 1)),
    provider_remaining INTEGER CHECK (provider_remaining >= 0),
    provider_reset_at INTEGER
);
CREATE TABLE quota_attempts (
    id INTEGER PRIMARY KEY,
    quota_group TEXT NOT NULL REFERENCES quota_state(quota_group),
    reserved_at INTEGER NOT NULL
);
CREATE INDEX quota_attempt_window ON quota_attempts (quota_group, reserved_at);
CREATE TABLE storage_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    clock_high_water INTEGER NOT NULL
);
