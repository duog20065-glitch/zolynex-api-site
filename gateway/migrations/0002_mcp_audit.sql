-- AI clients allowed to use the /mcp endpoint, and an audit log of every change.
-- MCP tokens are stored only as SHA-256 hashes; the token is shown once when issued.

CREATE TABLE mcp_clients (
  name         TEXT PRIMARY KEY,           -- e.g. claudecode, codex, muse
  token_hash   TEXT NOT NULL UNIQUE,
  token_hint   TEXT NOT NULL,
  can_write    INTEGER NOT NULL DEFAULT 1,
  enabled      INTEGER NOT NULL DEFAULT 1,
  created_at   TEXT NOT NULL,
  last_used_at TEXT
);

CREATE TABLE audit_log (
  id     INTEGER PRIMARY KEY AUTOINCREMENT,
  at     TEXT NOT NULL,
  actor  TEXT NOT NULL,                    -- haruself | mcp:<client>
  action TEXT NOT NULL,
  target TEXT,
  detail TEXT                              -- never contains keys
);

CREATE INDEX idx_audit_at ON audit_log(at);
