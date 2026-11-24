-- Customers and the API keys issued to them.
-- Keys are looked up by SHA-256 hash; the full key and any dedicated upstream
-- key are stored AES-GCM encrypted (DATA_KEY secret), never in plaintext.

CREATE TABLE customers (
  id                TEXT PRIMARY KEY,
  name              TEXT NOT NULL UNIQUE,
  note              TEXT NOT NULL DEFAULT '',
  status            TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  upstream_key_enc  TEXT,            -- NULL = use the shared UPSTREAM_API_KEY
  upstream_key_hint TEXT,
  created_at        TEXT NOT NULL,
  updated_at        TEXT NOT NULL
);

CREATE TABLE api_keys (
  id          TEXT PRIMARY KEY,
  customer_id TEXT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
  key_hash    TEXT NOT NULL UNIQUE,
  key_enc     TEXT NOT NULL,
  key_hint    TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  revoked_at  TEXT
);

CREATE INDEX idx_api_keys_customer ON api_keys(customer_id);
