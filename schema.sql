CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  full_name TEXT,
  email TEXT UNIQUE,
  password_hash TEXT NOT NULL,
  verified INTEGER NOT NULL DEFAULT 0,
  verification_code TEXT,
  code_expires_at TEXT,
  code_attempts INTEGER NOT NULL DEFAULT 0,
  last_code_sent_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS notebooks (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  title TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS rows (
  id TEXT PRIMARY KEY,
  notebook_id TEXT NOT NULL,
  position INTEGER NOT NULL,
  name TEXT,
  amount REAL DEFAULT 0,
  quantity REAL DEFAULT 0,
  notes TEXT,
  FOREIGN KEY (notebook_id) REFERENCES notebooks(id)
);
