-- ============ جداول ميزة "العمال" ============
-- شغّل هذا الملف على قاعدة D1 تبعتك:
-- wrangler d1 execute <DB_NAME> --file=./schema_workers.sql

-- كل صف = عامل واحد مرتبط بحساب المالك (وصول كامل لكل سجلاته، مو سجل وحد)
CREATE TABLE IF NOT EXISTS workers (
  id TEXT PRIMARY KEY,
  owner_user_id TEXT NOT NULL,
  name TEXT,
  code TEXT,
  code_expires_at TEXT,
  status TEXT NOT NULL DEFAULT 'pending', -- pending = كود لسه ما استخدم | active = عامل منضم فعلاً
  joined_at TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (owner_user_id) REFERENCES users(id)
);

-- جلسة العامل: منفصلة عن جلسة المالك (sessions) عشان تنحذف لحالها عند حذف العامل
-- بس تعطي نفس صلاحيات صاحب الحساب (owner_user_id)
CREATE TABLE IF NOT EXISTS worker_sessions (
  token TEXT PRIMARY KEY,
  worker_id TEXT NOT NULL,
  owner_user_id TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  FOREIGN KEY (worker_id) REFERENCES workers(id)
);

CREATE INDEX IF NOT EXISTS idx_workers_owner ON workers(owner_user_id);
CREATE INDEX IF NOT EXISTS idx_workers_code ON workers(code);
CREATE INDEX IF NOT EXISTS idx_worker_sessions_worker ON worker_sessions(worker_id);
