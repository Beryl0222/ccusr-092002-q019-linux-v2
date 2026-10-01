"""SQLite 持久化与每交易哈希链审计日志。

所有业务表都带 deal_id：会话是交易作用域的，策略层永远以会话上的
deal_id 过滤，因此跨交易读取在结构上不成立。

access_event 是按交易独立的哈希链（seq 从 1 开始）：
    prev_0 = sha256("GENESIS:" + deal_id)
    hash_n = sha256(prev_{n-1} || seq || ts || canonical(payload))
链上记录谁在何时对哪份文档的哪个版本（含脱敏版本号）做了什么、
配发了哪个水印，任何事后改写都会让 verify 失败。
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS deals (
  deal_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',          -- active / terminated
  phase TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS organizations (
  org_id TEXT PRIMARY KEY,
  deal_id TEXT NOT NULL REFERENCES deals(deal_id),
  name TEXT NOT NULL,
  nda_signed_at TEXT,                              -- NULL = 未签署
  frozen INTEGER NOT NULL DEFAULT 0,               -- 安全冻结（泄露等）
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS teams (
  team_id TEXT PRIMARY KEY,
  deal_id TEXT NOT NULL REFERENCES deals(deal_id),
  org_id TEXT NOT NULL REFERENCES organizations(org_id),
  name TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
  user_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,               -- 0 = 离职
  deactivated_at TEXT,
  created_at TEXT NOT NULL
);
-- 授权：交易/组织/团队/角色 + 期限；internal 角色 org_id/team_id 可空
CREATE TABLE IF NOT EXISTS access_grants (
  grant_id TEXT PRIMARY KEY,
  deal_id TEXT NOT NULL REFERENCES deals(deal_id),
  org_id TEXT REFERENCES organizations(org_id),
  team_id TEXT REFERENCES teams(team_id),
  user_id TEXT NOT NULL REFERENCES users(user_id),
  role TEXT NOT NULL,
  valid_from TEXT NOT NULL,
  valid_until TEXT NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0,
  revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_grants_deal_user ON access_grants(deal_id, user_id);

-- 交易内用户级停权（异常批量访问自动处置；与离职不同，仅限本交易）
CREATE TABLE IF NOT EXISTS deal_user_state (
  deal_id TEXT NOT NULL REFERENCES deals(deal_id),
  user_id TEXT NOT NULL REFERENCES users(user_id),
  suspended INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (deal_id, user_id)
);

CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  deal_id TEXT NOT NULL REFERENCES deals(deal_id),
  user_id TEXT NOT NULL REFERENCES users(user_id),
  created_at TEXT NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(deal_id, user_id);

CREATE TABLE IF NOT EXISTS documents (
  doc_id TEXT PRIMARY KEY,
  deal_id TEXT NOT NULL REFERENCES deals(deal_id),
  title TEXT NOT NULL,
  category TEXT NOT NULL,
  classification TEXT NOT NULL,                    -- 业务分类标签，如 工艺机密
  sensitivity TEXT NOT NULL,
  patient_level INTEGER NOT NULL DEFAULT 0,
  min_phase TEXT NOT NULL,                         -- 材料分阶段开放
  status TEXT NOT NULL DEFAULT 'available',        -- available / quarantined / withdrawn
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  redaction_parent_doc_id TEXT REFERENCES documents(doc_id)
);
CREATE INDEX IF NOT EXISTS idx_docs_deal ON documents(deal_id);

CREATE TABLE IF NOT EXISTS document_versions (
  version_id TEXT PRIMARY KEY,
  doc_id TEXT NOT NULL REFERENCES documents(doc_id),
  deal_id TEXT NOT NULL REFERENCES deals(deal_id),
  version_no INTEGER NOT NULL,
  sha256 TEXT NOT NULL,                            -- 内容指纹
  size INTEGER NOT NULL,
  is_redacted INTEGER NOT NULL DEFAULT 0,
  parent_version_id TEXT REFERENCES document_versions(version_id),  -- 脱敏谱系
  scan_status TEXT NOT NULL,                       -- clean / infected
  scan_detail TEXT,
  uploaded_by TEXT NOT NULL,
  uploaded_at TEXT NOT NULL,
  UNIQUE (doc_id, version_no)
);
CREATE INDEX IF NOT EXISTS idx_versions_doc ON document_versions(doc_id);

CREATE TABLE IF NOT EXISTS watermarks (
  watermark_id TEXT PRIMARY KEY,
  deal_id TEXT NOT NULL REFERENCES deals(deal_id),
  org_id TEXT,
  user_id TEXT NOT NULL,
  doc_id TEXT NOT NULL,
  version_id TEXT NOT NULL,
  action TEXT NOT NULL,                            -- preview / export / original
  download_id TEXT,
  issued_at TEXT NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS download_sessions (
  download_id TEXT PRIMARY KEY,
  deal_id TEXT NOT NULL REFERENCES deals(deal_id),
  user_id TEXT NOT NULL,
  org_id TEXT,
  version_id TEXT NOT NULL,
  watermark_id TEXT NOT NULL,
  artifact_sha256 TEXT NOT NULL,
  total_size INTEGER NOT NULL,
  bytes_delivered INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'open',             -- open / completed / interrupted / revoked
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS questions (
  qa_id TEXT PRIMARY KEY,
  deal_id TEXT NOT NULL REFERENCES deals(deal_id),
  org_id TEXT NOT NULL REFERENCES organizations(org_id),
  asked_by TEXT NOT NULL,
  question_text TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'draft',            -- draft/answered/approved/published/rejected
  created_at TEXT NOT NULL,
  answer_text TEXT,
  answer_citations TEXT,                           -- JSON [[doc_id, version_id], ...]
  answered_by TEXT,
  answered_at TEXT,
  legal_approver TEXT,
  legal_approved_at TEXT,
  medical_approver TEXT,
  medical_approved_at TEXT,
  published_at TEXT,
  reject_reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_qa_deal ON questions(deal_id);

CREATE TABLE IF NOT EXISTS security_incidents (
  incident_id TEXT PRIMARY KEY,
  deal_id TEXT NOT NULL REFERENCES deals(deal_id),
  org_id TEXT,
  user_id TEXT,
  kind TEXT NOT NULL,                              -- bulk_access_anomaly / suspected_leak
  status TEXT NOT NULL DEFAULT 'open',             -- open / remediated / closed
  detail TEXT NOT NULL,                            -- JSON
  remediation TEXT,                                -- JSON 持久化处置动作
  detected_at TEXT NOT NULL,
  remediated_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_inc_deal ON security_incidents(deal_id);

-- 每交易一条哈希链
CREATE TABLE IF NOT EXISTS access_event (
  deal_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  ts TEXT NOT NULL,
  actor_user_id TEXT,
  org_id TEXT,
  action TEXT NOT NULL,
  target_type TEXT,
  target_id TEXT,
  detail TEXT NOT NULL DEFAULT '{}',
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL,
  PRIMARY KEY (deal_id, seq)
);
"""

GENESIS_PREFIX = "GENESIS:"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


class Store:
    def __init__(self, db_path: str | Path, blob_dir: str | Path):
        self.db_path = str(db_path)
        self.blob_dir = Path(blob_dir)
        self.blob_dir.mkdir(parents=True, exist_ok=True)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    # ---- 基础工具 ----
    def now(self) -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def tx(self):
        return self._lock

    def query(self, sql, args=()):
        with self._lock:
            return self.conn.execute(sql, args).fetchall()

    def query_one(self, sql, args=()):
        with self._lock:
            return self.conn.execute(sql, args).fetchone()

    def execute(self, sql, args=()):
        with self._lock:
            cur = self.conn.execute(sql, args)
            return cur

    def commit(self):
        self.conn.commit()

    # ---- 内容指纹与 blob ----
    def put_blob(self, content: bytes) -> tuple[str, int]:
        digest = sha256_hex(content)
        p = self.blob_dir / digest
        if not p.exists():
            # 同内容同指纹：写临时文件再原子替换
            tmp = self.blob_dir / (digest + ".tmp")
            tmp.write_bytes(content)
            tmp.replace(p)
        return digest, len(content)

    def get_blob(self, digest: str) -> bytes:
        return (self.blob_dir / digest).read_bytes()

    # ---- 哈希链事件 ----
    def _genesis(self, deal_id: str) -> str:
        return sha256_hex((GENESIS_PREFIX + deal_id).encode("utf-8"))

    def append_event(self, deal_id, action, actor_user_id=None, org_id=None,
                     target_type=None, target_id=None, detail=None, commit=True):
        """在调用方事务内追加链上事件；返回 (seq, hash)。"""
        detail = detail or {}
        ts = self.now()
        with self._lock:
            row = self.conn.execute(
                "SELECT COALESCE(MAX(seq),0) AS m FROM access_event WHERE deal_id=?",
                (deal_id,),
            ).fetchone()
            seq = row["m"] + 1
            prev = self.conn.execute(
                "SELECT hash FROM access_event WHERE deal_id=? AND seq=?",
                (deal_id, seq - 1),
            ).fetchone()
            prev_hash = prev["hash"] if prev else self._genesis(deal_id)
            payload = {
                "deal_id": deal_id, "seq": seq, "ts": ts,
                "actor_user_id": actor_user_id, "org_id": org_id,
                "action": action, "target_type": target_type,
                "target_id": target_id, "detail": detail,
            }
            h = sha256_hex((prev_hash + canonical(payload)).encode("utf-8"))
            self.conn.execute(
                "INSERT INTO access_event(deal_id,seq,ts,actor_user_id,org_id,"
                "action,target_type,target_id,detail,prev_hash,hash) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (deal_id, seq, ts, actor_user_id, org_id, action, target_type,
                 target_id, canonical(detail), prev_hash, h),
            )
            if commit:
                self.conn.commit()
        return seq, h

    def verify_chain(self, deal_id: str) -> dict:
        """重算某交易的整条链，返回首处断裂位置（若有）。"""
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM access_event WHERE deal_id=? ORDER BY seq", (deal_id,)
            ).fetchall()
        prev_hash = self._genesis(deal_id)
        for r in rows:
            payload = {
                "deal_id": r["deal_id"], "seq": r["seq"], "ts": r["ts"],
                "actor_user_id": r["actor_user_id"], "org_id": r["org_id"],
                "action": r["action"], "target_type": r["target_type"],
                "target_id": r["target_id"], "detail": json.loads(r["detail"]),
            }
            expect = sha256_hex((prev_hash + canonical(payload)).encode("utf-8"))
            if r["prev_hash"] != prev_hash or r["hash"] != expect:
                return {"ok": False, "broken_at_seq": r["seq"], "events": len(rows)}
            prev_hash = r["hash"]
        return {"ok": True, "broken_at_seq": None, "events": len(rows)}

    def close(self):
        with self._lock:
            self.conn.close()
