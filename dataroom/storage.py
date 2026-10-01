"""持久化存储。

落盘布局::

    <data_dir>/state.json                 原子写入的主状态（含乐观版本号）
    <data_dir>/audit.jsonl                仅追加审计日志（每次访问一行）
    <data_dir>/incidents/<id>.json        事件卷宗（处置动作仅追加）
    <data_dir>/blobs/clean/<sha256>       扫描通过的内容寻址原件
    <data_dir>/blobs/quarantine/<sha256>  扫描失败/待扫的隔离件

状态文件整份原子替换；审计与卷宗只追加。重开进程后从这些文件复原全部记录。
"""

import json
import os
import threading

from .security import atomic_write, new_token, sha256_fingerprint, utcnow_iso

STATE_SCHEMA = 1


def _initial_state():
    return {
        "schema": STATE_SCHEMA,
        "rev": 0,
        "watermark_secret": new_token(32),
        "deals": {},
        "orgs": {},
        "teams": {},
        "users": {},
        "grants": {},
        "documents": {},
        "upload_sessions": {},
        "export_sessions": {},
        "questions": {},
        "incidents": {},
        "sessions": {},
        "enrollments": {},
        "counters": {},
    }


class Store:
    """文件存储，所有变更经同一把锁串行化并原子落盘。"""

    def __init__(self, data_dir):
        self.data_dir = os.fspath(data_dir)
        self.audit_path = os.path.join(self.data_dir, "audit.jsonl")
        self.incident_dir = os.path.join(self.data_dir, "incidents")
        self.clean_dir = os.path.join(self.data_dir, "blobs", "clean")
        self.quarantine_dir = os.path.join(self.data_dir, "blobs", "quarantine")
        for path in (self.data_dir, self.incident_dir, self.clean_dir, self.quarantine_dir):
            os.makedirs(path, exist_ok=True)
        self.lock = threading.RLock()
        self.state_path = os.path.join(self.data_dir, "state.json")
        self.state = self._load_state()
        self._resync_audit_counter()

    def _resync_audit_counter(self):
        """以盘上日志实际行数校准审计序号，防止重启后 audit_id 重复。"""
        count = 0
        if os.path.exists(self.audit_path):
            with open(self.audit_path, "r", encoding="utf-8") as fh:
                count = sum(1 for line in fh if line.strip())
        self.state["counters"]["audit"] = max(
            self.state["counters"].get("audit", 0), count)

    # ------------------------------------------------------------- state
    def _load_state(self):
        if not os.path.exists(self.state_path):
            state = _initial_state()
            self._write_state(state)
            return state
        with open(self.state_path, "r", encoding="utf-8") as fh:
            state = json.load(fh)
        # 向前兼容：补齐新增的顶层键。
        for key, value in _initial_state().items():
            state.setdefault(key, value if not isinstance(value, (dict, list)) else type(value)())
        state.setdefault("watermark_secret", new_token(32))
        return state

    def _write_state(self, state):
        data = (json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
        atomic_write(self.state_path, data)

    def commit(self):
        """持久化当前状态（调用方须持锁）。"""
        self.state["rev"] += 1
        self._write_state(self.state)
        return self.state["rev"]

    # ----------------------------------------------------------- blob 存储
    def _blob_path(self, zone, fingerprint):
        base = self.clean_dir if zone == "clean" else self.quarantine_dir
        prefix_dir = os.path.join(base, fingerprint[:2])
        return os.path.join(prefix_dir, fingerprint)

    def put_quarantine(self, content: bytes) -> str:
        fingerprint = sha256_fingerprint(content)
        path = self._blob_path("quarantine", fingerprint)
        if not os.path.exists(path):
            atomic_write(path, content)
        return fingerprint

    def promote_to_clean(self, fingerprint: str):
        src = self._blob_path("quarantine", fingerprint)
        dst = self._blob_path("clean", fingerprint)
        if not os.path.exists(dst):
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(src, "rb") as fh:
                content = fh.read()
            atomic_write(dst, content)
        try:
            os.unlink(src)
        except FileNotFoundError:
            pass

    def read_clean(self, fingerprint: str) -> bytes:
        with open(self._blob_path("clean", fingerprint), "rb") as fh:
            return fh.read()

    def read_quarantine(self, fingerprint: str) -> bytes:
        with open(self._blob_path("quarantine", fingerprint), "rb") as fh:
            return fh.read()

    def delete_quarantine(self, fingerprint: str):
        try:
            os.unlink(self._blob_path("quarantine", fingerprint))
        except FileNotFoundError:
            pass

    def blob_exists(self, zone, fingerprint: str) -> bool:
        return os.path.exists(self._blob_path(zone, fingerprint))

    # ------------------------------------------------------------- 审计日志
    def append_audit(self, event: dict) -> dict:
        event = dict(event)
        event.setdefault("ts", utcnow_iso())
        event.setdefault("audit_id", f"AUD-{self.state['counters'].get('audit', 0) + 1:08d}")
        line = (json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
        with open(self.audit_path, "ab") as fh:
            fh.write(line)
            fh.flush()
            os.fsync(fh.fileno())
        self.state["counters"]["audit"] = self.state["counters"].get("audit", 0) + 1
        return event

    def iter_audit(self):
        if not os.path.exists(self.audit_path):
            return
        with open(self.audit_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield json.loads(line)

    # ------------------------------------------------------------- 事件卷宗
    def incident_path(self, incident_id: str):
        return os.path.join(self.incident_dir, f"{incident_id}.json")

    def write_incident_dossier(self, dossier: dict):
        atomic_write(
            self.incident_path(dossier["incident_id"]),
            (json.dumps(dossier, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        )

    def load_incident_dossier(self, incident_id: str) -> dict:
        with open(self.incident_path(incident_id), "r", encoding="utf-8") as fh:
            return json.load(fh)

    def next_seq(self, name: str) -> int:
        counters = self.state["counters"]
        counters[name] = counters.get(name, 0) + 1
        return counters[name]
