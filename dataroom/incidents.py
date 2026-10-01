"""异常事件的检测、持久化卷宗与处置。

覆盖五类必须留痕并处置的情形：
- VERSION_CONFLICT      并发上传/乐观锁冲突
- SCAN_FAILED           病毒扫描失败（版本入隔离）
- DOWNLOAD_INTERRUPTED  导出/下载中断
- ANOMALY_BULK_ACCESS   异常批量访问（阈值内大量预览/导出 → 自动停权）
- LEAK                  泄露事件（水印溯源 → 一键撤权冻结）

每个事件有独立 JSON 卷宗，处置动作仅追加；即使 state.json 损坏，
卷宗与审计日志仍可复原“谁在何时看过什么”。
"""

from . import models
from .errors import ConflictError, NotFoundError
from .security import short_id, utcnow_iso

INCIDENT_KINDS = {
    "VERSION_CONFLICT",
    "SCAN_FAILED",
    "DOWNLOAD_INTERRUPTED",
    "ANOMALY_BULK_ACCESS",
    "LEAK",
}


class IncidentManager:
    def __init__(self, store, audit):
        self.store = store
        self.audit = audit

    def open(self, kind, deal_id, summary, details=None, related_user=None,
             related_org=None, related_doc=None, auto_action=None):
        """立案：写 state、写独立卷宗、写审计，返回事件记录。"""
        if kind not in INCIDENT_KINDS:
            raise ValueError(f"未知事件类型: {kind}")
        incident_id = short_id("INC")
        record = {
            "incident_id": incident_id,
            "kind": kind,
            "deal_id": deal_id,
            "status": models.INC_OPEN,
            "summary": summary,
            "details": details or {},
            "related_user": related_user,
            "related_org": related_org,
            "related_doc": related_doc,
            "opened_ts": utcnow_iso(),
            "closed_ts": None,
            "actions": [],
        }
        if auto_action:
            record["actions"].append({
                "action": auto_action,
                "ts": utcnow_iso(),
                "by": "SYSTEM",
                "automatic": True,
            })
        with self.store.lock:
            self.store.state["incidents"][incident_id] = record
            self.store.commit()
            self._persist_dossier(record)
            self.audit.log("INCIDENT_OPENED", deal_id=deal_id, incident_id=incident_id,
                           kind=kind, related_user=related_user, related_org=related_org,
                           related_doc=related_doc, summary=summary)
        return record

    def act(self, incident_id, action, by, note=None):
        """追加处置动作（如 SUSPEND_USER / REVOKE_ORG / PURGE / RESOLVE），持久化。"""
        with self.store.lock:
            record = self.store.state["incidents"].get(incident_id)
            if record is None:
                raise NotFoundError(f"事件不存在: {incident_id}")
            entry = {"action": action, "ts": utcnow_iso(), "by": by,
                     "automatic": False, "note": note}
            record["actions"].append(entry)
            self.store.commit()
            self._persist_dossier(record)
            self.audit.log("INCIDENT_ACTION", deal_id=record["deal_id"],
                           incident_id=incident_id, action=action, by=by, note=note)
            return dict(record)

    def resolve(self, incident_id, by, note=None):
        with self.store.lock:
            record = self.store.state["incidents"].get(incident_id)
            if record is None:
                raise NotFoundError(f"事件不存在: {incident_id}")
            if record["status"] == models.INC_RESOLVED:
                raise ConflictError("事件已结案")
            record["status"] = models.INC_RESOLVED
            record["closed_ts"] = utcnow_iso()
            record["actions"].append({
                "action": "RESOLVE", "ts": record["closed_ts"], "by": by,
                "automatic": False, "note": note,
            })
            self.store.commit()
            self._persist_dossier(record)
            self.audit.log("INCIDENT_RESOLVED", deal_id=record["deal_id"],
                           incident_id=incident_id, by=by)
            return dict(record)

    def list_for_deal(self, deal_id):
        return [dict(r) for r in self.store.state["incidents"].values() if r["deal_id"] == deal_id]

    def get(self, incident_id):
        record = self.store.state["incidents"].get(incident_id)
        if record is None:
            raise NotFoundError(f"事件不存在: {incident_id}")
        # 卷宗可能被外部更新过，以盘上为准合并。
        return self.store.load_incident_dossier(incident_id)

    def _persist_dossier(self, record):
        """写出独立事件卷宗：事件本身 + 相关审计轨迹 + 处置动作。"""
        related_events = [
            e for e in self.audit.snapshot()
            if e.get("incident_id") == record["incident_id"]
            or (record.get("related_user") and e.get("user_id") == record["related_user"]
                and e.get("deal_id") == record["deal_id"]
                and e.get("action") in ("DOC_PREVIEW", "DOC_EXPORT", "EXPORT_INTERRUPTED"))
        ]
        dossier = dict(record)
        dossier["audit_trail"] = related_events
        self.store.write_incident_dossier(dossier)

    # ----------------------------------------------------- 泄露水印溯源
    def trace_watermark(self, code):
        """凭水印码反查访问事件与主体，供泄露排查。"""
        match = None
        for event in self.audit.snapshot():
            if (event.get("watermark") or {}).get("code") == code:
                match = event
                break
        if match is None:
            raise NotFoundError(f"水印码无法匹配任何访问记录: {code}")
        return match
