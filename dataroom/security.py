"""异常访问检测与泄露事件的持久化处置。

- 异常批量访问：在滑动窗口内统计同一用户接触的不同文档数，超阈值即
  自动处置——交易内停权 + 吊销会话 + 立安全事件，全程上链；
- 泄露事件：凭外泄物里的水印标识溯源到人/组织/文档版本，执行冻结/
  停权/吊销会话等补救动作并持久化；事件走 open→remediated→closed。
"""

from __future__ import annotations

import json
import uuid

from . import taxonomy as T
from .errors import DomainError, NotFound
from .store import Store

# 60 秒窗口内接触 >= 8 份不同文档视为异常批量访问
BULK_WINDOW_SECONDS = 60
BULK_DISTINCT_DOCS = 8


def _iid():
    return f"INC-{uuid.uuid4().hex[:12]}"


class Security:
    def __init__(self, store: Store, window=BULK_WINDOW_SECONDS,
                 threshold=BULK_DISTINCT_DOCS):
        self.store = store
        self.window = window
        self.threshold = threshold

    # ---- 异常批量访问 ----
    def note_access(self, deal_id, user_id, org_id, doc_id):
        """每次成功查看后调用；超阈值自动处置。返回事件 id 或 None。

        事件 target_id 是版本号，按 detail.doc_id 在滑动窗口内去重计数。
        """
        rows = self.store.query(
            "SELECT detail FROM access_event "
            "WHERE deal_id=? AND actor_user_id=? AND action IN ('preview','export') "
            "AND target_type='version' AND ts >= datetime(?, ?)",
            (deal_id, user_id, self.store.now(), f"-{self.window} seconds"),
        )
        docs = {json.loads(r["detail"]).get("doc_id") for r in rows}
        docs.add(doc_id)
        docs.discard(None)
        if len(docs) < self.threshold:
            return None
        return self.raise_bulk_incident(deal_id, user_id, org_id, sorted(docs))

    def raise_bulk_incident(self, deal_id, user_id, org_id, docs):
        # 已停权则不重复立案
        st = self.store.query_one(
            "SELECT suspended FROM deal_user_state WHERE deal_id=? AND user_id=?",
            (deal_id, user_id),
        )
        if st is not None and st["suspended"]:
            return None
        incident_id = _iid()
        now = self.store.now()
        detail = {"window_seconds": self.window, "distinct_docs": docs,
                  "distinct_count": len(docs), "auto": True}
        remediation = {"actions": ["suspend_user_in_deal", "revoke_sessions"],
                       "at": now}
        with self.store.tx():
            self.store.execute(
                "INSERT INTO deal_user_state(deal_id,user_id,suspended) VALUES(?,?,1) "
                "ON CONFLICT(deal_id,user_id) DO UPDATE SET suspended=1",
                (deal_id, user_id),
            )
            self.store.execute(
                "UPDATE sessions SET revoked=1 WHERE deal_id=? AND user_id=?",
                (deal_id, user_id),
            )
            self.store.execute(
                "INSERT INTO security_incidents(incident_id,deal_id,org_id,user_id,"
                "kind,status,detail,remediation,detected_at,remediated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (incident_id, deal_id, org_id, user_id, T.EVT_BULK_ANOMALY,
                 T.INC_REMEDIATED, json.dumps(detail, ensure_ascii=False),
                 json.dumps(remediation, ensure_ascii=False), now, now),
            )
            self.store.append_event(
                deal_id, "security_bulk_anomaly", actor_user_id=user_id,
                org_id=org_id, target_type="incident", target_id=incident_id,
                detail={**detail, "remediation": remediation}, commit=False,
            )
            self.store.commit()
        return incident_id

    # ---- 泄露事件：水印溯源 + 处置 ----
    def trace_watermark(self, watermark_id):
        w = self.store.query_one(
            "SELECT * FROM watermarks WHERE watermark_id=?", (watermark_id,)
        )
        if w is None:
            raise NotFound("水印标识无法溯源")
        doc = self.store.query_one(
            "SELECT title,category,sensitivity FROM documents WHERE doc_id=?",
            (w["doc_id"],),
        )
        v = self.store.query_one(
            "SELECT version_no,is_redacted,sha256 FROM document_versions WHERE version_id=?",
            (w["version_id"],),
        )
        return {
            "watermark_id": w["watermark_id"], "deal_id": w["deal_id"],
            "org_id": w["org_id"], "user_id": w["user_id"],
            "doc_id": w["doc_id"], "version_id": w["version_id"],
            "action": w["action"], "issued_at": w["issued_at"],
            "download_id": w["download_id"],
            "doc": dict(doc) if doc else None,
            "version": dict(v) if v else None,
        }

    def report_leak(self, deal_id, reporter, watermark_id, summary,
                    freeze_org=True, suspend_user=True):
        trace = self.trace_watermark(watermark_id)
        if trace["deal_id"] != deal_id:
            # 跨交易溯源同样被拒绝：管理员只能在本交易上下文操作
            raise DomainError("cross_deal_denied", "水印不属于本交易", 403)
        incident_id = _iid()
        now = self.store.now()
        actions = []
        with self.store.tx():
            if suspend_user and trace["user_id"]:
                self.store.execute(
                    "INSERT INTO deal_user_state(deal_id,user_id,suspended) VALUES(?,?,1) "
                    "ON CONFLICT(deal_id,user_id) DO UPDATE SET suspended=1",
                    (deal_id, trace["user_id"]),
                )
                self.store.execute(
                    "UPDATE sessions SET revoked=1 WHERE deal_id=? AND user_id=?",
                    (deal_id, trace["user_id"]),
                )
                actions.append("suspend_user_in_deal")
                actions.append("revoke_sessions")
            if freeze_org and trace["org_id"]:
                self.store.execute(
                    "UPDATE organizations SET frozen=1 WHERE org_id=? AND deal_id=?",
                    (trace["org_id"], deal_id),
                )
                actions.append("freeze_org")
            remediation = {"actions": actions, "watermark_id": watermark_id,
                           "traced_user": trace["user_id"],
                           "traced_org": trace["org_id"], "at": now}
            self.store.execute(
                "INSERT INTO security_incidents(incident_id,deal_id,org_id,user_id,"
                "kind,status,detail,remediation,detected_at,remediated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (incident_id, deal_id, trace["org_id"], trace["user_id"],
                 T.EVT_LEAK, T.INC_REMEDIATED,
                 json.dumps({"summary": summary, "trace": trace}, ensure_ascii=False),
                 json.dumps(remediation, ensure_ascii=False), now, now),
            )
            self.store.append_event(
                deal_id, "security_leak_reported", actor_user_id=reporter,
                org_id=trace["org_id"], target_type="incident", target_id=incident_id,
                detail={"summary": summary, "remediation": remediation,
                        "watermark_id": watermark_id}, commit=False,
            )
            self.store.commit()
        return incident_id, trace

    def close_incident(self, deal_id, incident_id, note):
        inc = self.store.query_one(
            "SELECT * FROM security_incidents WHERE incident_id=? AND deal_id=?",
            (incident_id, deal_id),
        )
        if inc is None:
            raise NotFound("安全事件不存在")
        with self.store.tx():
            self.store.execute(
                "UPDATE security_incidents SET status=? WHERE incident_id=?",
                (T.INC_CLOSED, incident_id),
            )
            self.store.append_event(
                deal_id, "security_incident_closed", target_type="incident",
                target_id=incident_id, detail={"note": note}, commit=False,
            )
            self.store.commit()
        return incident_id

    def list_incidents(self, deal_id):
        return self.store.query(
            "SELECT * FROM security_incidents WHERE deal_id=? ORDER BY detected_at",
            (deal_id,),
        )
