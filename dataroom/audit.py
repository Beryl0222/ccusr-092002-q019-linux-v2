"""仅追加审计日志与异常批量访问检测。

每次预览/导出/拒绝/管理动作都落一行 JSONL。检测器对单一用户在滑动
时间窗内的成功预览/导出计数，超阈值即由系统自动停权并立案。
"""

from . import models

ACCESS_ACTIONS = {"DOC_PREVIEW", "DOC_EXPORT"}


class AuditLog:
    def __init__(self, store):
        self.store = store
        self._events = list(self.store.iter_audit())

    def log(self, action, *, deal_id=None, org_id=None, user_id=None, result="OK",
            reason=None, doc_id=None, version_no=None, tier=None, watermark=None,
            incident_id=None, **details):
        event = {
            "action": action,
            "deal_id": deal_id,
            "org_id": org_id,
            "user_id": user_id,
            "doc_id": doc_id,
            "version_no": version_no,
            "tier": tier,
            "result": result,
            "reason": reason,
            "watermark": watermark,
            "incident_id": incident_id,
            "details": details or {},
        }
        with self.store.lock:
            event = self.store.append_audit(event)
            self._events.append(event)
        return event

    def snapshot(self):
        """返回当前全部审计事件（列表副本）。"""
        return list(self._events)

    def user_access_events(self, user_id):
        return [e for e in self._events
                if e.get("user_id") == user_id and e.get("action") in ACCESS_ACTIONS
                and e.get("result") == "OK"]

    def detect_bulk_access(self, user_id, window_seconds, threshold):
        """滑动窗口计数；超阈返回窗口内事件，否则 None。"""
        from datetime import timedelta
        from .security import utcnow, utcnow_iso

        events = self.user_access_events(user_id)
        if len(events) < threshold:
            return None
        cutoff = utcnow() - timedelta(seconds=window_seconds)
        recent = [e for e in events if e["ts"] >= cutoff.isoformat(timespec="seconds") + "Z"]
        if len(recent) >= threshold:
            return recent
        return None

    # ----------------------------------------------------------- 浏览复原
    def viewed_collection(self, *, deal_id=None, org_id=None, user_id=None):
        """按交易/组织/用户复原“曾看过的资料集合”（去重，保留末次访问与动作）。"""
        seen = {}
        for event in self._events:
            if event.get("action") not in ACCESS_ACTIONS or event.get("result") != "OK":
                continue
            if deal_id is not None and event.get("deal_id") != deal_id:
                continue
            if org_id is not None and event.get("org_id") != org_id:
                continue
            if user_id is not None and event.get("user_id") != user_id:
                continue
            key = (event.get("doc_id"), event.get("version_no"), event.get("tier"))
            entry = seen.get(key)
            if entry is None:
                seen[key] = {
                    "doc_id": key[0],
                    "version_no": key[1],
                    "tier": key[2],
                    "first_access_ts": event["ts"],
                    "last_access_ts": event["ts"],
                    "access_count": 0,
                    "actions": set(),
                }
                entry = seen[key]
            entry["access_count"] += 1
            entry["actions"].add(event["action"])
            if event["ts"] > entry["last_access_ts"]:
                entry["last_access_ts"] = event["ts"]
        result = []
        for key in sorted(seen, key=lambda k: (k[0] or "", k[1] or 0)):
            entry = seen[key]
            entry["actions"] = sorted(entry["actions"])
            result.append(entry)
        return result
