"""交易级管理员取证视图。

- 管理员身份本身绑定单个交易（会话带 deal_id），下列所有查询都以
  ctx.deal_id 为硬过滤；传入别的交易 id 会被策略层拒绝，因此管理员
  在结构上看不到其他交易的任何信息。
- reconstruct_viewed_set 准确复原某竞标方（组织或指定人员）曾看过的
  资料集合：具体文档、版本、内容指纹、脱敏/原件、每次水印与时间、
  下载是否完成。
"""

from __future__ import annotations

import json

from .errors import Forbidden
from .policy import Context
from .store import Store

VIEW_ACTIONS = ("preview", "export", "original")


class Forensics:
    def __init__(self, store: Store):
        self.store = store

    def _require_admin(self, ctx: Context):
        if not (ctx.is_deal_admin or ctx.is_deal_owner):
            raise Forbidden("deal_admin_only", "仅交易管理员/负责人可取证", 403)

    def reconstruct_viewed_set(self, ctx: Context, *, org_id=None, user_id=None):
        """复原观看集合。org_id 给整家竞标方；可叠加 user_id 缩到个人。"""
        self._require_admin(ctx)
        where = ["e.deal_id=?", "e.action IN ('preview','export','original')"]
        args: list = [ctx.deal_id]
        if org_id:
            where.append("e.org_id=?"); args.append(org_id)
        if user_id:
            where.append("e.actor_user_id=?"); args.append(user_id)
        if not org_id and not user_id:
            raise Forbidden("scope_required", "必须指定组织或人员")

        sql = (
            "SELECT e.seq,e.ts,e.actor_user_id,e.org_id,e.action,e.detail,"
            "d.title AS doc_title,d.category,d.sensitivity,d.patient_level,"
            "v.version_no,v.sha256 AS version_sha256,v.is_redacted,"
            "v.parent_version_id,w.download_id "
            "FROM access_event e "
            "LEFT JOIN document_versions v ON e.target_id=v.version_id "
            "LEFT JOIN documents d ON v.doc_id=d.doc_id "
            "LEFT JOIN watermarks w ON w.watermark_id=json_extract(e.detail,'$.watermark_id') "
            "WHERE " + " AND ".join(where) + " ORDER BY e.seq"
        )
        views = []
        doc_set: dict[str, dict] = {}
        for r in self.store.query(sql, tuple(args)):
            detail = json.loads(r["detail"])
            wm = detail.get("watermark_id")
            # 导出是否完成：以 download_completed 事件为准
            completed = None
            dl_id = r["download_id"]
            if dl_id:
                ds = self.store.query_one(
                    "SELECT status,bytes_delivered,total_size FROM download_sessions "
                    "WHERE download_id=? AND deal_id=?", (dl_id, ctx.deal_id)
                )
                completed = None if ds is None else {
                    "status": ds["status"],
                    "bytes_delivered": ds["bytes_delivered"],
                    "total_size": ds["total_size"],
                }
            item = {
                "seq": r["seq"], "ts": r["ts"], "user_id": r["actor_user_id"],
                "org_id": r["org_id"], "action": r["action"],
                "watermark_id": wm, "download_id": dl_id, "download": completed,
            }
            if r["doc_title"] is not None:
                item.update({
                    "doc_id": detail.get("doc_id"),
                    "title": r["doc_title"], "category": r["category"],
                    "sensitivity": r["sensitivity"],
                    "patient_level": bool(r["patient_level"]),
                    "version_no": r["version_no"],
                    "version_sha256": r["version_sha256"],
                    "is_redacted": bool(r["is_redacted"]),
                    "redaction_parent_version": r["parent_version_id"],
                })
                key = f"{detail.get('doc_id')}@v{r['version_no']}"
                doc_set.setdefault(key, {
                    "doc_id": detail.get("doc_id"), "title": r["doc_title"],
                    "category": r["category"], "sensitivity": r["sensitivity"],
                    "version_no": r["version_no"],
                    "version_sha256": r["version_sha256"],
                    "is_redacted": bool(r["is_redacted"]),
                    "redaction_parent_version": r["parent_version_id"],
                    "first_viewed_at": r["ts"], "watermark_ids": [],
                })
                if wm:
                    doc_set[key]["watermark_ids"].append(wm)
            views.append(item)

        return {
            "deal_id": ctx.deal_id,
            "scope": {"org_id": org_id, "user_id": user_id},
            "distinct_material_versions": len(doc_set),
            "materials": sorted(doc_set.values(), key=lambda m: (m["doc_id"], m["version_no"])),
            "access_count": len(views),
            "timeline": views,
        }

    def audit_verification(self, ctx: Context):
        self._require_admin(ctx)
        return self.store.verify_chain(ctx.deal_id)

    def list_incidents(self, ctx: Context, org_id=None):
        self._require_admin(ctx)
        if org_id:
            return self.store.query(
                "SELECT * FROM security_incidents WHERE deal_id=? AND org_id=? "
                "ORDER BY detected_at", (ctx.deal_id, org_id)
            )
        return self.store.query(
            "SELECT * FROM security_incidents WHERE deal_id=? ORDER BY detected_at",
            (ctx.deal_id,),
        )
