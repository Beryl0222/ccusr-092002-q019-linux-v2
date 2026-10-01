"""水印化预览/导出与可续传下载。

- 每次预览或导出都配发全局唯一 watermark_id，并嵌入产物本身
  （产物哈希随之变化且入库），水印与访问事实同入哈希链；
- 导出建立可续传下载会话，中断（interrupted）可凭 download_id 继续，
  服务端以 206 返回后续字节；
- 每个分块在投放前都重新过实时策略：撤权/离职/交易终止/冻结会让
  正在进行的下载立刻失败，会话持久化为 revoked。
"""

from __future__ import annotations

import uuid

from . import taxonomy as T
from .errors import Conflict, DomainError, Forbidden, NotFound
from .policy import Context, Policy
from .store import Store, sha256_hex


def watermark_id() -> str:
    return f"WM-{uuid.uuid4().hex[:20]}"


def render_watermarked(content: bytes, fields: dict) -> bytes:
    """把唯一水印嵌入产物。

    真实部署会在 PDF/Office 渲染层做隐写+明水印；此处用确定性的
    首尾水印封皮，保证产物里可机器提取水印标识且产物指纹唯一。
    """
    lines = [
        "X-DATAROOM-WATERMARK",
        f"id={fields['watermark_id']}",
        f"deal={fields['deal_id']}",
        f"org={fields.get('org_id') or 'INTERNAL'}",
        f"user={fields['user_id']}({fields['user_name']})",
        f"doc={fields['doc_id']} v{fields['version_no']}",
        f"copy={'REDACTED' if fields['is_redacted'] else 'FULL'}",
        f"issued={fields['issued_at']}",
        "END-X-DATAROOM-WATERMARK",
    ]
    header = ("\n".join(lines) + "\n").encode("utf-8")
    footer = (f"\n[watermark {fields['watermark_id']} "
              f"unauthorized disclosure is traceable to {fields['user_id']}]\n"
              ).encode("utf-8")
    return header + content + footer


def extract_watermark(artifact: bytes) -> str | None:
    for line in artifact[:2048].splitlines():
        if line.startswith(b"id="):
            return line[3:].decode("utf-8", "replace")
    return None


class Access:
    def __init__(self, store: Store, policy: Policy):
        self.store = store
        self.policy = policy

    def _load(self, version_id: str):
        v = self.store.query_one(
            "SELECT * FROM document_versions WHERE version_id=?", (version_id,)
        )
        if v is None:
            raise NotFound("版本不存在")
        doc = self.store.query_one(
            "SELECT * FROM documents WHERE doc_id=? AND deal_id=?",
            (v["doc_id"], v["deal_id"]),
        )
        if doc is None:
            raise NotFound("文档不存在")
        return doc, v

    def _issue(self, ctx: Context, doc, v, action, *, download_id=None):
        wm = watermark_id()
        now = self.store.now()
        fields = {
            "watermark_id": wm, "deal_id": ctx.deal_id, "org_id": ctx.org_id,
            "user_id": ctx.user_id, "user_name": ctx.user_name,
            "doc_id": doc["doc_id"], "version_no": v["version_no"],
            "is_redacted": bool(v["is_redacted"]), "issued_at": now,
        }
        artifact = render_watermarked(self.store.get_blob(v["sha256"]), fields)
        adigest, asize = self.store.put_blob(artifact)
        with self.store.tx():
            self.store.execute(
                "INSERT INTO watermarks(watermark_id,deal_id,org_id,user_id,doc_id,"
                "version_id,action,download_id,issued_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (wm, ctx.deal_id, ctx.org_id, ctx.user_id, doc["doc_id"],
                 v["version_id"], action, download_id, now),
            )
            self.store.append_event(
                ctx.deal_id, action, actor_user_id=ctx.user_id, org_id=ctx.org_id,
                target_type="version", target_id=v["version_id"],
                detail={"watermark_id": wm, "doc_id": doc["doc_id"],
                        "version_no": v["version_no"],
                        "artifact_sha256": adigest,
                        "is_redacted": bool(v["is_redacted"]),
                        "download_id": download_id}, commit=False,
            )
            self.store.commit()
        return wm, adigest, asize

    # ---- 预览：一次性水印化查看 ----
    def preview(self, ctx: Context, version_id: str):
        doc, v = self._load(version_id)
        self.policy.can_view_version(ctx, doc, v, action="preview")
        wm, adigest, _ = self._issue(ctx, doc, v, "preview")
        artifact = self.store.get_blob(adigest)
        return {"watermark_id": wm, "content": artifact,
                "doc_id": doc["doc_id"], "version_no": v["version_no"],
                "is_redacted": bool(v["is_redacted"])}

    # ---- 原件调取（仅负责人/管理员，仍打水印上链）----
    def view_original(self, ctx: Context, redacted_doc_id: str):
        doc = self.store.query_one(
            "SELECT * FROM documents WHERE doc_id=? AND deal_id=?",
            (redacted_doc_id, ctx.deal_id),
        )
        if doc is None or not doc["redaction_parent_doc_id"]:
            raise NotFound("未找到该脱敏件对应的谱系")
        parent = self.store.query_one(
            "SELECT * FROM documents WHERE doc_id=? AND deal_id=?",
            (doc["redaction_parent_doc_id"], ctx.deal_id),
        )
        v = self.store.query_one(
            "SELECT * FROM document_versions WHERE doc_id=? AND scan_status='clean' "
            "AND is_redacted=0 ORDER BY version_no DESC LIMIT 1", (parent["doc_id"],),
        )
        if v is None:
            raise NotFound("原件无可用版本")
        self.policy.can_view_version(ctx, parent, v, action="original_admin")
        wm, adigest, _ = self._issue(ctx, parent, v, "original")
        return {"watermark_id": wm, "content": self.store.get_blob(adigest),
                "doc_id": parent["doc_id"], "version_no": v["version_no"]}

    # ---- 导出：建立可续传会话 ----
    def start_export(self, ctx: Context, version_id: str):
        doc, v = self._load(version_id)
        self.policy.can_view_version(ctx, doc, v, action="export")
        download_id = f"DL-{uuid.uuid4().hex[:16]}"
        wm, adigest, asize = self._issue(ctx, doc, v, "export", download_id=download_id)
        now = self.store.now()
        with self.store.tx():
            self.store.execute(
                "INSERT INTO download_sessions(download_id,deal_id,user_id,org_id,"
                "version_id,watermark_id,artifact_sha256,total_size,bytes_delivered,"
                "status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (download_id, ctx.deal_id, ctx.user_id, ctx.org_id, v["version_id"],
                 wm, adigest, asize, 0, T.DL_OPEN, now, now),
            )
            self.store.commit()
        return {"download_id": download_id, "watermark_id": wm,
                "total_size": asize, "bytes_delivered": 0}

    def get_session(self, ctx: Context, download_id: str):
        d = self.store.query_one(
            "SELECT * FROM download_sessions WHERE download_id=?", (download_id,)
        )
        if d is None:
            raise NotFound("下载会话不存在")
        self.policy.assert_deal_scope(ctx, d["deal_id"])
        if d["user_id"] != ctx.user_id and not (ctx.is_deal_admin or ctx.is_deal_owner):
            raise Forbidden("download_not_owner", "不是该下载的归属人", 403)
        return d

    def _set_status(self, d, status, delivered=None):
        self.store.execute(
            "UPDATE download_sessions SET status=?, bytes_delivered=?, updated_at=? "
            "WHERE download_id=?",
            (status, d["bytes_delivered"] if delivered is None else delivered,
             self.store.now(), d["download_id"]),
        )

    def read_chunk(self, ctx: Context, download_id: str, max_chunk: int = 1 << 20,
                   start: int | None = None, end: int | None = None):
        """投放下一段。每次都重新做实时策略判定。

        start/end 用于 HTTP Range 续传：会先把服务端游标校正到 start
        （中断后客户端可凭最后字节定位）。撤权/离职/终止/冻结等会把
        会话持久化为 revoked 并抛 Forbidden。
        返回 dict(status, content, start, end, total, watermark_id)。
        """
        d = self.get_session(ctx, download_id)
        if d["status"] == T.DL_COMPLETED and start is None:
            return {"status": T.DL_COMPLETED, "content": b"", "start": d["total_size"],
                    "end": d["total_size"], "total": d["total_size"],
                    "watermark_id": d["watermark_id"]}
        try:
            # 关键：每个分块前以该用户「此刻」的身份重算授权，不依赖
            # 请求开始时的 ctx 快照——撤权/离职/终止/冻结/停权/到期都会
            # 让正在进行的下载在下一分块立即失败。
            v = self.store.query_one(
                "SELECT * FROM document_versions WHERE version_id=?", (d["version_id"],)
            )
            doc = self.store.query_one(
                "SELECT * FROM documents WHERE doc_id=? AND deal_id=?",
                (v["doc_id"], v["deal_id"]),
            )
            live_ctx = self.policy.context_for_user(ctx.deal_id, ctx.user_id)
            self.policy.can_view_version(live_ctx, doc, v, action="export")
        except Forbidden as e:
            with self.store.tx():
                self._set_status(d, T.DL_REVOKED)
                self.store.append_event(
                    ctx.deal_id, "download_revoked_midstream",
                    actor_user_id=ctx.user_id, org_id=ctx.org_id,
                    target_type="download", target_id=download_id,
                    detail={"reason": e.code, "watermark_id": d["watermark_id"]},
                    commit=False,
                )
                self.store.commit()
            raise

        cur = d["bytes_delivered"]
        if start is not None:
            if start < 0 or start > d["total_size"]:
                raise Conflict("bad_range", "Range 起点越界", 416)
            cur = start
        if cur >= d["total_size"]:
            with self.store.tx():
                self._set_status(d, T.DL_COMPLETED, delivered=cur)
                self.store.commit()
            return {"status": T.DL_COMPLETED, "content": b"", "start": cur,
                    "end": cur, "total": d["total_size"],
                    "watermark_id": d["watermark_id"]}

        artifact = self.store.get_blob(d["artifact_sha256"])
        stop = min(cur + max_chunk, d["total_size"])
        if end is not None:
            stop = min(stop, end + 1, d["total_size"])
        chunk = artifact[cur:stop]
        completed = stop >= d["total_size"]
        new_status = T.DL_COMPLETED if completed else T.DL_OPEN
        with self.store.tx():
            self._set_status(d, new_status, delivered=stop)
            if completed:
                self.store.append_event(
                    ctx.deal_id, "download_completed", actor_user_id=ctx.user_id,
                    org_id=ctx.org_id, target_type="download", target_id=download_id,
                    detail={"watermark_id": d["watermark_id"],
                            "bytes": d["total_size"]}, commit=False,
                )
            self.store.commit()
        return {"status": new_status, "content": chunk, "start": cur,
                "end": stop, "total": d["total_size"],
                "watermark_id": d["watermark_id"]}

    def mark_interrupted(self, ctx: Context, download_id: str):
        """客户端中断且未完成：持久化 interrupted，可后续续传。"""
        d = self.get_session(ctx, download_id)
        if d["status"] == T.DL_OPEN and d["bytes_delivered"] < d["total_size"]:
            with self.store.tx():
                self._set_status(d, T.DL_INTERRUPTED)
                self.store.append_event(
                    ctx.deal_id, "download_interrupted", actor_user_id=ctx.user_id,
                    org_id=ctx.org_id, target_type="download", target_id=download_id,
                    detail={"bytes_delivered": d["bytes_delivered"],
                            "total": d["total_size"],
                            "watermark_id": d["watermark_id"]}, commit=False,
                )
                self.store.commit()
        return self.get_session(ctx, download_id)

    def resume(self, ctx: Context, download_id: str, max_chunk: int = 1 << 20,
               start: int | None = None, end: int | None = None):
        """从中断点继续：open/interrupted 都可以。"""
        d = self.get_session(ctx, download_id)
        if d["status"] not in (T.DL_OPEN, T.DL_INTERRUPTED):
            raise Conflict("download_not_resumable",
                           f"下载会话状态为 {d['status']}，无法续传")
        return self.read_chunk(ctx, download_id, max_chunk, start=start, end=end)
