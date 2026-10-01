"""文档上传与版本管线。

- 上传即生成 SHA-256 内容指纹；
- 病毒扫描失败的版本持久化进隔离区（不参与任何投放），文档置 quarantined；
- 乐观并发：上传新版本必须携带期望的当前版本号，并发/过期提交得到 409；
- 脱敏件以独立文档形式挂在 redaction_parent_doc_id 下，并在版本上
  保留 parent_version_id 谱系。
"""

from __future__ import annotations

import uuid

from . import taxonomy as T
from .errors import Conflict, DomainError, Forbidden
from .policy import Context
from .store import Store, sha256_hex

# EICAR 测试特征串，便于演练/测试；真实部署替换为杀毒适配器
EICAR_MARKER = b"X5O!P%@AP[4\\PZX"


def default_scanner(content: bytes) -> tuple[str, str]:
    if EICAR_MARKER in content:
        return "infected", "EICAR-Test-Signature"
    return "clean", ""


def _vid():
    return f"VER-{uuid.uuid4().hex[:16]}"


class Documents:
    def __init__(self, store: Store, scanner=default_scanner):
        self.store = store
        self.scanner = scanner

    # ---- 登记元数据 ----
    def register_document(self, deal_id, doc_id, title, category, classification,
                          sensitivity, min_phase, created_by, *,
                          patient_level=False, redaction_parent_doc_id=None):
        if category not in T.CATEGORIES:
            raise DomainError("bad_category", f"未知材料分类: {category}")
        if sensitivity not in T.SENSITIVITY_ORDER:
            raise DomainError("bad_sensitivity", f"未知敏感级别: {sensitivity}")
        if min_phase not in T.PHASES:
            raise DomainError("bad_phase", f"未知阶段: {min_phase}")
        if redaction_parent_doc_id is not None:
            parent = self.store.query_one(
                "SELECT * FROM documents WHERE doc_id=? AND deal_id=?",
                (redaction_parent_doc_id, deal_id),
            )
            if parent is None:
                raise DomainError("bad_lineage", "脱敏谱系指向的原件不存在")
        now = self.store.now()
        with self.store.tx():
            self.store.execute(
                "INSERT INTO documents(doc_id,deal_id,title,category,classification,"
                "sensitivity,patient_level,min_phase,status,created_by,created_at,"
                "redaction_parent_doc_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (doc_id, deal_id, title, category, classification, sensitivity,
                 1 if patient_level else 0, min_phase, T.DOC_AVAILABLE, created_by,
                 now, redaction_parent_doc_id),
            )
            self.store.append_event(
                deal_id, "document_registered", actor_user_id=created_by,
                target_type="document", target_id=doc_id, commit=False,
                detail={"title": title, "category": category,
                        "sensitivity": sensitivity, "patient_level": patient_level,
                        "min_phase": min_phase,
                        "redaction_parent_doc_id": redaction_parent_doc_id},
            )
            self.store.commit()
        return doc_id

    # ---- 上传版本 ----
    def upload_version(self, deal_id, doc_id, expected_version_no, content,
                       uploaded_by, *, is_redacted=False, parent_version_id=None,
                       actor_org_id=None):
        doc = self.store.query_one(
            "SELECT * FROM documents WHERE doc_id=? AND deal_id=?", (doc_id, deal_id)
        )
        if doc is None:
            raise DomainError("not_found", "文档不存在", 404)

        with self.store.tx():
            row = self.store.execute(
                "SELECT COALESCE(MAX(version_no),0) AS m FROM document_versions "
                "WHERE doc_id=?", (doc_id,)
            ).fetchone()
            current_no = row["m"]
            # 乐观并发控制：陈旧/并发提交必须失败且持久化尝试
            if expected_version_no != current_no:
                self.store.append_event(
                    deal_id, "version_conflict", actor_user_id=uploaded_by,
                    org_id=actor_org_id, target_type="document", target_id=doc_id,
                    detail={"expected": expected_version_no, "actual": current_no},
                    commit=False,
                )
                self.store.commit()
                raise Conflict(
                    "concurrent_version",
                    f"并发版本冲突：期望基于 v{expected_version_no}，当前为 v{current_no}",
                )

            version_no = current_no + 1
            version_id = _vid()
            digest = sha256_hex(content)
            scan_status, scan_detail = self.scanner(content)
            now = self.store.now()

            if scan_status == "infected":
                # 持久化处置：哈希留证、样本入隔离目录、版本与文档置隔离
                qdir = self.store.blob_dir / "quarantine"
                qdir.mkdir(exist_ok=True)
                (qdir / digest).write_bytes(content)
                self.store.execute(
                    "INSERT INTO document_versions(version_id,doc_id,deal_id,version_no,"
                    "sha256,size,is_redacted,parent_version_id,scan_status,scan_detail,"
                    "uploaded_by,uploaded_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (version_id, doc_id, deal_id, version_no, digest, len(content),
                     1 if is_redacted else 0, parent_version_id, "infected",
                     scan_detail, uploaded_by, now),
                )
                self.store.execute(
                    "UPDATE documents SET status=? WHERE doc_id=?",
                    (T.DOC_QUARANTINED, doc_id),
                )
                self.store.append_event(
                    deal_id, "virus_scan_failed", actor_user_id=uploaded_by,
                    org_id=actor_org_id, target_type="version", target_id=version_id,
                    detail={"doc_id": doc_id, "version_no": version_no,
                            "sha256": digest, "threat": scan_detail,
                            "disposition": "quarantined"}, commit=False,
                )
                self.store.commit()
                raise DomainError(
                    "virus_scan_failed",
                    f"病毒扫描失败（{scan_detail}），版本已隔离，禁止投放", 422,
                )

            blob_digest, size = self.store.put_blob(content)
            assert blob_digest == digest
            self.store.execute(
                "INSERT INTO document_versions(version_id,doc_id,deal_id,version_no,"
                "sha256,size,is_redacted,parent_version_id,scan_status,scan_detail,"
                "uploaded_by,uploaded_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (version_id, doc_id, deal_id, version_no, digest, size,
                 1 if is_redacted else 0, parent_version_id, "clean", "",
                 uploaded_by, now),
            )
            self.store.append_event(
                deal_id, "version_uploaded", actor_user_id=uploaded_by,
                org_id=actor_org_id, target_type="version", target_id=version_id,
                detail={"doc_id": doc_id, "version_no": version_no,
                        "sha256": digest, "size": size,
                        "is_redacted": bool(is_redacted),
                        "parent_version_id": parent_version_id}, commit=False,
            )
            self.store.commit()
        return self.get_version(version_id)

    def withdraw_document(self, deal_id, doc_id, by, reason):
        with self.store.tx():
            self.store.execute(
                "UPDATE documents SET status=? WHERE doc_id=? AND deal_id=?",
                (T.DOC_WITHDRAWN, doc_id, deal_id),
            )
            self.store.append_event(
                deal_id, "document_withdrawn", actor_user_id=by,
                target_type="document", target_id=doc_id,
                detail={"reason": reason}, commit=False,
            )
            self.store.commit()

    # ---- 读取 ----
    def get_document(self, doc_id, deal_id=None):
        if deal_id:
            row = self.store.query_one(
                "SELECT * FROM documents WHERE doc_id=? AND deal_id=?",
                (doc_id, deal_id),
            )
        else:
            row = self.store.query_one("SELECT * FROM documents WHERE doc_id=?", (doc_id,))
        return row

    def get_version(self, version_id):
        return self.store.query_one(
            "SELECT * FROM document_versions WHERE version_id=?", (version_id,)
        )

    def latest_version(self, doc_id):
        return self.store.query_one(
            "SELECT * FROM document_versions WHERE doc_id=? AND scan_status='clean' "
            "ORDER BY version_no DESC LIMIT 1", (doc_id,)
        )

    def list_visible(self, ctx: Context):
        """返回该用户在当前交易此刻能看到的 (doc, version) 最新组合。"""
        from .policy import Policy  # 避免循环导入
        policy = Policy(self.store)
        out = []
        docs = self.store.query(
            "SELECT * FROM documents WHERE deal_id=? AND status=? ORDER BY doc_id",
            (ctx.deal_id, T.DOC_AVAILABLE),
        )
        for doc in docs:
            # 患者级原件文档对竞标方整体不可见，但其脱敏子文档可见
            if doc["patient_level"] and not doc["redaction_parent_doc_id"] \
                    and not (ctx.is_deal_owner or ctx.is_deal_admin or ctx.internal):
                continue
            v = self.latest_version(doc["doc_id"])
            if v is None:
                continue
            try:
                policy.can_view_version(ctx, doc, v)
            except Forbidden:
                continue
            out.append((doc, v))
        return out
