"""文档上传、扫描隔离、指纹谱系与水印预览/导出。

关键流程：
- 分块上传：init → 任意顺序/重复提交 chunk（断点续传）→ assemble 校验指纹；
  assemble 时校验文档乐观版本号，并发冲突持久化为事件且新版本不落库。
- 病毒扫描：失败版本留隔离区、状态 INFECTED、立案 SCAN_FAILED，永不可见；
  通过后内容寻址升入清洁区并开放。
- 脱敏谱系：脱敏件以子版本挂载，parent_version_no/children 双向可溯。
- 预览/导出：逐次生成 HMAC 唯一水印码与可见水印；L4 导出须逐次审批；
  导出中断持久化并立案；每次成功访问后跑异常批量访问检测。
"""

import base64
import os

from . import contract, models
from .errors import (
    AccessDeniedError,
    ConflictError,
    NotFoundError,
    ScanFailureError,
    VersionConflictError,
    WorkflowStateError,
)
from .security import (
    new_token,
    render_watermark,
    sha256_fingerprint,
    utcnow_iso,
    watermark_code,
)

# EICAR 测试签名：任何携带该串的文件判为染毒，便于无外部杀毒依赖时演示与测试。
EICAR_SIGNATURE = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE"

# 异常批量访问默认阈值：60 秒内 8 次成功预览/导出。
DEFAULT_ANOMALY_WINDOW = 60
DEFAULT_ANOMALY_THRESHOLD = 8


def default_scanner(content: bytes):
    """内置静态扫描器：命中 EICAR 签名即判毒。生产可替换为杀软适配器。"""
    if EICAR_SIGNATURE in content:
        return False, "EICAR_TEST_SIGNATURE"
    return True, None


class DocumentService:
    def __init__(self, store, authz, audit, incidents, scanner=None,
                 anomaly_window=DEFAULT_ANOMALY_WINDOW,
                 anomaly_threshold=DEFAULT_ANOMALY_THRESHOLD):
        self.store = store
        self.authz = authz
        self.audit = audit
        self.incidents = incidents
        self.scanner = scanner or default_scanner
        self.anomaly_window = anomaly_window
        self.anomaly_threshold = anomaly_threshold
        self.upload_dir = os.path.join(self.store.data_dir, "uploads")
        os.makedirs(self.upload_dir, exist_ok=True)

    # ======================================================= 内部辅助
    def _internal_user(self, user_id, deal_id, roles=("ROOM_ADMIN", "DEAL_LEAD")):
        decision = self.authz.require_deal_access(user_id, deal_id)
        if not decision.internal or not (set(roles) & decision.roles):
            raise AccessDeniedError("ADMIN_ONLY", "需要内部资料管理员权限")
        return decision

    def _doc(self, doc_id):
        doc = self.store.state["documents"].get(doc_id)
        if doc is None:
            raise NotFoundError(f"文档不存在: {doc_id}")
        return doc

    def _session_dir(self, upload_id):
        path = os.path.join(self.upload_dir, upload_id)
        os.makedirs(path, exist_ok=True)
        return path

    def _user_label(self, user_id):
        user = self.store.state["users"][user_id]
        org = self.store.state["orgs"][user["org_id"]]
        deal = self.store.state["deals"][user["deal_id"]]
        return {"user": f'{user["name"]}({user_id})', "org": org["name"], "deal": deal["name"]}

    # ======================================================= 文档登记
    def create_document(self, user_id, title, category, sensitivity):
        contract.validate_category(category)
        contract.validate_sensitivity(sensitivity)
        deal_id = self.store.state["users"][user_id]["deal_id"]
        self._internal_user(user_id, deal_id)
        with self.store.lock:
            doc = models.new_document(deal_id, title, category, sensitivity, user_id)
            self.store.state["documents"][doc["doc_id"]] = doc
            self.store.commit()
            self.audit.log("DOC_CREATED", deal_id=deal_id, org_id=None, user_id=user_id,
                           doc_id=doc["doc_id"], category=category, sensitivity=sensitivity)
            return dict(doc)

    def advance_phase(self, user_id, deal_id, phase):
        self._internal_user(user_id, deal_id, roles=("DEAL_LEAD",))
        if phase not in contract.phase_gates():
            raise NotFoundError(f"阶段不存在: {phase}")
        with self.store.lock:
            deal = self.store.state["deals"][deal_id]
            old = deal["phase"]
            if phase < old:
                raise WorkflowStateError("阶段只能向前推进")
            deal["phase"] = phase
            self.store.commit()
            self.audit.log("PHASE_ADVANCED", deal_id=deal_id, user_id=user_id,
                           **{"from": old, "to": phase})
            return {"from": old, "to": phase}

    # ======================================================= 分块上传
    def init_upload(self, user_id, doc_id, filename, total_size, chunk_size,
                    tier=models.TIER_ORIGINAL, expected_sha256=None,
                    parent_version_no=None):
        """初始化断点续传上传。parent_version_no 非空表示这是脱敏子版本。"""
        contract.validate_redaction_tier(tier)
        doc = self._doc(doc_id)
        self._internal_user(user_id, doc["deal_id"])
        if tier != models.TIER_ORIGINAL and parent_version_no is None:
            raise WorkflowStateError("脱敏件必须指定父版本（原件版本号）")
        if parent_version_no is not None and str(parent_version_no) not in doc["versions"]:
            raise NotFoundError(f"父版本不存在: v{parent_version_no}")
        upload_id = "UPL-" + new_token(12)
        total_chunks = (total_size + chunk_size - 1) // chunk_size
        session = {
            "upload_id": upload_id,
            "doc_id": doc_id,
            "filename": filename,
            "total_size": total_size,
            "chunk_size": chunk_size,
            "total_chunks": total_chunks,
            "received": [],
            "tier": tier,
            "parent_version_no": parent_version_no,
            "expected_sha256": expected_sha256,
            "status": models.US_INIT,
            "created_by": user_id,
            "created_ts": utcnow_iso(),
            "assembled_fingerprint": None,
        }
        with self.store.lock:
            self.store.state["upload_sessions"][upload_id] = session
            self.store.commit()
            self.audit.log("UPLOAD_INIT", deal_id=doc["deal_id"], user_id=user_id,
                           doc_id=doc_id, upload_id=upload_id, total_chunks=total_chunks)
        return {"upload_id": upload_id, "total_chunks": total_chunks,
                "received": [], "chunk_size": chunk_size}

    def put_chunk(self, upload_id, index, content: bytes):
        """提交单个分块；相同 index 重复提交幂等（断点续传关键）。"""
        with self.store.lock:
            session = self.store.state["upload_sessions"].get(upload_id)
            if session is None:
                raise NotFoundError(f"上传会话不存在: {upload_id}")
            if session["status"] in (models.US_ASSEMBLED, models.US_ABORTED):
                raise WorkflowStateError(f"上传已{session['status']}，不可再写分块")
            if not 0 <= index < session["total_chunks"]:
                raise ConflictError(f"分块序号越界: {index}")
            path = os.path.join(self._session_dir(upload_id), f"{index:08d}.part")
            # 已存在且指纹一致 → 幂等重传，直接确认。
            if os.path.exists(path):
                with open(path, "rb") as fh:
                    if sha256_fingerprint(fh.read()) == sha256_fingerprint(content):
                        return self._upload_status(session)
            with open(path, "wb") as fh:
                fh.write(content)
            if index not in session["received"]:
                session["received"].append(index)
                session["received"].sort()
            session["status"] = models.US_UPLOADING
            self.store.commit()
            return self._upload_status(session)

    def abort_upload(self, upload_id, reason="USER_ABORT"):
        with self.store.lock:
            session = self.store.state["upload_sessions"].get(upload_id)
            if session is None:
                raise NotFoundError(f"上传会话不存在: {upload_id}")
            if session["status"] == models.US_ASSEMBLED:
                raise WorkflowStateError("上传已完成，不可中止")
            session["status"] = models.US_ABORTED
            session["abort_reason"] = reason
            session["aborted_ts"] = utcnow_iso()
            self.store.commit()
            self.audit.log("UPLOAD_ABORTED", user_id=session["created_by"],
                           doc_id=session["doc_id"], upload_id=upload_id, reason=reason)
            return self._upload_status(session)

    def upload_status(self, upload_id):
        session = self.store.state["upload_sessions"].get(upload_id)
        if session is None:
            raise NotFoundError(f"上传会话不存在: {upload_id}")
        return self._upload_status(session)

    @staticmethod
    def _upload_status(session):
        missing = sorted(set(range(session["total_chunks"])) - set(session["received"]))
        return {
            "upload_id": session["upload_id"],
            "status": session["status"],
            "received": list(session["received"]),
            "missing_chunks": missing,
            "total_chunks": session["total_chunks"],
            "assembled_fingerprint": session.get("assembled_fingerprint"),
        }

    def complete_upload(self, upload_id, expected_version=None):
        """拼装、校验、扫描、落版本。expected_version 做乐观并发控制。"""
        with self.store.lock:
            session = self.store.state["upload_sessions"].get(upload_id)
            if session is None:
                raise NotFoundError(f"上传会话不存在: {upload_id}")
            doc = self._doc(session["doc_id"])
            missing = sorted(set(range(session["total_chunks"])) - set(session["received"]))
            if missing:
                raise WorkflowStateError(f"缺少分块，无法拼装: {missing[:10]}")
            if session["status"] == models.US_ASSEMBLED:
                return {"fingerprint": session["assembled_fingerprint"],
                        "version_no": session.get("version_no"), "idempotent": True}

            content = self._assemble(upload_id, session)
            fingerprint = sha256_fingerprint(content)
            if session["expected_sha256"] and session["expected_sha256"] != fingerprint:
                raise ConflictError("客户端指纹与拼装结果不一致")
            if len(content) != session["total_size"]:
                raise ConflictError("拼装大小与声明大小不一致")

            # 乐观并发：仅新原件版本检查 latest；脱敏子版本挂在固定父版本下。
            if (session["parent_version_no"] is None
                    and expected_version is not None
                    and doc["latest_version"] != expected_version):
                self.store.put_quarantine(content)  # 冲突件不入清洁区
                session["status"] = models.US_ABORTED
                session["abort_reason"] = "VERSION_CONFLICT"
                session["aborted_ts"] = utcnow_iso()
                self.store.commit()
                self.incidents.open(
                    "VERSION_CONFLICT", doc["deal_id"],
                    f"并发版本冲突：{doc['doc_id']} 基于 v{expected_version}，当前 v{doc['latest_version']}",
                    details={"doc_id": doc["doc_id"], "expected_version": expected_version,
                             "actual_version": doc["latest_version"], "fingerprint": fingerprint,
                             "upload_id": upload_id},
                    related_user=session["created_by"], related_doc=doc["doc_id"],
                    auto_action="QUARANTINE_BLOB",
                )
                raise VersionConflictError(
                    f"版本冲突：期望 v{expected_version}，实际 v{doc['latest_version']}",
                    expected=expected_version, actual=doc["latest_version"])

            # 内容先进隔离区待扫。
            self.store.put_quarantine(content)
            version_no = self._next_version_no(doc, session)
            version = models.new_version(
                version_no, fingerprint, len(content), session["filename"],
                session["tier"], session["created_by"],
                parent_version_no=session["parent_version_no"],
                scan_status=models.SCAN_PENDING)
            doc["versions"][str(version_no)] = version
            self.store.commit()

        # 扫描在锁外执行（可能很慢），结论再回写。
        return self._apply_scan(doc["doc_id"], version_no, upload_id)

    @staticmethod
    def _next_version_no(doc, session):
        """原件版本占用主版本号；脱敏子版本使用 <父>.<序号> 字符串。"""
        if session["parent_version_no"] is None:
            return doc["latest_version"] + 1
        parent = session["parent_version_no"]
        suffix = 1
        while f"{parent}.{suffix}" in doc["versions"]:
            suffix += 1
        return f"{parent}.{suffix}"

    def _assemble(self, upload_id, session):
        parts = []
        for index in range(session["total_chunks"]):
            with open(os.path.join(self._session_dir(upload_id), f"{index:08d}.part"), "rb") as fh:
                parts.append(fh.read())
        return b"".join(parts)

    def _apply_scan(self, doc_id, version_no, upload_id):
        with self.store.lock:
            doc = self._doc(doc_id)
            version = doc["versions"][str(version_no)]
            content = self.store.read_quarantine(version["fingerprint"])
            clean, reason = self.scanner(content)
            version["scanned_ts"] = utcnow_iso()
            if not clean:
                version["scan_status"] = models.SCAN_INFECTED
                version["scan_reason"] = reason
                session = self.store.state["upload_sessions"].get(upload_id)
                if session is not None:
                    session["status"] = models.US_ABORTED
                    session["abort_reason"] = "SCAN_FAILED"
                    session["aborted_ts"] = utcnow_iso()
                self.store.commit()
                self.incidents.open(
                    "SCAN_FAILED", doc["deal_id"],
                    f"病毒扫描失败：{doc_id} v{version_no}（{reason}）",
                    details={"doc_id": doc_id, "version_no": version_no,
                             "fingerprint": version["fingerprint"], "reason": reason},
                    related_user=version["uploaded_by"], related_doc=doc_id,
                    auto_action="KEEP_IN_QUARANTINE",
                )
                raise ScanFailureError(f"扫描未通过: {reason}", fingerprint=version["fingerprint"])

            version["scan_status"] = models.SCAN_CLEAN
            self.store.promote_to_clean(version["fingerprint"])
            # 谱系回链 + 主版本推进。
            parent = version["parent_version_no"]
            if parent is not None:
                doc["versions"][str(parent)]["children"].append(version_no)
            else:
                doc["latest_version"] = max(doc["latest_version"], version_no)
            # 精确标记发起本次上传的会话完成。
            session = self.store.state["upload_sessions"].get(upload_id)
            if session is not None:
                session["status"] = models.US_ASSEMBLED
                session["assembled_fingerprint"] = version["fingerprint"]
                session["version_no"] = version_no
            self.store.commit()
            self.audit.log("SCAN_CLEAN", deal_id=doc["deal_id"], user_id=version["uploaded_by"],
                           doc_id=doc_id, version_no=version_no, tier=version["tier"],
                           fingerprint=version["fingerprint"])
            return {"doc_id": doc_id, "version_no": version_no,
                    "fingerprint": version["fingerprint"], "scan_status": models.SCAN_CLEAN,
                    "tier": version["tier"], "parent_version_no": parent}

    # ======================================================= 谱系与目录
    def lineage(self, user_id, doc_id):
        doc = self._doc(doc_id)
        self.authz.require_deal_access(user_id, doc["deal_id"])
        nodes = []
        for key in sorted(doc["versions"], key=lambda k: tuple(int(x) for x in str(k).split("."))):
            v = doc["versions"][key]
            nodes.append({
                "version_no": v["version_no"], "tier": v["tier"],
                "fingerprint": v["fingerprint"], "scan_status": v["scan_status"],
                "parent_version_no": v["parent_version_no"], "children": list(v["children"]),
                "uploaded_ts": v["uploaded_ts"],
            })
        return {"doc_id": doc_id, "category": doc["category"],
                "sensitivity": doc["sensitivity"], "versions": nodes}

    def list_documents(self, user_id, deal_id):
        return self.authz.list_visible_documents(user_id, deal_id)

    def withdraw_document(self, user_id, doc_id, reason):
        doc = self._doc(doc_id)
        self._internal_user(user_id, doc["deal_id"], roles=("DEAL_LEAD", "ROOM_ADMIN"))
        with self.store.lock:
            doc["status"] = models.DOC_WITHDRAWN
            doc["withdrawn_ts"] = utcnow_iso()
            doc["withdraw_reason"] = reason
            self.store.commit()
            self.audit.log("DOC_WITHDRAWN", deal_id=doc["deal_id"], user_id=user_id,
                           doc_id=doc_id, reason=reason)
        return {"doc_id": doc_id, "status": models.DOC_WITHDRAWN}

    # ======================================================= 水印访问
    def _mint_watermark(self, user_id, action, doc_id, version_no):
        nonce = new_token(16)
        code = watermark_code(self.store.state["watermark_secret"], f"{action}:{nonce}")
        label = self._user_label(user_id)
        text = render_watermark({**label, "when": utcnow_iso(), "code": code})
        return {"code": code, "nonce": nonce, "text": text}

    def verify_watermark_code(self, code):
        """管理员验证水印真伪并返回溯源访问事件。"""
        return self.incidents.trace_watermark(code)

    def _record_access(self, action, user_id, doc, version, watermark, **extra):
        user = self.store.state["users"][user_id]
        event = self.audit.log(
            action, deal_id=doc["deal_id"], org_id=user["org_id"], user_id=user_id,
            doc_id=doc["doc_id"], version_no=version["version_no"], tier=version["tier"],
            watermark=watermark, **extra)
        self._check_anomaly(user_id, doc["deal_id"])
        return event

    def _check_anomaly(self, user_id, deal_id):
        """超阈值批量访问 → 系统自动停权（新的查看立即被授权层阻断）并立案。"""
        user = self.store.state["users"].get(user_id)
        if user is None or user.get("suspended"):
            return
        recent = self.audit.detect_bulk_access(user_id, self.anomaly_window, self.anomaly_threshold)
        if not recent:
            return
        user["suspended"] = True
        user["suspend_reason"] = "ANOMALY_BULK_ACCESS"
        self.store.commit()
        self.incidents.open(
            "ANOMALY_BULK_ACCESS", deal_id,
            f"异常批量访问：{user['name']} 在 {self.anomaly_window}s 内访问 {len(recent)} 份材料",
            details={"window_seconds": self.anomaly_window,
                     "threshold": self.anomaly_threshold,
                     "audit_ids": [e["audit_id"] for e in recent]},
            related_user=user_id, related_org=user["org_id"],
            auto_action="SUSPEND_USER",
        )

    def preview(self, user_id, doc_id, version_no):
        """预览：授权实时求值 + 唯一水印，返回内容（base64）与水印。"""
        with self.store.lock:
            doc = self._doc(doc_id)
            version = self.authz.visible_version(user_id, doc, version_no)
            watermark = self._mint_watermark(user_id, "PREVIEW", doc_id, version_no)
            content = self.store.read_clean(version["fingerprint"])
            event = self._record_access("DOC_PREVIEW", user_id, doc, version, watermark)
        return {
            "doc_id": doc_id, "version_no": version["version_no"],
            "tier": version["tier"], "filename": version["filename"],
            "fingerprint": version["fingerprint"],
            "watermark": watermark, "audit_id": event["audit_id"],
            "content_base64": base64.b64encode(content).decode("ascii"),
        }

    # ======================================================= 导出（含 L4 审批与中断）
    def request_export(self, user_id, doc_id, version_no):
        with self.store.lock:
            doc = self._doc(doc_id)
            version = self.authz.visible_version(user_id, doc, version_no)
            approval_required = doc["sensitivity"] == "L4"
            export_id = "EXP-" + new_token(12)
            record = {
                "export_id": export_id,
                "deal_id": doc["deal_id"], "org_id": self.store.state["users"][user_id]["org_id"],
                "user_id": user_id, "doc_id": doc_id, "version_no": version["version_no"],
                "tier": version["tier"], "fingerprint": version["fingerprint"],
                "status": "PENDING_APPROVAL" if approval_required else models.EXPORT_ACTIVE,
                "size": version["size"], "delivered": 0,
                "created_ts": utcnow_iso(), "watermark": None,
                "approval": {"required": approval_required, "by": None, "ts": None},
            }
            self.store.state["export_sessions"][export_id] = record
            self.store.commit()
            self.audit.log("EXPORT_REQUESTED", deal_id=doc["deal_id"], user_id=user_id,
                           doc_id=doc_id, version_no=version["version_no"],
                           export_id=export_id, approval_required=approval_required,
                           result="PENDING" if approval_required else "OK")
            return dict(record)

    def approve_export(self, admin_id, export_id, approve=True):
        with self.store.lock:
            record = self.store.state["export_sessions"].get(export_id)
            if record is None:
                raise NotFoundError(f"导出会话不存在: {export_id}")
            self._internal_user(admin_id, record["deal_id"],
                                roles=("ROOM_ADMIN", "DEAL_LEAD", "LEGAL"))
            if record["status"] != "PENDING_APPROVAL":
                raise WorkflowStateError("该导出无需审批或已审批")
            record["status"] = models.EXPORT_ACTIVE if approve else "REJECTED"
            record["approval"]["by"] = admin_id
            record["approval"]["ts"] = utcnow_iso()
            self.store.commit()
            self.audit.log("EXPORT_APPROVED" if approve else "EXPORT_REJECTED",
                           deal_id=record["deal_id"], user_id=admin_id,
                           doc_id=record["doc_id"], export_id=export_id,
                           result="OK" if approve else "DENIED")
            return dict(record)

    def fetch_export(self, user_id, export_id, max_bytes):
        """拉取导出内容块；每次导出会话只有一个唯一水印。"""
        with self.store.lock:
            record = self.store.state["export_sessions"].get(export_id)
            if record is None:
                raise NotFoundError(f"导出会话不存在: {export_id}")
            if record["user_id"] != user_id:
                raise AccessDeniedError("NOT_EXPORT_OWNER", "仅导出申请人可拉取")
            if record["status"] == "PENDING_APPROVAL":
                raise AccessDeniedError("EXPORT_PENDING_APPROVAL", "L4 导出等待逐次审批")
            if record["status"] == "REJECTED":
                raise AccessDeniedError("EXPORT_REJECTED", "导出申请已被拒绝")
            if record["status"] == models.EXPORT_INTERRUPTED:
                raise WorkflowStateError("导出已中断，请重新申请")
            if record["status"] == models.EXPORT_COMPLETED:
                raise WorkflowStateError("导出已完成")
            doc = self._doc(record["doc_id"])
            # 实时再校验：审批后若被撤权/撤文档，立即阻断。
            version = self.authz.visible_version(user_id, doc, record["version_no"])
            if record["watermark"] is None:
                record["watermark"] = self._mint_watermark(user_id, "EXPORT",
                                                           record["doc_id"], record["version_no"])
            content = self.store.read_clean(record["fingerprint"])
            start = record["delivered"]
            end = min(start + max_bytes, len(content))
            chunk = content[start:end]
            record["delivered"] = end
            finished = end >= len(content)
            if finished:
                record["status"] = models.EXPORT_COMPLETED
                record["completed_ts"] = utcnow_iso()
            self.store.commit()
            event = None
            if start == 0:
                event = self._record_access("DOC_EXPORT", user_id, doc, version,
                                            record["watermark"], export_id=export_id)
            return {
                "export_id": export_id, "status": record["status"],
                "offset": start, "next_offset": end, "total": len(content),
                "finished": finished, "watermark": record["watermark"],
                "audit_id": event["audit_id"] if event else None,
                "content_base64": base64.b64encode(chunk).decode("ascii"),
            }

    def interrupt_export(self, export_id, byte_offset=None, by="USER"):
        """下载中断：持久化状态并立事件卷宗（可恢复或重新申请）。"""
        with self.store.lock:
            record = self.store.state["export_sessions"].get(export_id)
            if record is None:
                raise NotFoundError(f"导出会话不存在: {export_id}")
            if record["status"] in (models.EXPORT_COMPLETED, models.EXPORT_INTERRUPTED):
                return dict(record)
            record["status"] = models.EXPORT_INTERRUPTED
            record["interrupted_ts"] = utcnow_iso()
            record["interrupted_at_offset"] = byte_offset if byte_offset is not None else record["delivered"]
            record["interrupted_by"] = by
            self.store.commit()
            self.incidents.open(
                "DOWNLOAD_INTERRUPTED", record["deal_id"],
                f"下载中断：{record['doc_id']} v{record['version_no']} 于 {record['interrupted_at_offset']} 字节",
                details={"export_id": export_id, "offset": record["interrupted_at_offset"],
                         "size": record["size"], "by": by},
                related_user=record["user_id"], related_org=record["org_id"],
                related_doc=record["doc_id"], auto_action="MARK_EXPORT_INTERRUPTED",
            )
            return dict(record)

    def export_status(self, user_id, export_id):
        record = self.store.state["export_sessions"].get(export_id)
        if record is None:
            raise NotFoundError(f"导出会话不存在: {export_id}")
        if record["user_id"] != user_id:
            raise AccessDeniedError("NOT_EXPORT_OWNER")
        return dict(record)
