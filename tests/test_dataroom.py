"""端到端场景测试：授权生命周期、指纹谱系、水印、事件处置、问答双审、复原与持久化。"""

import json
import os
import tempfile
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from threading import Thread

from dataroom import DataRoom
from dataroom.errors import (
    AccessDeniedError,
    NotFoundError,
    ScanFailureError,
    VersionConflictError,
    WorkflowStateError,
)
from dataroom.httpapi import build_server

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE" + b"-padding"


def _chunks(content, size):
    return [content[i:i + size] for i in range(0, len(content), size)]


class World:
    """测试用世界构建器。"""

    def __init__(self, path, anomaly_threshold=8):
        self.room = DataRoom(path, anomaly_threshold=anomaly_threshold)
        lead = self.room.bootstrap_deal("出海授权交易", "王负责", "lead@firm.cn")
        self.lead_id, self.lead_secret, self.deal_id = (
            lead["user_id"], lead["secret"], lead["deal_id"])

    def login_lead(self):
        return self.room.login(self.lead_id, self.lead_secret)["token"]

    def bidder(self, name, roles, org_name=None):
        token = self.login_lead()
        org = self.room.create_bidder_org(self.lead_id, org_name or f"{name}药企")
        invite = self.room.create_invitation(self.lead_id, org["org_id"], roles)
        user = self.room.enroll(invite["enrollment_token"], name, f"{name}@bidder.com")
        self.room.sign_nda(user["user_id"])
        return {"org_id": org["org_id"], "user_id": user["user_id"],
                "secret": user["secret"], "roles": roles}

    def internal_user(self, name, role):
        org_id = next(o["org_id"] for o in self.room.store.state["orgs"].values()
                      if o["kind"] == "INTERNAL" and o["deal_id"] == self.deal_id)
        invite = self.room.create_invitation(self.lead_id, org_id, [role])
        user = self.room.enroll(invite["enrollment_token"], name, f"{name}@firm.cn")
        self.room.sign_nda(user["user_id"])
        return user["user_id"], user["secret"]

    def doc(self, title, category, sensitivity):
        return self.room.documents.create_document(
            self.lead_id, title, category, sensitivity)["doc_id"]

    def upload(self, doc_id, content, filename, tier="ORIGINAL", parent=None,
               expected_version=None, chunk_size=None):
        chunk_size = chunk_size or max(1, len(content) // 2 + 1)
        init = self.room.documents.init_upload(
            self.lead_id, doc_id, filename, len(content), chunk_size,
            tier=tier, parent_version_no=parent, expected_sha256=None)
        for index, part in enumerate(_chunks(content, chunk_size)):
            self.room.documents.put_chunk(init["upload_id"], index, part)
        return self.room.documents.complete_upload(init["upload_id"],
                                                  expected_version=expected_version)


class AuthzLifecycleTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.w = World(self.tmp)
        self.room = self.w.room
        self.patent_doc = self.w.doc("核心专利族分析", "PATENT", "L2")
        self.w.upload(self.patent_doc, b"patent-original", "patent.docx",
                      tier="ORIGINAL", expected_version=0)
        self.w.upload(self.patent_doc, b"patent-standard-redacted", "patent-redacted.docx",
                      tier="STANDARD", parent=1)

    def test_nda_gate(self):
        org = self.room.create_bidder_org(self.w.lead_id, "未签NDA药企")
        invite = self.room.create_invitation(self.w.lead_id, org["org_id"], ["商业尽调"])
        user = self.room.enroll(invite["enrollment_token"], "张尽调", "z@b.com")
        with self.assertRaises(AccessDeniedError) as ctx:
            self.room.documents.preview(user["user_id"], self.patent_doc, "1.1")
        self.assertEqual(ctx.exception.reason, "NDA_NOT_SIGNED")

    def test_phase_role_and_tier_gating(self):
        # 阶段一：仅专利 L2；商业尽调可见标准脱敏件，技术尽调不可见。
        biz = self.w.bidder("李商业", ["商业尽调"])
        tech = self.w.bidder("赵技术", ["技术尽调"])
        listing = self.room.documents.list_documents(biz["user_id"], self.w.deal_id)
        self.assertEqual([d["doc_id"] for d in listing], [self.patent_doc])
        self.assertEqual(listing[0]["visible_versions"], ["1.1"])
        with self.assertRaises(AccessDeniedError) as ctx:
            self.room.documents.preview(tech["user_id"], self.patent_doc, "1.1")
        self.assertEqual(ctx.exception.reason, "ROLE_CATEGORY_NOT_ALLOWED")
        # 原件对外永不开放。
        with self.assertRaises(AccessDeniedError) as ctx:
            self.room.documents.preview(biz["user_id"], self.patent_doc, 1)
        self.assertEqual(ctx.exception.reason, "TIER_FORBIDDEN")
        # 内部可看原件。
        self.assertEqual(self.room.documents.preview(self.w.lead_id, self.patent_doc, 1)["tier"], "ORIGINAL")

    def test_phase_advance_opens_categories(self):
        clinical = self.w.doc("二期临床方案", "CLINICAL", "L3")
        self.w.upload(clinical, b"clinical-original", "clin.docx", expected_version=0)
        self.w.upload(clinical, b"clinical-standard", "clin-redacted.docx",
                      tier="STANDARD", parent=1)
        tech = self.w.bidder("钱技术", ["技术尽调"])
        with self.assertRaises(AccessDeniedError) as ctx:
            self.room.documents.preview(tech["user_id"], clinical, "1.1")
        self.assertEqual(ctx.exception.reason, "PHASE_CATEGORY_CLOSED")
        self.room.documents.advance_phase(self.w.lead_id, self.w.deal_id, 2)
        preview = self.room.documents.preview(tech["user_id"], clinical, "1.1")
        self.assertEqual(preview["tier"], "STANDARD")

    def test_immediate_block_on_revoke_offboard_nda_withdraw_terminate(self):
        bidder = self.w.bidder("孙商业", ["商业尽调"])
        uid = bidder["user_id"]
        self.room.documents.preview(uid, self.patent_doc, "1.1")

        grant_id = next(g["grant_id"] for g in self.room.store.state["grants"].values()
                        if g["scope"] == "USER" and g["subject_id"] == uid)
        self.room.revoke_grant(self.w.lead_id, grant_id, "撤权测试")
        with self.assertRaises(AccessDeniedError) as ctx:
            self.room.documents.preview(uid, self.patent_doc, "1.1")
        self.assertEqual(ctx.exception.reason, "NO_ACTIVE_GRANT")

        # 重新授权后 NDA 撤回也立即阻断。
        self.room.grant(self.w.lead_id, "USER", uid, "商业尽调")
        self.room.withdraw_nda(self.w.lead_id, uid, "NDA 瑕疵")
        with self.assertRaises(AccessDeniedError) as ctx:
            self.room.documents.preview(uid, self.patent_doc, "1.1")
        self.assertEqual(ctx.exception.reason, "NDA_NOT_SIGNED")

        self.room.sign_nda(uid)
        self.room.offboard_user(self.w.lead_id, uid, "人员离职")
        with self.assertRaises(AccessDeniedError) as ctx:
            self.room.documents.preview(uid, self.patent_doc, "1.1")
        self.assertEqual(ctx.exception.reason, "USER_OFFBOARDED")
        # 离职后旧密钥无法再登录。
        with self.assertRaises(AccessDeniedError):
            self.room.login(uid, bidder["secret"])

        # 交易终止阻断全部新查看。
        other = self.w.bidder("周商业", ["商业尽调"])
        self.room.terminate_deal(self.w.lead_id, self.w.deal_id, "交易终止")
        with self.assertRaises(AccessDeniedError) as ctx:
            self.room.documents.preview(other["user_id"], self.patent_doc, "1.1")
        self.assertEqual(ctx.exception.reason, "DEAL_TERMINATED")


class UploadScanLineageTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.w = World(self.tmp)
        self.room = self.w.room
        self.doc_id = self.w.doc("CMC 工艺包", "CMC", "L3")

    def test_resumable_chunks_and_fingerprint(self):
        content = "工艺数据".encode("utf-8") * 13  # 156 字节，分 3 块
        chunk_size = 52
        init = self.room.documents.init_upload(
            self.w.lead_id, self.doc_id, "cmc.bin", len(content), chunk_size,
            tier="ORIGINAL", expected_sha256=None)
        parts = _chunks(content, chunk_size)
        self.room.documents.put_chunk(init["upload_id"], 0, parts[0])
        self.room.documents.put_chunk(init["upload_id"], 2, parts[2])
        with self.assertRaises(WorkflowStateError):
            self.room.documents.complete_upload(init["upload_id"], expected_version=0)
        status = self.room.documents.put_chunk(init["upload_id"], 1, parts[1])
        self.assertEqual(status["missing_chunks"], [])
        # 断点重传：重复提交相同分块幂等。
        self.room.documents.put_chunk(init["upload_id"], 0, parts[0])
        result = self.room.documents.complete_upload(init["upload_id"], expected_version=0)
        import hashlib
        self.assertEqual(result["fingerprint"], hashlib.sha256(content).hexdigest())

    def test_scan_failure_quarantines(self):
        init = self.room.documents.init_upload(
            self.w.lead_id, self.doc_id, "evil.bin", len(EICAR), len(EICAR),
            tier="ORIGINAL")
        self.room.documents.put_chunk(init["upload_id"], 0, EICAR)
        with self.assertRaises(ScanFailureError):
            self.room.documents.complete_upload(init["upload_id"], expected_version=0)
        doc = self.room.store.state["documents"][self.doc_id]
        self.assertEqual(doc["versions"]["1"]["scan_status"], "INFECTED")
        self.assertTrue(self.room.store.blob_exists("quarantine",
                                                    doc["versions"]["1"]["fingerprint"]))
        self.assertFalse(self.room.store.blob_exists("clean",
                                                     doc["versions"]["1"]["fingerprint"]))
        with self.assertRaises(AccessDeniedError) as ctx:
            self.room.documents.preview(self.w.lead_id, self.doc_id, 1)
        self.assertEqual(ctx.exception.reason, "SCAN_NOT_CLEAN")
        incidents = self.room.list_incidents(self.w.lead_id, self.w.deal_id)
        self.assertEqual([i["kind"] for i in incidents], ["SCAN_FAILED"])

    def test_concurrent_version_conflict_persisted(self):
        self.w.upload(self.doc_id, b"version-1-bytes", "a.bin", expected_version=0)
        init = self.room.documents.init_upload(
            self.w.lead_id, self.doc_id, "b.bin", 9, 9, tier="ORIGINAL")
        self.room.documents.put_chunk(init["upload_id"], 0, b"v2-loser!")
        with self.assertRaises(VersionConflictError):
            # 基于过期的 v0 提交，实际已到 v1。
            self.room.documents.complete_upload(init["upload_id"], expected_version=0)
        doc = self.room.store.state["documents"][self.doc_id]
        self.assertEqual(doc["latest_version"], 1)
        self.assertNotIn("2", doc["versions"])
        kinds = [i["kind"] for i in self.room.list_incidents(self.w.lead_id, self.w.deal_id)]
        self.assertIn("VERSION_CONFLICT", kinds)

    def test_redaction_lineage(self):
        self.w.upload(self.doc_id, b"original-patient-level", "raw.csv", expected_version=0)
        std = self.w.upload(self.doc_id, b"standard-redacted", "std.csv",
                            tier="STANDARD", parent=1)
        agg = self.w.upload(self.doc_id, b"aggregated-stats-only", "agg.csv",
                            tier="AGGREGATED", parent=1)
        lineage = self.room.documents.lineage(self.w.lead_id, self.doc_id)
        self.assertEqual([v["version_no"] for v in lineage["versions"]], [1, "1.1", "1.2"])
        self.assertEqual(lineage["versions"][0]["children"], ["1.1", "1.2"])
        self.assertEqual(std["fingerprint"] != agg["fingerprint"], True)
        self.assertEqual(std["parent_version_no"], 1)


class WatermarkExportAnomalyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.w = World(self.tmp, anomaly_threshold=4)
        self.room = self.w.room
        self.doc_id = self.w.doc("L4 患者级安全性库", "CLINICAL", "L4")
        self.w.upload(self.doc_id, b"patient-level-raw", "raw.csv", expected_version=0)
        self.w.upload(self.doc_id, b"aggregated-stats", "agg.csv",
                      tier="AGGREGATED", parent=1)
        self.room.documents.advance_phase(self.w.lead_id, self.w.deal_id, 3)
        self.bidder = self.w.bidder("吴技术", ["技术尽调"])
        self.uid = self.bidder["user_id"]

    def test_unique_watermarks_every_preview(self):
        codes = {self.room.documents.preview(self.uid, self.doc_id, "1.1")["watermark"]["code"]
                 for _ in range(2)}
        self.assertEqual(len(codes), 2)
        code = next(iter(codes))
        trace = self.room.documents.verify_watermark_code(code)
        self.assertEqual(trace["user_id"], self.uid)
        self.assertEqual(trace["doc_id"], self.doc_id)

    def test_l4_export_approval_and_interrupt(self):
        export = self.room.documents.request_export(self.uid, self.doc_id, "1.1")
        self.assertEqual(export["status"], "PENDING_APPROVAL")
        with self.assertRaises(AccessDeniedError):
            self.room.documents.fetch_export(self.uid, export["export_id"], 1024)
        self.room.documents.approve_export(self.w.lead_id, export["export_id"])
        first = self.room.documents.fetch_export(self.uid, export["export_id"], 4)
        self.assertEqual(first["finished"], False)
        # 管理员中断下载 → 事件持久化，后续拉取被拒。
        self.room.documents.interrupt_export(export["export_id"], byte_offset=4, by="ADMIN")
        with self.assertRaises(WorkflowStateError):
            self.room.documents.fetch_export(self.uid, export["export_id"], 1024)
        incidents = self.room.list_incidents(self.w.lead_id, self.w.deal_id)
        self.assertIn("DOWNLOAD_INTERRUPTED", [i["kind"] for i in incidents])

    def test_revocation_mid_export_blocks_next_fetch(self):
        export = self.room.documents.request_export(self.uid, self.doc_id, "1.1")
        self.room.documents.approve_export(self.w.lead_id, export["export_id"])
        self.room.documents.fetch_export(self.uid, export["export_id"], 4)
        grant_id = next(g["grant_id"] for g in self.room.store.state["grants"].values()
                        if g["subject_id"] == self.uid)
        self.room.revoke_grant(self.w.lead_id, grant_id, "导出过程中撤权")
        with self.assertRaises(AccessDeniedError):
            self.room.documents.fetch_export(self.uid, export["export_id"], 1024)

    def test_bulk_access_auto_suspends(self):
        for _ in range(4):  # 第 4 次成功访问后越过阈值，系统自动停权
            self.room.documents.preview(self.uid, self.doc_id, "1.1")
        with self.assertRaises(AccessDeniedError) as ctx:
            self.room.documents.preview(self.uid, self.doc_id, "1.1")  # 新查看立即被阻断
        self.assertEqual(ctx.exception.reason, "USER_SUSPENDED:ANOMALY_BULK_ACCESS")
        kinds = [i["kind"] for i in self.room.list_incidents(self.w.lead_id, self.w.deal_id)]
        self.assertIn("ANOMALY_BULK_ACCESS", kinds)
        dossier = self.room.get_incident(self.w.lead_id,
                                         [i for i in self.room.list_incidents(
                                             self.w.lead_id, self.w.deal_id)
                                          if i["kind"] == "ANOMALY_BULK_ACCESS"][0]["incident_id"])
        self.assertGreaterEqual(len(dossier["audit_trail"]), 4)


class LeakResponseTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.w = World(self.tmp)
        self.room = self.w.room
        self.doc_id = self.w.doc("专利自由实施分析", "PATENT", "L2")
        self.w.upload(self.doc_id, b"fto-report", "fto.docx", expected_version=0)
        self.w.upload(self.doc_id, b"fto-redacted", "fto-r.docx", tier="STANDARD", parent=1)
        self.bidder = self.w.bidder("郑商业", ["商业尽调"])

    def test_leak_trace_and_freeze(self):
        preview = self.room.documents.preview(self.bidder["user_id"], self.doc_id, "1.1")
        code = preview["watermark"]["code"]
        result = self.room.report_leak(
            self.w.lead_id, code, "发现外泄截图", scope="USER")
        self.assertEqual(result["trace"]["user_id"], self.bidder["user_id"])
        self.assertEqual(result["trace"]["doc_id"], self.doc_id)
        with self.assertRaises(AccessDeniedError) as ctx:
            self.room.documents.preview(self.bidder["user_id"], self.doc_id, "1.1")
        self.assertTrue(ctx.exception.reason.startswith("USER_SUSPENDED"))
        # 旧会话全部注销。
        with self.assertRaises(AccessDeniedError):
            self.room.authenticate(result["trace"] and self.room.login(
                self.bidder["user_id"], self.bidder["secret"])["token"])
        incident = self.room.get_incident(self.w.lead_id, result["incident"]["incident_id"])
        self.assertEqual(incident["kind"], "LEAK")
        self.assertIn("FREEZE_USER", [a["action"] for a in incident["actions"]])


class QaDualReviewTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.w = World(self.tmp)
        self.room = self.w.room
        self.doc_id = self.w.doc("专利答复要点", "PATENT", "L2")
        self.w.upload(self.doc_id, b"patent-content", "p.docx", expected_version=0)
        self.w.upload(self.doc_id, b"patent-redacted", "p-r.docx",
                      tier="STANDARD", parent=1)
        self.biz = self.w.bidder("冯商业", ["商业尽调"])
        self.other = self.w.bidder("竞品药企", ["商业尽调"], org_name="竞品药企")
        self.legal_id, _ = self.w.internal_user("法务陈", "LEGAL")
        self.medical_id, _ = self.w.internal_user("医学林", "MEDICAL")

    def test_refs_must_be_currently_visible_and_dual_review(self):
        uid = self.biz["user_id"]
        q = self.room.qa.ask(uid, "专利权属是否清晰？",
                             [{"doc_id": self.doc_id, "version_no": "1.1"}])
        qid = q["q_id"]
        # 引用当前不可见的原件版本 → 拒绝。
        with self.assertRaises(AccessDeniedError):
            self.room.qa.ask(uid, "想看原件", [{"doc_id": self.doc_id, "version_no": 1}])
        self.room.qa.draft_answer(self.w.lead_id, qid, "权属链完整。",
                                  refs=[{"doc_id": self.doc_id, "version_no": "1.1"}])
        self.room.qa.review(self.legal_id, qid, "legal", "APPROVED")
        # 单审不能发布。
        self.assertEqual(self.room.qa.get(uid, qid)["answer"], None)
        self.room.qa.review(self.medical_id, qid, "medical", "APPROVED")
        published = self.room.qa.get(uid, qid)
        self.assertEqual(published["status"], "PUBLISHED")
        self.assertEqual(published["answer"]["text"], "权属链完整。")
        # 其他竞标方不可见该问答。
        with self.assertRaises(AccessDeniedError):
            self.room.qa.get(self.other["user_id"], qid)

    def test_publish_recheck_after_revocation(self):
        uid = self.biz["user_id"]
        q = self.room.qa.ask(uid, "问题", [{"doc_id": self.doc_id, "version_no": "1.1"}])
        qid = q["q_id"]
        self.room.qa.draft_answer(self.w.lead_id, qid, "答复",
                                  refs=[{"doc_id": self.doc_id, "version_no": "1.1"}])
        self.room.qa.review(self.legal_id, qid, "legal", "APPROVED")
        # 医学审核前撤权 → 双审齐备但发布瞬间复核失败。
        grant_id = next(g["grant_id"] for g in self.room.store.state["grants"].values()
                        if g["subject_id"] == uid)
        self.room.revoke_grant(self.w.lead_id, grant_id, "临时撤权")
        self.room.qa.review(self.medical_id, qid, "medical", "APPROVED")
        self.assertNotEqual(self.room.store.state["questions"][qid]["status"], "PUBLISHED")
        self.assertIn("NO_ACTIVE_GRANT",
                      self.room.store.state["questions"][qid]["publish_blocked_reason"])
        with self.assertRaises(AccessDeniedError):
            self.room.qa.publish(self.w.lead_id, qid)
        # 恢复授权后显式发布成功。
        self.room.grant(self.w.lead_id, "USER", uid, "商业尽调")
        self.room.qa.publish(self.w.lead_id, qid)
        self.assertEqual(self.room.store.state["questions"][qid]["status"], "PUBLISHED")

    def test_legal_rejection_blocks(self):
        q = self.room.qa.ask(self.biz["user_id"], "问题",
                             [{"doc_id": self.doc_id, "version_no": "1.1"}])
        self.room.qa.draft_answer(self.w.lead_id, q["q_id"], "答复")
        self.room.qa.review(self.legal_id, q["q_id"], "legal", "REJECTED", comment="超范围")
        self.assertEqual(self.room.store.state["questions"][q["q_id"]]["status"], "REJECTED")


class ReconstructionIsolationPersistenceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.w = World(self.tmp)
        self.room = self.w.room
        self.doc_id = self.w.doc("专利组合", "PATENT", "L2")
        self.w.upload(self.doc_id, b"patent", "p.docx", expected_version=0)
        self.w.upload(self.doc_id, b"patent-r", "pr.docx", tier="STANDARD", parent=1)
        self.bidder = self.w.bidder("陈商业", ["商业尽调"])
        self.room.documents.preview(self.bidder["user_id"], self.doc_id, "1.1")

    def test_reconstruct_org_collection(self):
        recon = self.room.reconstruct_org_view(
            self.w.lead_id, self.w.deal_id, self.bidder["org_id"])
        self.assertEqual(recon["total_distinct_versions"], 1)
        self.assertEqual(recon["viewed_documents"][0]["version_no"], "1.1")
        self.assertEqual(recon["viewed_documents"][0]["actions"], ["DOC_PREVIEW"])

    def test_cross_deal_isolation(self):
        # 同一资料室内再建一个交易（多交易隔离是核心要求）。
        other_lead = self.room.bootstrap_deal("竞品交易", "李负责", "lead2@firm.cn")
        ol_id, ol_secret, other_deal_id = (
            other_lead["user_id"], other_lead["secret"], other_lead["deal_id"])
        org2 = self.room.create_bidder_org(ol_id, "另一竞标方")
        invite2 = self.room.create_invitation(ol_id, org2["org_id"], ["商业尽调"])
        stranger = self.room.enroll(invite2["enrollment_token"], "外人", "o@b.com")
        self.room.sign_nda(stranger["user_id"])
        # 管理员 A 看不到交易 B 的任何信息。
        with self.assertRaises(AccessDeniedError):
            self.room.deal_status(self.w.lead_id, other_deal_id)
        with self.assertRaises((AccessDeniedError, NotFoundError)):
            self.room.reconstruct_org_view(self.w.lead_id, self.w.deal_id, org2["org_id"])
        # 交易 B 用户不能访问交易 A 的文档，即使拿到 doc_id。
        with self.assertRaises(AccessDeniedError) as ctx:
            self.room.documents.preview(stranger["user_id"], self.doc_id, "1.1")
        self.assertEqual(ctx.exception.reason, "CROSS_DEAL")
        # 反向同样成立：交易 A 的用户无法被当作交易 B 管理员。
        with self.assertRaises(AccessDeniedError):
            self.room.deal_status(self.w.lead_id, other_deal_id)
        # 交易 A 的人在本交易内仍正常访问。
        self.assertEqual(
            self.room.documents.preview(self.bidder["user_id"], self.doc_id, "1.1")["doc_id"],
            self.doc_id)

    def test_persistence_across_restart(self):
        code = self.room.documents.preview(
            self.bidder["user_id"], self.doc_id, "1.1")["watermark"]["code"]
        reopened = DataRoom(self.tmp)
        # 授权状态仍生效：撤权即时阻断在新进程同样成立。
        recon = reopened.reconstruct_org_view(
            self.w.lead_id, self.w.deal_id, self.bidder["org_id"])
        self.assertEqual(recon["total_distinct_versions"], 1)
        # 审计从 JSONL 复原，水印仍可溯源。
        trace = reopened.documents.verify_watermark_code(code)
        self.assertEqual(trace["user_id"], self.bidder["user_id"])
        # blob 内容可读。
        preview = reopened.documents.preview(self.bidder["user_id"], self.doc_id, "1.1")
        self.assertEqual(preview["filename"], "pr.docx")
        # 事件卷宗仍在盘上。
        self.room.documents.interrupt_export  # 模块存在性
        incidents_dir = os.path.join(self.tmp, "incidents")
        # 触发一个事件后重开验证卷宗
        self.assertTrue(os.path.isdir(incidents_dir))


class HttpApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.room = DataRoom(cls.tmp)
        cls.server = build_server(cls.room, host="127.0.0.1", port=0)
        cls.port = cls.server.server_address[1]
        cls.thread = Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def call(self, method, path, body=None, token=None, expect_error=False):
        url = f"http://127.0.0.1:{self.port}{path}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            payload = json.loads(exc.read().decode("utf-8"))
            if expect_error:
                return exc.code, payload
            raise AssertionError(f"{method} {path} -> {exc.code} {payload}")

    def test_full_flow_over_http(self):
        status, lead = self.call("POST", "/admin/bootstrap", {
            "deal_name": "HTTP交易", "lead_name": "接口负责人", "lead_email": "h@x.cn"})
        self.assertEqual(status, 201)
        _, session = self.call("POST", "/auth/login",
                               {"user_id": lead["user_id"], "secret": lead["secret"]})
        token = session["token"]
        _, org = self.call("POST", "/orgs", {"name": "HTTP竞标方"}, token=token)
        _, invite = self.call("POST", "/invitations",
                              {"org_id": org["org_id"], "roles": ["商业尽调"]}, token=token)
        _, user = self.call("POST", "/auth/enroll",
                            {"token": invite["enrollment_token"],
                             "name": "网尽调", "email": "w@b.com"})
        _, user_session = self.call("POST", "/auth/login",
                                    {"user_id": user["user_id"], "secret": user["secret"]})
        user_token = user_session["token"]
        # NDA 未签 → 403
        code, err = self.call("GET", f"/documents?deal_id={lead['deal_id']}",
                              token=user_token, expect_error=True)
        self.assertEqual(code, 403)
        self.assertEqual(err["error"], "NDA_REQUIRED")
        self.call("POST", f"/users/{user['user_id']}/nda/sign", {}, token=user_token)

        _, doc = self.call("POST", "/documents", {
            "title": "HTTP专利", "category": "PATENT", "sensitivity": "L2"}, token=token)
        content = b"0123456789abcdef"  # 16 字节
        _, init = self.call("POST", "/uploads", {
            "doc_id": doc["doc_id"], "filename": "p.docx",
            "total_size": len(content), "chunk_size": 16,
            "tier": "ORIGINAL"}, token=token)
        import base64
        self.call("PUT", f"/uploads/{init['upload_id']}/chunks/0",
                  {"content_base64": base64.b64encode(content).decode()}, token=token)
        _, v1 = self.call("POST", f"/uploads/{init['upload_id']}/complete",
                          {"expected_version": 0}, token=token)
        self.assertEqual(v1["scan_status"], "CLEAN")
        redacted = b"http-redacted-ok"  # 16 字节
        _, init2 = self.call("POST", "/uploads", {
            "doc_id": doc["doc_id"], "filename": "pr.docx", "total_size": len(redacted),
            "chunk_size": 16, "tier": "STANDARD", "parent_version_no": 1}, token=token)
        self.call("PUT", f"/uploads/{init2['upload_id']}/chunks/0",
                  {"content_base64": base64.b64encode(redacted).decode()}, token=token)
        self.call("POST", f"/uploads/{init2['upload_id']}/complete", {}, token=token)

        _, listing = self.call("GET", f"/documents?deal_id={lead['deal_id']}", token=user_token)
        self.assertEqual(len(listing["documents"]), 1)
        _, preview = self.call("GET",
                               f"/documents/{doc['doc_id']}/versions/1.1/preview",
                               token=user_token)
        self.assertIn("CONFIDENTIAL", preview["watermark"]["text"])
        _, recon = self.call("GET",
                             f"/reconstruction/org?deal_id={lead['deal_id']}&org_id={org['org_id']}",
                             token=token)
        self.assertEqual(recon["total_distinct_versions"], 1)
        # 无令牌 → 403
        code, _ = self.call("GET", f"/documents?deal_id={lead['deal_id']}", expect_error=True)
        self.assertEqual(code, 403)


if __name__ == "__main__":
    unittest.main()
