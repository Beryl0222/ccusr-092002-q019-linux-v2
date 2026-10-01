"""受控资料室端到端领域测试（不经网络，直接驱动服务）。"""

import json
import tempfile
import unittest
from pathlib import Path

from dataroom import taxonomy as T
from dataroom.access import extract_watermark
from dataroom.app import DataRoom
from dataroom.errors import Conflict, DomainError, Forbidden


class Case(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        # 阈值调低，便于演练异常批量访问
        self.app = DataRoom(root / "d.db", root / "blobs",
                            bulk_window=300, bulk_threshold=3)
        self.p = self.app.provisioning

    def tearDown(self):
        self.app.close()
        self.tmp.cleanup()

    # ---- 夹具 ----
    def bootstrap(self, *, deal_phase=T.PHASE_DETAILED, nda=True,
                  bidder_role=T.ROLE_MEDICAL_DD, sensitivity=T.SENS_HIGH,
                  patient_level=False, min_phase=T.PHASE_DETAILED):
        deal = self.p.create_deal("交易A", phase=deal_phase, deal_id="DEAL-A")
        org = self.p.create_org(deal, "跨国药企甲", nda_signed=nda, org_id="ORG-A")
        team = self.p.create_team(deal, org, "医学团队", team_id="TEAM-A")
        self.p.create_user("U-BID", "竞标方医生")
        self.p.create_user("U-ADM", "交易管理员")
        self.p.create_user("U-OWN", "交易负责人")
        self.p.create_user("U-LEG", "法务审核员")
        self.p.create_user("U-MED", "医学审核员")
        self.p.grant(deal, "U-ADM", T.ROLE_DEAL_ADMIN)
        self.p.grant(deal, "U-OWN", T.ROLE_DEAL_OWNER)
        self.p.grant(deal, "U-LEG", T.ROLE_LEGAL_REVIEW)
        self.p.grant(deal, "U-MED", T.ROLE_MEDICAL_REVIEW)
        self.p.grant(deal, "U-BID", bidder_role, org_id=org, team_id=team)
        # 文档
        self.app.documents.register_document(
            deal, "DOC-1", "三期临床总结", T.CAT_CLINICAL, "临床机密",
            sensitivity, min_phase, "U-OWN", patient_level=patient_level)
        v = self.app.documents.upload_version(
            deal, "DOC-1", 0, b"clean body v1", "U-OWN")
        return {"deal": deal, "org": org, "team": team, "v1": v}

    def ctx(self, user, deal="DEAL-A"):
        token = self.p.issue_session(deal, user)
        return self.app.context(token), token


class TestAccessControl(Case):
    def test_nda_unsigned_blocks_immediately(self):
        self.bootstrap(nda=False)
        # 未签 NDA：构造上下文即拒绝
        with self.assertRaises(Forbidden) as cm:
            self.app.context(self.p.issue_session("DEAL-A", "U-BID"))
        self.assertEqual(cm.exception.code, "nda_unsigned")
        self.p.sign_nda("DEAL-A", "ORG-A")
        ctx = self.app.context(self.p.issue_session("DEAL-A", "U-BID"))
        self.assertEqual(ctx.org_id, "ORG-A")

    def test_grant_expiry_blocks(self):
        self.bootstrap()
        self.p.grant("DEAL-A", "U-BID", T.ROLE_MEDICAL_DD, org_id="ORG-A",
                     valid_from="2000-01-01T00:00:00Z",
                     valid_until="2000-01-02T00:00:00Z")
        # 存在一条过期授权，但也有长期授权 → 仍可访问；撤掉长期授权后即被拒
        self.p.revoke_grant("DEAL-A", user_id="U-BID",
                            role=T.ROLE_MEDICAL_DD, reason="到期测试")
        # 上面把两条医学尽调授权都撤了（包括过期的那条也一并撤），重新发仅过期授权
        self.p.grant("DEAL-A", "U-BID", T.ROLE_MEDICAL_DD, org_id="ORG-A",
                     valid_from="2000-01-01T00:00:00Z",
                     valid_until="2000-01-02T00:00:00Z")
        with self.assertRaises(Forbidden) as cm:
            self.app.context(self.p.issue_session("DEAL-A", "U-BID"))
        self.assertEqual(cm.exception.code, "no_valid_grant")

    def test_revoke_is_immediate_for_new_views(self):
        b = self.bootstrap()
        ctx, token = self.ctx("U-BID")
        self.app.preview(ctx, b["v1"]["version_id"])
        self.p.revoke_grant("DEAL-A", user_id="U-BID", reason="竞标退出")
        # 撤权后授权即时失效（会话同时被吊销）
        with self.assertRaises(Forbidden) as cm:
            self.app.context(token)
        self.assertIn(cm.exception.code, ("no_valid_grant", "session_revoked"))

    def test_deactivation_is_cross_deal_immediate(self):
        b = self.bootstrap()
        deal2 = self.p.create_deal("交易B", deal_id="DEAL-B")
        org2 = self.p.create_org(deal2, "药企乙", nda_signed=True, org_id="ORG-B")
        self.p.grant(deal2, "U-BID", T.ROLE_TECH_DD, org_id=org2)
        t1 = self.p.issue_session("DEAL-A", "U-BID")
        t2 = self.p.issue_session("DEAL-B", "U-BID")
        self.app.context(t1); self.app.context(t2)
        self.p.deactivate_user("U-BID", "离职")
        for t in (t1, t2):
            with self.assertRaises(Forbidden) as cm:
                self.app.context(t)
            self.assertEqual(cm.exception.code, "user_deactivated")

    def test_deal_termination_blocks(self):
        b = self.bootstrap()
        token = self.p.issue_session("DEAL-A", "U-BID")
        self.app.context(token)
        self.p.terminate_deal("DEAL-A")
        with self.assertRaises(Forbidden) as cm:
            self.app.context(token)
        self.assertEqual(cm.exception.code, "deal_terminated")

    def test_phase_gate_and_role_sensitivity(self):
        # 材料在扩展尽调才开放，交易仍处初始披露 → 不可见
        self.bootstrap(deal_phase=T.PHASE_INITIAL, min_phase=T.PHASE_EXTENDED,
                       sensitivity=T.SENS_CONFIDENTIAL)
        ctx, _ = self.ctx("U-BID")
        v = self.app.documents.latest_version("DOC-1")
        doc = self.app.documents.get_document("DOC-1")
        with self.assertRaises(Forbidden) as cm:
            self.app.policy.can_view_version(ctx, doc, v)
        self.assertEqual(cm.exception.code, "phase_not_open")
        # 推进阶段后可见
        self.p.set_phase("DEAL-A", T.PHASE_EXTENDED)
        ctx, _ = self.ctx("U-BID")
        self.app.policy.can_view_version(ctx, doc, v)
        # 观察方角色碰不到机密级
        self.p.create_user("U-OBS", "观察方")
        self.p.grant("DEAL-A", "U-OBS", T.ROLE_OBSERVER, org_id="ORG-A")
        octx = self.app.context(self.p.issue_session("DEAL-A", "U-OBS"))
        with self.assertRaises(Forbidden) as cm:
            self.app.policy.can_view_version(octx, doc, v)
        self.assertEqual(cm.exception.code, "sensitivity_denied")


class TestDocumentPipeline(Case):
    def test_fingerprint_and_quarantine(self):
        b = self.bootstrap()
        # 并发版本：陈旧期望号失败
        self.app.documents.upload_version("DEAL-A", "DOC-1", 1, b"v2", "U-OWN")
        with self.assertRaises(Conflict) as cm:
            self.app.documents.upload_version("DEAL-A", "DOC-1", 1, b"stale", "U-OWN")
        self.assertEqual(cm.exception.code, "concurrent_version")
        # 病毒扫描失败：持久化隔离，不投放
        with self.assertRaises(DomainError) as em:
            self.app.documents.upload_version(
                "DEAL-A", "DOC-1", 2, b"X5O!P%@AP[4\\PZX infected", "U-OWN")
        self.assertEqual(em.exception.code, "virus_scan_failed")
        doc = self.app.documents.get_document("DOC-1")
        self.assertEqual(doc["status"], T.DOC_QUARANTINED)
        ctx, _ = self.ctx("U-BID")
        v3 = self.app.documents.get_version(self.app.store.query_one(
            "SELECT version_id FROM document_versions WHERE doc_id='DOC-1' "
            "AND version_no=3")["version_id"])
        self.assertEqual(v3["scan_status"], "infected")
        with self.assertRaises(Forbidden) as cm:
            self.app.access.preview(ctx, v3["version_id"])
        self.assertEqual(cm.exception.code, "doc_quarantined")
        # 隔离样本落盘留证
        self.assertTrue((self.app.store.blob_dir / "quarantine").exists())

    def test_patient_level_lineage(self):
        b = self.bootstrap(patient_level=True, sensitivity=T.SENS_PATIENT,
                           bidder_role=T.ROLE_MEDICAL_DD)
        # 登记脱敏子文档（谱系指回原件）
        self.app.documents.register_document(
            "DEAL-A", "DOC-1-R", "三期临床总结(脱敏)", T.CAT_CLINICAL, "脱敏件",
            T.SENS_HIGH, T.PHASE_DETAILED, "U-OWN",
            redaction_parent_doc_id="DOC-1")
        rv = self.app.documents.upload_version(
            "DEAL-A", "DOC-1-R", 0, b"de-identified body", "U-OWN",
            is_redacted=True, parent_version_id=b["v1"]["version_id"])

        bidder, _ = self.ctx("U-BID")
        # 竞标方看不到患者级原件
        with self.assertRaises(Forbidden) as cm:
            self.app.access.preview(bidder, b["v1"]["version_id"])
        self.assertEqual(cm.exception.code, "patient_original_blocked")
        # 可以看脱敏件
        res = self.app.preview(bidder, rv["version_id"])
        self.assertTrue(res["is_redacted"])
        # 不能借谱系调原件
        with self.assertRaises(Forbidden) as cm:
            self.app.access.view_original(bidder, "DOC-1-R")
        self.assertEqual(cm.exception.code, "original_admin_only")
        # 列表里原件文档对竞标方不可见，脱敏件可见
        ids = {d["doc_id"] for d, _ in self.app.documents.list_visible(bidder)}
        self.assertNotIn("DOC-1", ids)
        self.assertIn("DOC-1-R", ids)
        # 负责人可调取原件，但同样打水印上链
        owner = self.app.context(self.p.issue_session("DEAL-A", "U-OWN"))
        ores = self.app.access.view_original(owner, "DOC-1-R")
        self.assertIn(b"clean body v1", ores["content"])
        self.assertTrue(ores["watermark_id"].startswith("WM-"))


class TestWatermarkAndDownload(Case):
    def test_each_preview_gets_unique_watermark(self):
        b = self.bootstrap()
        ctx, _ = self.ctx("U-BID")
        r1 = self.app.preview(ctx, b["v1"]["version_id"])
        r2 = self.app.preview(ctx, b["v1"]["version_id"])
        self.assertNotEqual(r1["watermark_id"], r2["watermark_id"])
        self.assertEqual(extract_watermark(r1["content"]), r1["watermark_id"])
        self.assertIn(ctx.user_id.encode(), r1["content"])

    def test_resumable_download_interrupted_then_revoke(self):
        b = self.bootstrap()
        ctx, token = self.ctx("U-BID")
        exp = self.app.start_export(ctx, b["v1"]["version_id"])
        did = exp["download_id"]
        # 小块拉取，模拟中断
        part1 = self.app.read_chunk(ctx, did, max_chunk=40)
        self.assertEqual(part1["start"], 0)
        self.app.access.mark_interrupted(ctx, did)
        d = self.app.access.get_session(ctx, did)
        self.assertEqual(d["status"], T.DL_INTERRUPTED)
        # 续传
        part2 = self.app.access.resume(ctx, did, max_chunk=1 << 20, start=part1["end"])
        body = part1["content"] + part2["content"]
        self.assertIn(b"X-DATAROOM-WATERMARK", body)
        artifact_digest = self.app.store.query_one(
            "SELECT artifact_sha256 FROM download_sessions WHERE download_id=?",
            (did,))["artifact_sha256"]
        self.assertEqual(body, self.app.store.get_blob(artifact_digest))
        # 新导出一个会话，下载途中撤权：下一分块立即被拒且会话持久化为 revoked
        exp2 = self.app.start_export(ctx, b["v1"]["version_id"])
        self.app.read_chunk(ctx, exp2["download_id"], max_chunk=20)
        self.p.revoke_grant("DEAL-A", user_id="U-BID", reason="尽调中止")
        # 旧 ctx 是撤权前的快照，但分块投放前会以该用户实时身份重算授权
        with self.assertRaises(Forbidden) as cm:
            self.app.read_chunk(ctx, exp2["download_id"])
        self.assertEqual(cm.exception.code, "no_valid_grant")
        d = self.app.access.get_session(ctx, exp2["download_id"])
        self.assertEqual(d["status"], T.DL_REVOKED)
        # 旧会话令牌的授权也已即时失效
        with self.assertRaises(Forbidden) as cm:
            self.app.context(token)
        self.assertIn(cm.exception.code, ("no_valid_grant", "session_revoked"))


class TestQA(Case):
    def _qa_flow_setup(self):
        b = self.bootstrap()
        bidder = self.app.context(self.p.issue_session("DEAL-A", "U-BID"))
        qid = self.app.qa.ask(bidder, "请引用材料说明主要终点",
                              citations=[["DOC-1", b["v1"]["version_id"]]])
        return b, bidder, qid

    def test_dual_approval_and_publish(self):
        b, bidder, qid = self._qa_flow_setup()
        internal = self.app.context(self.p.issue_session("DEAL-A", "U-OWN"))
        self.app.qa.answer(internal, qid, "主要终点为 PFS",
                           [["DOC-1", b["v1"]["version_id"]]])
        # 双审缺一时不能发布
        leg = self.app.context(self.p.issue_session("DEAL-A", "U-LEG"))
        med = self.app.context(self.p.issue_session("DEAL-A", "U-MED"))
        self.app.qa.approve_legal(leg, qid)
        with self.assertRaises(Forbidden) as cm:
            self.app.qa.publish(internal, qid)
        self.assertEqual(cm.exception.code, "dual_approval_required")
        self.app.qa.approve_medical(med, qid)
        self.app.qa.publish(internal, qid)
        qa = self.app.qa.read(bidder, qid)
        self.assertEqual(qa["status"], T.QA_PUBLISHED)
        # 竞标方列表只含本组织已发布
        items = self.app.qa.list_for(bidder)
        self.assertEqual(len(items), 1)

    def test_same_person_cannot_be_both_approvers(self):
        b, _, qid = self._qa_flow_setup()
        # 给法务审核员同时叠加医学审核角色
        self.p.grant("DEAL-A", "U-LEG", T.ROLE_MEDICAL_REVIEW)
        leg = self.app.context(self.p.issue_session("DEAL-A", "U-LEG"))
        internal = self.app.context(self.p.issue_session("DEAL-A", "U-OWN"))
        self.app.qa.answer(internal, qid, "答复", [["DOC-1", b["v1"]["version_id"]]])
        self.app.qa.approve_legal(leg, qid)
        with self.assertRaises(Forbidden) as cm:
            self.app.qa.approve_medical(leg, qid)
        self.assertEqual(cm.exception.code, "dual_approval_distinct_persons")

    def test_citation_revalidated_at_publish_after_revoke(self):
        b, bidder, qid = self._qa_flow_setup()
        internal = self.app.context(self.p.issue_session("DEAL-A", "U-OWN"))
        self.app.qa.answer(internal, qid, "答复", [["DOC-1", b["v1"]["version_id"]]])
        leg = self.app.context(self.p.issue_session("DEAL-A", "U-LEG"))
        med = self.app.context(self.p.issue_session("DEAL-A", "U-MED"))
        self.app.qa.approve_legal(leg, qid)
        self.app.qa.approve_medical(med, qid)
        # 发布前提问方离职：引用对其不再可见 → 拒绝发布
        self.p.deactivate_user("U-BID", "离职")
        with self.assertRaises(Forbidden) as cm:
            self.app.qa.publish(internal, qid)
        self.assertEqual(cm.exception.code, "user_deactivated")

    def test_bidder_cannot_see_other_org_or_unpublished(self):
        b, _, qid = self._qa_flow_setup()
        # 另一家竞标方
        org2 = self.p.create_org("DEAL-A", "跨国药企乙", nda_signed=True, org_id="ORG-B")
        self.p.create_user("U-B2", "乙公司医生")
        self.p.grant("DEAL-A", "U-B2", T.ROLE_MEDICAL_DD, org_id=org2)
        b2 = self.app.context(self.p.issue_session("DEAL-A", "U-B2"))
        with self.assertRaises(Forbidden):
            self.app.qa.read(b2, qid)
        self.assertEqual(self.app.qa.list_for(b2), [])

    def test_answer_cannot_cite_invisible_doc(self):
        b, _, qid = self._qa_flow_setup()
        internal = self.app.context(self.p.issue_session("DEAL-A", "U-OWN"))
        # 高敏材料，观察方不可见
        self.p.create_user("U-OBS", "观察方用户")
        org = self.p.create_org("DEAL-A", "药企丙", nda_signed=True, org_id="ORG-C")
        self.p.grant("DEAL-A", "U-OBS", T.ROLE_OBSERVER, org_id=org)
        qo = self.app.context(self.p.issue_session("DEAL-A", "U-OBS"))
        with self.assertRaises(Forbidden):
            self.app.qa.ask(qo, "问题", citations=[["DOC-1", b["v1"]["version_id"]]])


class TestSecurity(Case):
    def test_bulk_access_auto_remediation(self):
        b = self.bootstrap()
        # 再准备 2 份文档，使 3 份阈值可触发
        for i in (2, 3):
            self.app.documents.register_document(
                "DEAL-A", f"DOC-{i}", f"文件{i}", T.CAT_PATENT, "专利",
                T.SENS_HIGH, T.PHASE_DETAILED, "U-OWN")
            self.app.documents.upload_version(
                "DEAL-A", f"DOC-{i}", 0, f"body{i}".encode(), "U-OWN")
        ctx = self.app.context(self.p.issue_session("DEAL-A", "U-BID"))
        for did in ("DOC-1", "DOC-2", "DOC-3"):
            v = self.app.documents.latest_version(did)
            inc = None
            try:
                self.app.preview(ctx, v["version_id"])
            except Forbidden as e:
                self.assertEqual(e.code, "user_suspended_in_deal")
        incs = self.app.security.list_incidents("DEAL-A")
        kinds = [i["kind"] for i in incs]
        self.assertIn(T.EVT_BULK_ANOMALY, kinds)
        # 立即停权：下一次请求被拒
        with self.assertRaises(Forbidden) as cm:
            self.app.context(self.p.issue_session("DEAL-A", "U-BID"))
        self.assertEqual(cm.exception.code, "user_suspended_in_deal")

    def test_leak_traced_by_watermark_and_remediated(self):
        b = self.bootstrap()
        ctx = self.app.context(self.p.issue_session("DEAL-A", "U-BID"))
        exp = self.app.start_export(ctx, b["v1"]["version_id"])
        self.app.read_chunk(ctx, exp["download_id"])
        # 从外泄物中提取水印（这里直接用水印号），立案
        admin = self.app.context(self.p.issue_session("DEAL-A", "U-ADM"))
        iid, trace = self.app.security.report_leak(
            "DEAL-A", "U-ADM", exp["watermark_id"], "外发到公开论坛")
        self.assertEqual(trace["user_id"], "U-BID")
        self.assertEqual(trace["doc_id"], "DOC-1")
        self.assertEqual(trace["version"]["version_no"], 1)
        # 组织冻结 + 人员停权立即生效
        with self.assertRaises(Forbidden) as cm:
            self.app.context(self.p.issue_session("DEAL-A", "U-BID"))
        self.assertEqual(cm.exception.code, "org_frozen")
        inc = self.app.store.query_one(
            "SELECT * FROM security_incidents WHERE incident_id=?", (iid,))
        self.assertEqual(inc["status"], T.INC_REMEDIATED)
        self.assertIn("freeze_org", json.loads(inc["remediation"])["actions"])


class TestForensicsAndChain(Case):
    def test_reconstruct_viewed_set_and_cross_deal_isolation(self):
        b = self.bootstrap()
        ctx = self.app.context(self.p.issue_session("DEAL-A", "U-BID"))
        self.app.preview(ctx, b["v1"]["version_id"])
        exp = self.app.start_export(ctx, b["v1"]["version_id"])
        self.app.read_chunk(ctx, exp["download_id"])

        # 第二个交易，同样的管理员角色，看不到交易A
        d2 = self.p.create_deal("交易B", deal_id="DEAL-B")
        self.p.create_user("U-A2", "B交易管理员")
        self.p.grant(d2, "U-A2", T.ROLE_DEAL_ADMIN)
        admin_b = self.app.context(self.p.issue_session(d2, "U-A2"))
        rep_b = self.app.forensics.reconstruct_viewed_set(admin_b, org_id="ORG-A")
        self.assertEqual(rep_b["deal_id"], "DEAL-B")
        self.assertEqual(rep_b["materials"], [])
        # 水印溯源跨交易拒绝
        with self.assertRaises(DomainError):
            self.app.security.report_leak(d2, "U-A2", exp["watermark_id"], "x")

        # A 交易管理员可准确复原
        admin_a = self.app.context(self.p.issue_session("DEAL-A", "U-ADM"))
        rep = self.app.forensics.reconstruct_viewed_set(admin_a, org_id="ORG-A")
        self.assertEqual(rep["distinct_material_versions"], 1)
        m = rep["materials"][0]
        self.assertEqual(m["doc_id"], "DOC-1")
        self.assertEqual(m["version_no"], 1)
        self.assertEqual(m["version_sha256"], b["v1"]["sha256"])
        # 同一份材料两次访问（预览+导出）两个水印
        self.assertEqual(len(m["watermark_ids"]), 2)
        self.assertEqual(rep["access_count"], 2)
        # 非管理员不能取证
        with self.assertRaises(Forbidden):
            self.app.forensics.reconstruct_viewed_set(ctx, org_id="ORG-A")

    def test_chain_detects_tampering(self):
        b = self.bootstrap()
        ctx = self.app.context(self.p.issue_session("DEAL-A", "U-BID"))
        self.app.preview(ctx, b["v1"]["version_id"])
        admin = self.app.context(self.p.issue_session("DEAL-A", "U-ADM"))
        self.assertTrue(self.app.forensics.audit_verification(admin)["ok"])
        # 直接改写库内审计行
        self.app.store.execute(
            "UPDATE access_event SET actor_user_id='HACKER' WHERE seq=2")
        self.app.store.commit()
        res = self.app.forensics.audit_verification(admin)
        self.assertFalse(res["ok"])
        self.assertEqual(res["broken_at_seq"], 2)


class TestPersistenceAcrossRestart(Case):
    def test_state_survives_restart(self):
        b = self.bootstrap()
        ctx, _ = self.ctx("U-BID")
        exp = self.app.start_export(ctx, b["v1"]["version_id"])
        part = self.app.read_chunk(ctx, exp["download_id"], max_chunk=30)
        self.app.access.mark_interrupted(ctx, exp["download_id"])
        delivered = part["end"]
        # 病毒隔离 + 撤权都在重启前落盘
        self.p.revoke_grant("DEAL-A", user_id="U-BID", reason="竞标退出")
        db, blobs = self.app.store.db_path, self.app.store.blob_dir
        self.app.close()

        app2 = DataRoom(db, blobs, bulk_window=300, bulk_threshold=3)
        # 撤权在重启后仍生效
        with self.assertRaises(Forbidden):
            app2.context(app2.provisioning.issue_session("DEAL-A", "U-BID"))
        # 审计链跨重启可校验
        admin = app2.context(app2.provisioning.issue_session("DEAL-A", "U-ADM"))
        self.assertTrue(app2.forensics.audit_verification(admin)["ok"])
        # 中断的下载会话持久化、可按字节位置续传
        owner = app2.context(app2.provisioning.issue_session("DEAL-A", "U-OWN"))
        d = app2.access.get_session(owner, exp["download_id"])
        self.assertEqual(d["status"], T.DL_INTERRUPTED)
        self.assertEqual(d["bytes_delivered"], delivered)
        rest = app2.access.resume(owner, exp["download_id"], start=delivered)
        self.assertGreater(len(rest["content"]), 0)


if __name__ == "__main__":
    unittest.main()
