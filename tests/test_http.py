"""HTTP 边界端到端测试：起真实本地端口，验证鉴权、水印头与 Range 续传。"""

import http.client
import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

from dataroom import taxonomy as T
from dataroom.app import DataRoom
import service


class HttpCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.app = DataRoom(root / "d.db", root / "blobs",
                            bulk_window=300, bulk_threshold=8)
        p = self.app.provisioning
        self.deal = p.create_deal("交易A", phase=T.PHASE_DETAILED, deal_id="DEAL-A")
        self.org = p.create_org(self.deal, "药企甲", nda_signed=True, org_id="ORG-A")
        p.create_user("U-BID", "竞标医生")
        p.create_user("U-ADM", "管理员")
        p.grant(self.deal, "U-BID", T.ROLE_MEDICAL_DD, org_id=self.org)
        p.grant(self.deal, "U-ADM", T.ROLE_DEAL_ADMIN)
        self.app.documents.register_document(
            self.deal, "DOC-1", "临床总结", T.CAT_CLINICAL, "机密",
            T.SENS_HIGH, T.PHASE_DETAILED, "U-ADM")
        v = self.app.documents.upload_version(
            self.deal, "DOC-1", 0, b"payload-" * 100, "U-ADM")
        self.version_id = v["version_id"]

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), service.Handler)
        service.Handler.app = self.app
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.bid_token = p.issue_session(self.deal, "U-BID")
        self.adm_token = p.issue_session(self.deal, "U-ADM")

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.app.close()
        self.tmp.cleanup()

    def req(self, method, path, body=None, token=None, headers=None, raw=False):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        h = {"Content-Type": "application/json"}
        if token:
            h["Authorization"] = f"Bearer {token}"
        if headers:
            h.update(headers)
        if body is not None and not isinstance(body, (bytes, bytearray)):
            body = json.dumps(body).encode("utf-8")
        conn.request(method, path, body=body, headers=h)
        r = conn.getresponse()
        data = r.read()
        ctype = r.getheader("Content-Type", "")
        parsed = data if raw else (json.loads(data.decode("utf-8")) if data else None)
        return r.status, dict(r.getheaders()), parsed

    def test_health(self):
        status, _, body = self.req("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(body["service"], service.SERVICE_ID)

    def test_auth_required_and_cross_deal(self):
        status, _, _ = self.req("GET", f"/api/deals/{self.deal}/documents")
        self.assertEqual(status, 401)
        # 令牌属于 DEAL-A，访问别的交易路径直接 403
        status, _, body = self.req(
            "GET", "/api/deals/DEAL-X/documents", token=self.bid_token)
        self.assertEqual(status, 403)
        self.assertEqual(body["error"], "cross_deal_denied")

    def test_preview_unique_watermark_header(self):
        s1, h1, b1 = self.req(
            "POST", f"/api/deals/DEAL-A/versions/{self.version_id}/preview",
            body={}, token=self.bid_token)
        s2, h2, b2 = self.req(
            "POST", f"/api/deals/DEAL-A/versions/{self.version_id}/preview",
            body={}, token=self.bid_token)
        self.assertEqual(s1, 200)
        self.assertTrue(h1["X-Watermark-Id"].startswith("WM-"))
        self.assertNotEqual(h1["X-Watermark-Id"], h2["X-Watermark-Id"])

    def test_range_resume_then_revoke_midstream(self):
        _, _, exp = self.req(
            "POST", f"/api/deals/DEAL-A/versions/{self.version_id}/export",
            body={}, token=self.bid_token)
        did, total = exp["download_id"], exp["total_size"]
        # 第一分块
        s, h, chunk1 = self.req(
            "GET", f"/api/deals/DEAL-A/downloads/{did}", token=self.bid_token,
            headers={"Range": "bytes=0-255"}, raw=True)
        self.assertEqual(s, 206)
        self.assertEqual(len(chunk1), 256)
        self.assertTrue(h["Content-Range"].startswith("bytes 0-255/"))
        # 撤权（管理员操作）
        s, _, _ = self.req(
            "DELETE", "/api/deals/DEAL-A/grants",
            body={"user_id": "U-BID", "reason": "退出"}, token=self.adm_token)
        self.assertEqual(s, 200)
        # 正在进行的下载下一分块立即 403，且服务端会话已持久化为 revoked
        s, h, body = self.req(
            "GET", f"/api/deals/DEAL-A/downloads/{did}", token=self.bid_token,
            headers={"Range": "bytes=256-511"}, raw=False)
        self.assertEqual(s, 403)
        self.assertIn(body["error"], ("no_valid_grant", "session_revoked"))
        row = self.app.store.query_one(
            "SELECT status FROM download_sessions WHERE download_id=?", (did,))
        self.assertEqual(row["status"], T.DL_REVOKED)

    def test_forensics_reconstructs_over_http(self):
        self.req("POST", f"/api/deals/DEAL-A/versions/{self.version_id}/preview",
                 body={}, token=self.bid_token)
        s, _, body = self.req(
            "GET", "/api/deals/DEAL-A/forensics/viewed?org_id=ORG-A",
            token=self.adm_token)
        self.assertEqual(s, 200)
        self.assertEqual(body["distinct_material_versions"], 1)
        self.assertEqual(body["materials"][0]["doc_id"], "DOC-1")
        self.assertEqual(body["materials"][0]["watermark_ids"][0][:3], "WM-")
        # 竞标方无权取证
        s, _, _ = self.req(
            "GET", "/api/deals/DEAL-A/forensics/viewed?org_id=ORG-A",
            token=self.bid_token)
        self.assertEqual(s, 403)
        # 审计链可校验
        s, _, body = self.req("GET", "/api/deals/DEAL-A/audit/verify",
                              token=self.adm_token)
        self.assertTrue(body["ok"])


if __name__ == "__main__":
    unittest.main()
