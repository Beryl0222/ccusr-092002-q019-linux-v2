"""受控资料室 JSON HTTP API。

鉴权：除 /health、/auth/enroll、/auth/login、/admin/bootstrap 外，
所有请求需 ``Authorization: Bearer <会话令牌>``。
被拒绝的访问也写入审计（result=DENIED），证明“谁在何时被阻断”。
"""

import base64
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from .errors import DataRoomError
from .security import utcnow_iso


def _json_bytes(payload, status=200):
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    return status, body


class ApiHandler(BaseHTTPRequestHandler):
    server_version = "BiopharmaDataRoom/1.0"

    # ----------------------------------------------------------- 协议辅助
    def _send(self, status, body: bytes):
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _ok(self, payload, status=200):
        self._send(*_json_bytes(payload, status))

    def _read_json(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        if not raw:
            return {}
        return json.loads(raw.decode("utf-8"))

    def _token(self):
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth.split(" ", 1)[1].strip()
        return None

    def _current_user(self):
        token = self._token()
        if not token:
            return None
        return self.server.room.authenticate(token)

    def log_message(self, *_args):
        return

    # ----------------------------------------------------------- 路由
    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_PUT(self):
        self._dispatch("PUT")

    def _dispatch(self, method):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        room = self.server.room
        try:
            if method == "GET" and path == "/health":
                self._ok({"status": "ok", "service": "biopharma-data-room",
                          "name": "跨境药研尽调资料室", "time": utcnow_iso()})
                return
            if method == "POST" and path in ("/admin/bootstrap", "/auth/enroll", "/auth/login"):
                pass  # 公开端点，无需会话令牌
            elif not self._token():
                self._send(403, json.dumps(
                    {"error": "ACCESS_DENIED", "message": "缺少 Bearer 会话令牌",
                     "context": {"reason": "NO_SESSION"}},
                    ensure_ascii=False).encode("utf-8"))
                return
            self._route(method, path, query, room)
        except DataRoomError as exc:
            user = None
            try:
                user = self._current_user()
            except DataRoomError:
                pass
            if user is not None:
                room.log_denied(user["user_id"], f"HTTP_{method}_{path}",
                                getattr(exc, "reason", exc.code))
            self._send(exc.http_status,
                       json.dumps(exc.to_dict(), ensure_ascii=False).encode("utf-8"))
        except (ValueError, KeyError) as exc:
            self._send(400, json.dumps(
                {"error": "BAD_REQUEST", "message": str(exc)}, ensure_ascii=False).encode("utf-8"))
        except json.JSONDecodeError:
            self._send(400, json.dumps(
                {"error": "BAD_JSON", "message": "请求体不是合法 JSON"},
                ensure_ascii=False).encode("utf-8"))

    # ----------------------------------------------------------- 路由表
    def _route(self, method, path, query, room):
        p = [seg for seg in path.split("/") if seg]
        body = self._read_json() if method in ("POST", "PUT") else {}
        uid = lambda: self._current_user()["user_id"]

        # ---- 引导 / 认证
        if method == "POST" and path == "/admin/bootstrap":
            return self._ok(room.bootstrap_deal(
                body["deal_name"], body["lead_name"], body["lead_email"]), 201)
        if method == "POST" and path == "/auth/enroll":
            return self._ok(room.enroll(body["token"], body["name"], body["email"]), 201)
        if method == "POST" and path == "/auth/login":
            session = room.login(body["user_id"], body["secret"],
                                 ttl_seconds=int(body.get("ttl_seconds", 28800)))
            return self._ok({"token": session["token"], "expires_ts": session["expires_ts"],
                             "user_id": session["user_id"], "deal_id": session["deal_id"]})
        if method == "POST" and path == "/auth/logout":
            token = self._token()
            return self._ok(room.logout(token))

        # ---- 交易 / 阶段
        if method == "POST" and path.startswith("/deals/") and len(p) == 3 and p[2] == "terminate":
            deal_id = p[1]
            return self._ok(room.terminate_deal(uid(), deal_id, body.get("reason", "")))
        if method == "GET" and len(p) == 3 and p[0] == "deals" and p[2] == "status":
            return self._ok(room.deal_status(uid(), p[1]))
        if method == "POST" and len(p) == 3 and p[0] == "deals" and p[2] == "phase":
            return self._ok(room.documents.advance_phase(uid(), p[1], int(body["phase"])))

        # ---- 组织 / 团队 / 邀请 / NDA / 离职
        if method == "POST" and path == "/orgs":
            return self._ok(room.create_bidder_org(uid(), body["name"]), 201)
        if method == "POST" and len(p) == 3 and p[0] == "orgs" and p[2] == "teams":
            return self._ok(room.create_team(uid(), p[1], body["name"]), 201)
        if method == "POST" and path == "/invitations":
            return self._ok(room.create_invitation(
                uid(), body["org_id"], body["roles"], teams=body.get("teams"),
                valid_from=body.get("valid_from"), valid_until=body.get("valid_until"),
                categories=body.get("categories")), 201)
        if method == "POST" and len(p) == 4 and p[0] == "users" and p[2] == "nda" and p[3] == "sign":
            return self._ok(room.sign_nda(p[1], body.get("version")))
        if method == "POST" and len(p) == 4 and p[0] == "users" and p[2] == "nda" and p[3] == "withdraw":
            return self._ok(room.withdraw_nda(uid(), p[1], body.get("reason", "")))
        if method == "POST" and len(p) == 3 and p[0] == "users" and p[2] == "offboard":
            return self._ok(room.offboard_user(uid(), p[1], body.get("reason", "")))

        # ---- 授权
        if method == "POST" and path == "/grants":
            return self._ok(room.grant(
                uid(), body["scope"], body["subject_id"], body["role"],
                valid_from=body.get("valid_from"), valid_until=body.get("valid_until"),
                categories=body.get("categories")), 201)
        if method == "POST" and len(p) == 3 and p[0] == "grants" and p[2] == "revoke":
            return self._ok(room.revoke_grant(uid(), p[1], body.get("reason", "")))

        # ---- 文档与谱系
        if method == "POST" and path == "/documents":
            return self._ok(room.documents.create_document(
                uid(), body["title"], body["category"], body["sensitivity"]), 201)
        if method == "GET" and path == "/documents":
            return self._ok({"documents": room.documents.list_documents(uid(), query["deal_id"])})
        if method == "GET" and len(p) == 3 and p[0] == "documents" and p[2] == "lineage":
            return self._ok(room.documents.lineage(uid(), p[1]))
        if method == "POST" and len(p) == 3 and p[0] == "documents" and p[2] == "withdraw":
            return self._ok(room.documents.withdraw_document(uid(), p[1], body.get("reason", "")))

        # ---- 分块上传
        if method == "POST" and path == "/uploads":
            return self._ok(room.documents.init_upload(
                uid(), body["doc_id"], body["filename"], int(body["total_size"]),
                int(body["chunk_size"]), tier=body.get("tier", "ORIGINAL"),
                expected_sha256=body.get("expected_sha256"),
                parent_version_no=body.get("parent_version_no")), 201)
        if method in ("PUT", "POST") and len(p) == 4 and p[0] == "uploads" and p[2] == "chunks":
            content = base64.b64decode(body["content_base64"])
            return self._ok(room.documents.put_chunk(p[1], int(p[3]), content))
        if method == "GET" and len(p) == 2 and p[0] == "uploads":
            return self._ok(room.documents.upload_status(p[1]))
        if method == "POST" and len(p) == 3 and p[0] == "uploads" and p[2] == "abort":
            return self._ok(room.documents.abort_upload(p[1], body.get("reason", "USER_ABORT")))
        if method == "POST" and len(p) == 3 and p[0] == "uploads" and p[2] == "complete":
            expected = body.get("expected_version")
            return self._ok(room.documents.complete_upload(
                p[1], expected_version=int(expected) if expected is not None else None))

        # ---- 预览 / 导出
        if method == "GET" and len(p) == 5 and p[0] == "documents" and p[2] == "versions" \
                and p[4] == "preview":
            doc_id, version_no = p[1], p[3]
            version_no = int(version_no) if version_no.isdigit() else version_no
            return self._ok(room.documents.preview(uid(), doc_id, version_no))
        if method == "POST" and path == "/exports":
            version_no = body["version_no"]
            return self._ok(room.documents.request_export(
                uid(), body["doc_id"],
                int(version_no) if str(version_no).isdigit() else version_no), 201)
        if method == "POST" and len(p) == 3 and p[0] == "exports" and p[2] == "approve":
            return self._ok(room.documents.approve_export(
                uid(), p[1], bool(body.get("approve", True))))
        if method == "GET" and len(p) == 3 and p[0] == "exports" and p[2] == "fetch":
            return self._ok(room.documents.fetch_export(
                uid(), p[1], int(query.get("max_bytes", "1048576"))))
        if method == "POST" and len(p) == 3 and p[0] == "exports" and p[2] == "interrupt":
            offset = body.get("byte_offset")
            return self._ok(room.documents.interrupt_export(
                p[1], byte_offset=int(offset) if offset is not None else None,
                by=body.get("by", "USER")))
        if method == "GET" and len(p) == 2 and p[0] == "exports":
            return self._ok(room.documents.export_status(uid(), p[1]))

        # ---- 问答
        if method == "POST" and path == "/questions":
            return self._ok(room.qa.ask(uid(), body["text"], body["refs"]), 201)
        if method == "GET" and path == "/questions":
            return self._ok({"questions": room.qa.list_for_user(uid())})
        if method == "GET" and len(p) == 2 and p[0] == "questions":
            return self._ok(room.qa.get(uid(), p[1]))
        if method == "POST" and len(p) == 3 and p[0] == "questions" and p[2] == "answer":
            return self._ok(room.qa.draft_answer(uid(), p[1], body["answer"],
                                                 refs=body.get("refs")))
        if method == "POST" and len(p) == 4 and p[0] == "questions" and p[2] == "reviews":
            return self._ok(room.qa.review(uid(), p[1], p[3], body["verdict"],
                                           comment=body.get("comment")))
        if method == "POST" and len(p) == 3 and p[0] == "questions" and p[2] == "publish":
            return self._ok(room.qa.publish(uid(), p[1]))

        # ---- 事件与溯源
        if method == "POST" and path == "/incidents/leak":
            return self._ok(room.report_leak(uid(), body["watermark"], body["summary"],
                                             scope=body.get("scope", "USER")), 201)
        if method == "GET" and path == "/incidents":
            return self._ok({"incidents": room.list_incidents(uid(), query["deal_id"])})
        if method == "GET" and len(p) == 2 and p[0] == "incidents":
            return self._ok(room.get_incident(uid(), p[1]))
        if method == "POST" and len(p) == 3 and p[0] == "incidents" and p[2] == "actions":
            return self._ok(room.incident_action(uid(), p[1], body["action"],
                                                 note=body.get("note")))
        if method == "POST" and len(p) == 3 and p[0] == "incidents" and p[2] == "resolve":
            return self._ok(room.resolve_incident(uid(), p[1], note=body.get("note")))
        if method == "GET" and path == "/watermark/verify":
            return self._ok(room.documents.verify_watermark_code(query["code"]))

        # ---- 审计复原
        if method == "GET" and path == "/audit":
            return self._ok({"events": room.audit_trail(
                uid(), query["deal_id"], limit=int(query.get("limit", "200")))})
        if method == "GET" and path == "/reconstruction/org":
            return self._ok(room.reconstruct_org_view(
                uid(), query["deal_id"], query["org_id"]))
        if method == "GET" and path == "/reconstruction/user":
            return self._ok(room.reconstruct_user_view(uid(), query["user_id"]))

        self._send(404, json.dumps({"error": "NOT_FOUND", "message": path},
                                   ensure_ascii=False).encode("utf-8"))


def build_server(room, host="0.0.0.0", port=8000):
    server = ThreadingHTTPServer((host, port), ApiHandler)
    server.room = room
    return server
