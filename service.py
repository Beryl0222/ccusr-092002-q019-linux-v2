"""跨境药研尽调资料室 HTTP 边界。

保留基础契约：GET /health 与 `python3 service.py --check`。
其余 /api/** 为受控资料室接口；除平台引导（建交易/组织/用户/换会话）
外，所有交易内操作都要 Authorization: Bearer <会话令牌>，令牌绑定
单一交易，策略层逐请求实时判定。
"""

from __future__ import annotations

import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from dataroom import taxonomy as T
from dataroom.app import DataRoom
from dataroom.errors import DomainError

SERVICE_ID = "biopharma-data-room"
SERVICE_NAME = "跨境药研尽调资料室"


def health_payload():
    """返回稳定的服务身份信息。"""
    return {"status": "ok", "service": SERVICE_ID, "name": SERVICE_NAME}


def _row(r):
    return dict(r) if r is not None else None


class Handler(BaseHTTPRequestHandler):
    app: DataRoom = None  # 由 main 注入

    # ---- 工具 ----
    def _send(self, status, payload, headers=None, raw=False):
        if raw:
            body = payload
        else:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type",
                         "application/octet-stream" if raw else "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json_body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        raw = self.rfile.read(n)
        ctype = self.headers.get("Content-Type", "")
        if "application/json" in ctype or raw[:1] in (b"{", b"["):
            return json.loads(raw.decode("utf-8"))
        return {"__raw__": raw}

    def _token(self):
        h = self.headers.get("Authorization", "")
        return h[7:].strip() if h.startswith("Bearer ") else None

    def _ctx(self, deal_id):
        ctx = self.app.context(self._token())
        if ctx.deal_id != deal_id:
            from dataroom.errors import Forbidden
            raise Forbidden("cross_deal_denied", "令牌不属于该交易", 403)
        return ctx

    def _require_internal(self, ctx, admin=False):
        from dataroom.errors import Forbidden
        if not ctx.internal:
            raise Forbidden("internal_only", "仅限内部人员", 403)
        if admin and not (ctx.is_deal_admin or ctx.is_deal_owner):
            raise Forbidden("deal_admin_only", "仅限交易管理员/负责人", 403)

    def _admin_ctx(self, deal_id):
        """交易管理员上下文；也接受平台引导令牌（仅用于开通类操作）。"""
        from dataroom.policy import Context
        tok = self._token()
        boot = os.environ.get("DATAROOM_BOOTSTRAP_TOKEN")
        if boot and tok == boot:
            return Context(
                token="__bootstrap__", deal_id=deal_id,
                user_id="__platform_bootstrap__", user_name="平台引导",
                org_id=None, roles={T.ROLE_DEAL_ADMIN, T.ROLE_DEAL_OWNER},
                internal=True, is_deal_admin=True, is_deal_owner=True)
        ctx = self._ctx(deal_id)
        self._require_internal(ctx, admin=True)
        return ctx

    def _revoke_download_if_active(self, deal_id, download_id):
        d = self.app.store.query_one(
            "SELECT * FROM download_sessions WHERE download_id=? AND deal_id=?",
            (download_id, deal_id))
        if d is not None and d["status"] in ("open", "interrupted"):
            with self.app.store.tx():
                self.app.store.execute(
                    "UPDATE download_sessions SET status='revoked', updated_at=? "
                    "WHERE download_id=?", (self.app.store.now(), download_id))
                self.app.store.append_event(
                    deal_id, "download_revoked_at_gate",
                    actor_user_id=d["user_id"], org_id=d["org_id"],
                    target_type="download", target_id=download_id,
                    detail={"watermark_id": d["watermark_id"],
                            "bytes_delivered": d["bytes_delivered"]}, commit=False)
                self.app.store.commit()

    # ---- 路由 ----
    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_DELETE(self):
        self._dispatch("DELETE")

    def _dispatch(self, method):
        path = self.path.split("?", 1)[0]
        try:
            self._route(method, path)
        except DomainError as e:
            self._send(e.http_status, {"error": e.code, "message": e.message})
        except (ValueError, KeyError) as e:
            self._send(400, {"error": "bad_request", "message": str(e)})

    def _route(self, method, path):
        app = self.app
        P = path.strip("/").split("/")

        if method == "GET" and path == "/health":
            return self._send(200, health_payload())

        # 平台引导（无交易上下文）
        if method == "POST" and path == "/api/deals":
            b = self._json_body()
            did = app.provisioning.create_deal(b["name"], b.get("phase", T.PHASE_INITIAL),
                                               b.get("deal_id"))
            return self._send(201, {"deal_id": did})
        if method == "POST" and path == "/api/users":
            b = self._json_body()
            app.provisioning.create_user(b["user_id"], b["name"])
            return self._send(201, {"user_id": b["user_id"]})
        if method == "POST" and P[:2] == ["api", "users"] and len(P) == 4 and P[3] == "deactivate":
            b = self._json_body()
            app.provisioning.deactivate_user(P[2], b.get("reason", ""))
            return self._send(200, {"deactivated": P[2]})

        if len(P) >= 3 and P[0] == "api" and P[1] == "deals":
            return self._deal_routes(method, P, app)

        from dataroom.errors import NotFound
        raise NotFound("未知路径")

    def _deal_routes(self, method, P, app):
        deal_id = P[2]
        tail = P[3:]

        # ---- 组织/团队/授权/会话（引导） ----
        if method == "POST" and tail == ["orgs"]:
            b = self._json_body()
            oid = app.provisioning.create_org(deal_id, b["name"], bool(b.get("nda_signed")),
                                              b.get("org_id"))
            return self._send(201, {"org_id": oid})
        if method == "POST" and len(tail) == 3 and tail[0] == "orgs" and tail[2] == "nda":
            app.provisioning.sign_nda(deal_id, tail[1])
            return self._send(200, {"nda": "signed"})
        if method == "POST" and tail == ["teams"]:
            b = self._json_body()
            tid = app.provisioning.create_team(deal_id, b["org_id"], b["name"], b.get("team_id"))
            return self._send(201, {"team_id": tid})
        if method == "POST" and tail == ["sessions"]:
            b = self._json_body()
            token = app.provisioning.issue_session(deal_id, b["user_id"])
            return self._send(201, {"token": token})
        if method == "POST" and tail == ["grants"]:
            ctx = self._admin_ctx(deal_id)
            b = self._json_body()
            from dataroom.provisioning import FAR_PAST, FAR_FUTURE
            gid = app.provisioning.grant(
                deal_id, b["user_id"], b["role"], b.get("org_id"), b.get("team_id"),
                b.get("valid_from", FAR_PAST), b.get("valid_until", FAR_FUTURE))
            return self._send(201, {"grant_id": gid})
        if method == "DELETE" and tail == ["grants"]:
            ctx = self._admin_ctx(deal_id)
            b = self._json_body()
            n = app.provisioning.revoke_grant(deal_id, b.get("user_id"), b.get("grant_id"),
                                              b.get("role"), b.get("reason", ""))
            return self._send(200, {"revoked_grants": n})
        if method == "POST" and tail == ["phase"]:
            ctx = self._admin_ctx(deal_id)
            b = self._json_body()
            app.provisioning.set_phase(deal_id, b["phase"])
            return self._send(200, {"phase": b["phase"]})
        if method == "POST" and tail == ["terminate"]:
            ctx = self._admin_ctx(deal_id)
            app.provisioning.terminate_deal(deal_id)
            return self._send(200, {"status": "terminated"})
        if method == "POST" and len(tail) == 2 and tail[0] == "orgs" and tail[1] == "freeze":
            ctx = self._admin_ctx(deal_id)
            b = self._json_body()
            app.provisioning.set_org_frozen(deal_id, b["org_id"], True, b.get("reason", ""))
            return self._send(200, {"frozen": b["org_id"]})

        # ---- 文档 ----
        if method == "POST" and tail == ["documents"]:
            ctx = self._admin_ctx(deal_id)
            b = self._json_body()
            did = app.documents.register_document(
                deal_id, b["doc_id"], b["title"], b["category"], b["classification"],
                b["sensitivity"], b["min_phase"], ctx.user_id,
                patient_level=bool(b.get("patient_level")),
                redaction_parent_doc_id=b.get("redaction_parent_doc_id"))
            return self._send(201, {"doc_id": did})
        if method == "POST" and len(tail) == 3 and tail[0] == "documents" and tail[2] == "versions":
            ctx = self._admin_ctx(deal_id)
            b = self._json_body()
            content = b["__raw__"]
            expected = int(self.headers.get("X-Expected-Version", "0"))
            v = app.documents.upload_version(
                deal_id, tail[1], expected, content, ctx.user_id,
                is_redacted=self.headers.get("X-Redacted") == "1",
                parent_version_id=self.headers.get("X-Parent-Version") or None,
                actor_org_id=ctx.org_id)
            return self._send(201, {"version_id": v["version_id"],
                                    "version_no": v["version_no"], "sha256": v["sha256"]})
        if method == "GET" and tail == ["documents"]:
            ctx = self._ctx(deal_id)
            items = [{"doc_id": d["doc_id"], "title": d["title"],
                      "category": d["category"], "sensitivity": d["sensitivity"],
                      "patient_level": bool(d["patient_level"]),
                      "is_redacted_doc": bool(d["redaction_parent_doc_id"]),
                      "version_id": v["version_id"], "version_no": v["version_no"],
                      "sha256": v["sha256"], "is_redacted": bool(v["is_redacted"])}
                     for d, v in app.documents.list_visible(ctx)]
            return self._send(200, {"documents": items})

        # ---- 水印化预览/导出/续传 ----
        if method == "POST" and len(tail) == 3 and tail[0] == "versions" and tail[2] == "preview":
            ctx = self._ctx(deal_id)
            from dataroom.store import sha256_hex
            res = app.preview(ctx, tail[1])
            return self._send(200, {"watermark_id": res["watermark_id"],
                                    "doc_id": res["doc_id"],
                                    "version_no": res["version_no"],
                                    "is_redacted": res["is_redacted"],
                                    "artifact_sha256": sha256_hex(res["content"])},
                             headers={"X-Watermark-Id": res["watermark_id"]})
        if method == "POST" and len(tail) == 3 and tail[0] == "versions" and tail[2] == "export":
            ctx = self._ctx(deal_id)
            res = app.start_export(ctx, tail[1])
            return self._send(201, res)
        if method == "GET" and len(tail) == 2 and tail[0] == "downloads":
            download_id = tail[1]
            try:
                ctx = self._ctx(deal_id)
            except Exception:
                # 会话门拒绝（撤权/离职/终止/冻结）时，若该令牌对应一个
                # 进行中的下载，也持久化为 revoked，再把拒绝返回给客户端。
                self._revoke_download_if_active(deal_id, download_id)
                raise
            rng = self.headers.get("Range")
            start = end = None
            if rng and rng.startswith("bytes="):
                spec = rng.split("=", 1)[1].split("-")
                start = int(spec[0]) if spec[0] else None
                end = int(spec[1]) if len(spec) > 1 and spec[1] else None
            res = app.read_chunk(ctx, tail[1], start=start, end=end)
            headers = {"Content-Range": f"bytes {res['start']}-{res['end']-1}/{res['total']}",
                       "X-Watermark-Id": res["watermark_id"],
                       "X-Download-Status": res["status"],
                       "Accept-Ranges": "bytes"}
            self.send_response(206 if res["content"] else 200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(res["content"])))
            for k, v in headers.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(res["content"])
            return
        if method == "POST" and len(tail) == 3 and tail[0] == "downloads" and tail[2] == "interrupt":
            ctx = self._ctx(deal_id)
            d = app.access.mark_interrupted(ctx, tail[1])
            return self._send(200, {"status": d["status"],
                                    "bytes_delivered": d["bytes_delivered"]})

        # ---- 问答 ----
        if method == "POST" and tail == ["qa"]:
            ctx = self._ctx(deal_id)
            b = self._json_body()
            qid = app.qa.ask(ctx, b["text"], b.get("citations"))
            return self._send(201, {"qa_id": qid})
        if method == "GET" and tail == ["qa"]:
            ctx = self._ctx(deal_id)
            rows = [self._qa_public(r) for r in app.qa.list_for(ctx)]
            return self._send(200, {"items": rows})
        if len(tail) == 3 and tail[0] == "qa":
            ctx = self._ctx(deal_id)
            qid, act = tail[1], tail[2]
            if method == "POST" and act == "answer":
                b = self._json_body()
                app.qa.answer(ctx, qid, b["text"], b["citations"])
                return self._send(200, {"qa_id": qid, "status": T.QA_ANSWERED})
            if method == "POST" and act == "legal-approve":
                app.qa.approve_legal(ctx, qid)
                return self._send(200, {"legal": "approved"})
            if method == "POST" and act == "medical-approve":
                app.qa.approve_medical(ctx, qid)
                return self._send(200, {"medical": "approved"})
            if method == "POST" and act == "reject":
                b = self._json_body()
                app.qa.reject(ctx, qid, b.get("reason", ""))
                return self._send(200, {"status": T.QA_REJECTED})
            if method == "POST" and act == "publish":
                app.qa.publish(ctx, qid)
                return self._send(200, {"status": T.QA_PUBLISHED})
            if method == "GET":
                return self._send(200, self._qa_public(app.qa.read(ctx, qid)))

        # ---- 安全事件 ----
        if method == "GET" and tail == ["incidents"]:
            ctx = self._ctx(deal_id)
            return self._send(200, {"items": [dict(r) for r in
                                              app.forensics.list_incidents(ctx)]})
        if method == "POST" and tail == ["incidents", "leak"]:
            ctx = self._admin_ctx(deal_id)
            b = self._json_body()
            iid, trace = app.security.report_leak(
                deal_id, ctx.user_id, b["watermark_id"], b["summary"],
                bool(b.get("freeze_org", True)), bool(b.get("suspend_user", True)))
            return self._send(201, {"incident_id": iid, "trace": trace})
        if method == "GET" and len(tail) == 3 and tail[0] == "watermarks":
            ctx = self._ctx(deal_id)
            self._require_internal(ctx, admin=True)
            return self._send(200, app.security.trace_watermark(tail[1]))

        # ---- 取证 ----
        if method == "GET" and tail[:1] == ["forensics"]:
            ctx = self._ctx(deal_id)
            if len(tail) >= 2 and tail[1] == "viewed":
                from urllib.parse import parse_qs, urlparse
                qs = parse_qs(urlparse(self.path).query)
                rep = app.forensics.reconstruct_viewed_set(
                    ctx, org_id=(qs.get("org_id") or [None])[0],
                    user_id=(qs.get("user_id") or [None])[0])
                return self._send(200, rep)
        if method == "GET" and tail == ["audit", "verify"]:
            ctx = self._ctx(deal_id)
            return self._send(200, app.forensics.audit_verification(ctx))

        from dataroom.errors import NotFound
        raise NotFound("未知路径")

    def _qa_public(self, r):
        d = dict(r)
        for k in ("answer_citations",):
            if d.get(k):
                d[k] = json.loads(d[k])
        return d

    def log_message(self, *_args):
        return


def build_app():
    db = os.environ.get("DATAROOM_DB", "data/dataroom.db")
    blobs = os.environ.get("DATAROOM_BLOB", "data/blobs")
    win = int(os.environ.get("DATAROOM_BULK_WINDOW", "60"))
    thr = int(os.environ.get("DATAROOM_BULK_THRESHOLD", "8"))
    return DataRoom(db, blobs, win, thr)


def main():
    parser = argparse.ArgumentParser(description=SERVICE_NAME)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        assert health_payload()["service"] == SERVICE_ID
        tax = T.load_contract_taxonomy()
        assert tax["service"] == SERVICE_ID
        assert set(tax["taxonomy"]["categories"]) == set(T.CATEGORIES)
        print("基础检查通过")
        return
    Handler.app = build_app()
    ThreadingHTTPServer(("0.0.0.0", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
