"""受控资料室总装门面。

组合存储、授权、文档、问答、事件各子系统，提供交易/组织/团队/用户/授权
的生命周期管理与泄露应急、审计复原。管理员严格按交易隔离：不存在可跨
交易查看信息的全局角色。
"""

from datetime import timedelta

from . import contract, models
from .audit import AuditLog
from .authz import Authz
from .documents import DocumentService
from .errors import AccessDeniedError, NotFoundError, WorkflowStateError
from .incidents import IncidentManager
from .qa import QAService
from .security import new_token, utcnow, utcnow_iso
from .storage import Store

DEFAULT_SESSION_TTL_SECONDS = 8 * 3600


class DataRoom:
    def __init__(self, data_dir, **doc_kwargs):
        self.store = Store(data_dir)
        self.audit = AuditLog(self.store)
        self.authz = Authz(self.store)
        self.incidents = IncidentManager(self.store, self.audit)
        self.documents = DocumentService(self.store, self.authz, self.audit,
                                         self.incidents, **doc_kwargs)
        self.qa = QAService(self.store, self.authz, self.audit)

    # ======================================================= 引导与交易
    def bootstrap_deal(self, deal_name, lead_name, lead_email):
        """从零建设：创建交易 + 内部组织 + 交易负责人，返回其登录密钥（仅一次）。"""
        with self.store.lock:
            deal = models.new_deal(deal_name, created_by=None)
            org = models.new_org(deal["deal_id"], f"{deal_name}-内部团队", models.ORG_INTERNAL)
            lead = models.new_user(org["org_id"], deal["deal_id"], lead_name, lead_email,
                                   roles=["DEAL_LEAD", "ROOM_ADMIN", "LEGAL", "MEDICAL"])
            lead["nda_signed"] = True  # 内部人员 NDA 在入职流程完成，此处标记已签
            lead["nda_ts"] = utcnow_iso()
            lead["secret"] = new_token(24)
            deal["created_by"] = lead["user_id"]
            self.store.state["deals"][deal["deal_id"]] = deal
            self.store.state["orgs"][org["org_id"]] = org
            self.store.state["users"][lead["user_id"]] = lead
            # 内部负责人持有覆盖全部分类、无有效期的 DEAL 级授权。
            lead_grant = models.new_grant(
                deal["deal_id"], "USER", lead["user_id"], "DEAL_LEAD",
                categories=None)
            lead_grant["roles"] = ["DEAL_LEAD", "ROOM_ADMIN", "LEGAL", "MEDICAL"]
            lead_grant["valid_until"] = None
            self.store.state["grants"][lead_grant["grant_id"]] = lead_grant
            self.store.commit()
            self.audit.log("DEAL_BOOTSTRAPPED", deal_id=deal["deal_id"], user_id=lead["user_id"])
            return {"deal_id": deal["deal_id"], "org_id": org["org_id"],
                    "user_id": lead["user_id"], "secret": lead["secret"],
                    "name": lead_name, "roles": lead["roles"]}

    def _internal(self, user_id, deal_id, roles=None):
        decision = self.authz.require_deal_access(user_id, deal_id)
        if not decision.internal:
            raise AccessDeniedError("INTERNAL_ONLY", "仅内部人员可执行该操作")
        if roles and not (set(roles) & decision.roles):
            raise AccessDeniedError("ROLE_FORBIDDEN", "角色无权执行该操作")
        return decision

    def terminate_deal(self, user_id, deal_id, reason):
        """交易终止：状态落盘，授权引擎对该交易的一切新查看立即阻断。"""
        self._internal(user_id, deal_id, roles=("DEAL_LEAD",))
        with self.store.lock:
            deal = self.store.state["deals"][deal_id]
            if deal["status"] == models.DEAL_TERMINATED:
                raise WorkflowStateError("交易已终止")
            deal["status"] = models.DEAL_TERMINATED
            deal["terminated_ts"] = utcnow_iso()
            deal["terminate_reason"] = reason
            # 主动撤销该交易全部活跃授权（双保险，状态判定本身已阻断）。
            for grant in self.store.state["grants"].values():
                if grant["deal_id"] == deal_id and grant["status"] == models.GRANT_ACTIVE:
                    grant["status"] = models.GRANT_REVOKED
                    grant["revoked_ts"] = utcnow_iso()
                    grant["revoked_reason"] = "DEAL_TERMINATED"
            # 注销全部会话。
            for token, session in list(self.store.state["sessions"].items()):
                if session["deal_id"] == deal_id:
                    del self.store.state["sessions"][token]
            self.store.commit()
            self.audit.log("DEAL_TERMINATED", deal_id=deal_id, user_id=user_id, reason=reason)
            return dict(deal)

    def deal_status(self, user_id, deal_id):
        self._internal(user_id, deal_id)
        deal = self.store.state["deals"][deal_id]
        return dict(deal)

    # ======================================================= 组织与团队
    def create_bidder_org(self, user_id, name):
        deal_id = self.store.state["users"][user_id]["deal_id"]
        self._internal(user_id, deal_id, roles=("DEAL_LEAD", "ROOM_ADMIN"))
        with self.store.lock:
            org = models.new_org(deal_id, name, models.ORG_BIDDER)
            self.store.state["orgs"][org["org_id"]] = org
            self.store.commit()
            self.audit.log("ORG_CREATED", deal_id=deal_id, user_id=user_id, org_id=org["org_id"])
            return {"org_id": org["org_id"], "name": name, "kind": models.ORG_BIDDER}

    def create_team(self, user_id, org_id, name):
        org = self.store.state["orgs"].get(org_id)
        if org is None:
            raise NotFoundError(f"组织不存在: {org_id}")
        self._internal(user_id, org["deal_id"], roles=("DEAL_LEAD", "ROOM_ADMIN"))
        with self.store.lock:
            team = models.new_team(org_id, name)
            self.store.state.setdefault("teams", {})[team["team_id"]] = team
            self.store.commit()
            self.audit.log("TEAM_CREATED", deal_id=org["deal_id"], user_id=user_id,
                           org_id=org_id, team_id=team["team_id"])
            return dict(team)

    # ======================================================= 用户、NDA 与入会
    def create_invitation(self, user_id, org_id, roles, teams=None,
                          valid_from=None, valid_until=None, categories=None):
        """内部人员向某组织发放入会令牌；令牌绑定组织、角色、团队与有效期。"""
        org = self.store.state["orgs"].get(org_id)
        if org is None:
            raise NotFoundError(f"组织不存在: {org_id}")
        self._internal(user_id, org["deal_id"], roles=("DEAL_LEAD", "ROOM_ADMIN"))
        for role in roles:
            contract.validate_role(role)
        with self.store.lock:
            token = new_token(24)
            enrollment = {
                "token": token, "deal_id": org["deal_id"], "org_id": org_id,
                "roles": list(roles), "teams": list(teams or []),
                "categories": list(categories) if categories else None,
                "valid_from": valid_from, "valid_until": valid_until,
                "created_by": user_id, "created_ts": utcnow_iso(),
                "status": "OPEN", "consumed_by": None,
            }
            self.store.state["enrollments"][token] = enrollment
            self.store.commit()
            self.audit.log("INVITATION_CREATED", deal_id=org["deal_id"], user_id=user_id,
                           org_id=org_id, roles=list(roles), teams=list(teams or []))
            return {"enrollment_token": token, "org_id": org_id,
                    "valid_from": valid_from, "valid_until": valid_until}

    def enroll(self, token, name, email):
        """竞标方人员凭令牌入会；初始 NDA 未签，尚不能查看任何材料。"""
        enrollment = self.store.state["enrollments"].get(token)
        if enrollment is None or enrollment["status"] != "OPEN":
            raise AccessDeniedError("INVALID_ENROLLMENT", "入会令牌无效或已使用")
        now_s = utcnow_iso()
        if enrollment["valid_from"] and enrollment["valid_from"] > now_s:
            raise AccessDeniedError("ENROLLMENT_NOT_STARTED", "入会尚未生效")
        if enrollment["valid_until"] and enrollment["valid_until"] <= now_s:
            raise AccessDeniedError("ENROLLMENT_EXPIRED", "入会已过期")
        with self.store.lock:
            # 团队资格校验
            team_ids = {t["team_id"] for t in self.store.state.get("teams", {}).values()}
            for team_id in enrollment["teams"]:
                if team_id not in team_ids:
                    raise NotFoundError(f"团队不存在: {team_id}")
            user = models.new_user(enrollment["org_id"], enrollment["deal_id"], name, email,
                                   roles=enrollment["roles"], teams=enrollment["teams"])
            user["secret"] = new_token(24)
            self.store.state["users"][user["user_id"]] = user
            enrollment["status"] = "CONSUMED"
            enrollment["consumed_by"] = user["user_id"]
            # 令牌携带的角色自动落成一条 USER 授权，受相同有效期约束。
            grant = models.new_grant(
                enrollment["deal_id"], "USER", user["user_id"], enrollment["roles"][0],
                valid_from=enrollment["valid_from"], valid_until=enrollment["valid_until"],
                categories=enrollment["categories"])
            # 多角色时保存全部角色。
            grant["roles"] = list(enrollment["roles"])
            self.store.state["grants"][grant["grant_id"]] = grant
            self.store.commit()
            self.audit.log("USER_ENROLLED", deal_id=user["deal_id"], org_id=user["org_id"],
                           user_id=user["user_id"], roles=user["roles"])
            return {"user_id": user["user_id"], "secret": user["secret"],
                    "nda_signed": False, "roles": user["roles"]}

    def sign_nda(self, user_id, version=None):
        with self.store.lock:
            user = self._user(user_id)
            if user["nda_signed"]:
                raise WorkflowStateError("NDA 已签署")
            user["nda_signed"] = True
            user["nda_ts"] = utcnow_iso()
            user["nda_version"] = version or "DEFAULT"
            self.store.commit()
            self.audit.log("NDA_SIGNED", deal_id=user["deal_id"], org_id=user["org_id"],
                           user_id=user_id, nda_version=user["nda_version"])
            return {"user_id": user_id, "nda_signed": True, "nda_ts": user["nda_ts"]}

    def withdraw_nda(self, admin_id, user_id, reason):
        """NDA 撤回（如发现协议瑕疵）：即时阻断新查看。"""
        user = self._user(user_id)
        self._internal(admin_id, user["deal_id"], roles=("DEAL_LEAD", "LEGAL"))
        with self.store.lock:
            user["nda_signed"] = False
            user["nda_withdrawn_ts"] = utcnow_iso()
            self.store.commit()
            self.audit.log("NDA_WITHDRAWN", deal_id=user["deal_id"], user_id=admin_id,
                           target_user=user_id, reason=reason)
            return {"user_id": user_id, "nda_signed": False}

    def offboard_user(self, admin_id, user_id, reason):
        """离职：即时阻断。状态置 OFFBOARDED、撤权、销会话。"""
        target = self._user(user_id)
        self._internal(admin_id, target["deal_id"], roles=("DEAL_LEAD", "ROOM_ADMIN"))
        with self.store.lock:
            target["status"] = models.USER_OFFBOARDED
            target["offboarded_ts"] = utcnow_iso()
            target["offboard_reason"] = reason
            self._revoke_subject_grants("USER", user_id, "USER_OFFBOARDED")
            for token, session in list(self.store.state["sessions"].items()):
                if session["user_id"] == user_id:
                    del self.store.state["sessions"][token]
            self.store.commit()
            self.audit.log("USER_OFFBOARDED", deal_id=target["deal_id"], user_id=admin_id,
                           target_user=user_id, reason=reason)
            return {"user_id": user_id, "status": models.USER_OFFBOARDED}

    def _user(self, user_id):
        user = self.store.state["users"].get(user_id)
        if user is None:
            raise NotFoundError(f"用户不存在: {user_id}")
        return user

    # ======================================================= 授权与撤权
    def grant(self, admin_id, scope, subject_id, role, valid_from=None,
              valid_until=None, categories=None):
        """按交易/组织/团队/用户设置角色授权与期限。"""
        contract.validate_role(role)
        if scope == "DEAL":
            deal = self.store.state["deals"].get(subject_id)
            deal_id = deal["deal_id"] if deal else None
        elif scope in ("ORG", "TEAM"):
            if scope == "TEAM":
                team = self.store.state.get("teams", {}).get(subject_id)
                org = self.store.state["orgs"].get(team["org_id"]) if team else None
            else:
                org = self.store.state["orgs"].get(subject_id)
            if (scope == "ORG" and org is None) or (scope == "TEAM" and (team is None or org is None)):
                raise NotFoundError(f"{scope} 主体不存在: {subject_id}")
            deal_id = org["deal_id"]
        else:
            user = self._user(subject_id)
            deal_id = user["deal_id"]
        self._internal(admin_id, deal_id, roles=("DEAL_LEAD", "ROOM_ADMIN"))
        with self.store.lock:
            record = models.new_grant(deal_id, scope, subject_id, role,
                                      valid_from=valid_from, valid_until=valid_until,
                                      categories=categories)
            self.store.state["grants"][record["grant_id"]] = record
            self.store.commit()
            self.audit.log("GRANT_CREATED", deal_id=deal_id, user_id=admin_id,
                           scope=scope, subject_id=subject_id, role=role,
                           valid_until=valid_until, categories=categories)
            return dict(record)

    def _revoke_subject_grants(self, scope, subject_id, reason):
        for grant in self.store.state["grants"].values():
            if grant["scope"] == scope and grant["subject_id"] == subject_id \
                    and grant["status"] == models.GRANT_ACTIVE:
                grant["status"] = models.GRANT_REVOKED
                grant["revoked_ts"] = utcnow_iso()
                grant["revoked_reason"] = reason

    def revoke_grant(self, admin_id, grant_id, reason):
        """撤权：授权引擎下一次实时求值即阻断，无需等待会话过期。"""
        grant = self.store.state["grants"].get(grant_id)
        if grant is None:
            raise NotFoundError(f"授权不存在: {grant_id}")
        self._internal(admin_id, grant["deal_id"], roles=("DEAL_LEAD", "ROOM_ADMIN"))
        with self.store.lock:
            if grant["status"] != models.GRANT_ACTIVE:
                raise WorkflowStateError("授权已撤销")
            grant["status"] = models.GRANT_REVOKED
            grant["revoked_ts"] = utcnow_iso()
            grant["revoked_reason"] = reason
            self.store.commit()
            self.audit.log("GRANT_REVOKED", deal_id=grant["deal_id"], user_id=admin_id,
                           grant_id=grant_id, scope=grant["scope"],
                           subject_id=grant["subject_id"], reason=reason)
            return dict(grant)

    # ======================================================= 会话
    def login(self, user_id, secret, ttl_seconds=DEFAULT_SESSION_TTL_SECONDS):
        user = self._user(user_id)
        if user.get("secret") != secret:
            raise AccessDeniedError("BAD_CREDENTIALS", "身份凭据不正确")
        if user["status"] == models.USER_OFFBOARDED:
            raise AccessDeniedError("USER_OFFBOARDED", "人员已离职")
        if user.get("suspended"):
            raise AccessDeniedError("USER_SUSPENDED", user.get("suspend_reason") or "账号已冻结")
        token = new_token(24)
        expires = utcnow() + timedelta(seconds=ttl_seconds)
        session = {
            "token": token, "user_id": user_id, "deal_id": user["deal_id"],
            "org_id": user["org_id"], "created_ts": utcnow_iso(),
            "expires_ts": expires.isoformat(timespec="seconds") + "Z",
        }
        with self.store.lock:
            self.store.state["sessions"][token] = session
            self.store.commit()
            self.audit.log("SESSION_LOGIN", deal_id=user["deal_id"], org_id=user["org_id"],
                           user_id=user_id)
        return session

    def logout(self, token):
        with self.store.lock:
            session = self.store.state["sessions"].pop(token, None)
            if session:
                self.store.commit()
                self.audit.log("SESSION_LOGOUT", deal_id=session["deal_id"],
                               user_id=session["user_id"])
        return {"ok": True}

    def authenticate(self, token):
        """令牌 → 当前用户；每次请求实时校验主体状态。"""
        session = self.authz.session(token)
        user = self._user(session["user_id"])
        return user

    def log_denied(self, user_id, action, reason, **details):
        user = self.store.state["users"].get(user_id) if user_id else None
        self.audit.log(action, deal_id=user["deal_id"] if user else details.get("deal_id"),
                       org_id=user["org_id"] if user else None, user_id=user_id,
                       result="DENIED", reason=reason, **details)

    # ======================================================= 泄露应急
    def report_leak(self, reporter_id, watermark_code_text, summary, scope="USER"):
        """凭外泄件水印码溯源并冻结。scope=ORG 时扩大至整个竞标方。"""
        trace = self.incidents.trace_watermark(watermark_code_text)
        deal_id = trace["deal_id"]
        self._internal(reporter_id, deal_id, roles=("DEAL_LEAD", "LEGAL", "ROOM_ADMIN"))
        target_user = trace["user_id"]
        target_org = trace["org_id"]
        with self.store.lock:
            incident = self.incidents.open(
                "LEAK", deal_id, summary,
                details={"watermark_code": watermark_code_text,
                         "trace_audit_id": trace["audit_id"],
                         "doc_id": trace["doc_id"], "version_no": trace["version_no"],
                         "freeze_scope": scope},
                related_user=target_user, related_org=target_org,
                related_doc=trace["doc_id"],
                auto_action="FREEZE_ORG" if scope == "ORG" else "FREEZE_USER",
            )
            self._freeze_subject(target_user, "LEAK_SUSPECTED", incident["incident_id"])
            if scope == "ORG":
                for user in self.store.state["users"].values():
                    if user["org_id"] == target_org and user["user_id"] != target_user:
                        self._freeze_subject(user["user_id"], "LEAK_ORG_FREEZE",
                                             incident["incident_id"])
            self.store.commit()
            return {"incident": incident, "trace": {
                "audit_id": trace["audit_id"], "user_id": target_user,
                "org_id": target_org, "doc_id": trace["doc_id"],
                "version_no": trace["version_no"], "ts": trace["ts"]}}

    def _freeze_subject(self, user_id, reason, incident_id):
        user = self._user(user_id)
        user["suspended"] = True
        user["suspend_reason"] = reason
        user["suspended_ts"] = utcnow_iso()
        user["suspend_incident"] = incident_id
        self._revoke_subject_grants("USER", user_id, reason)
        for token, session in list(self.store.state["sessions"].items()):
            if session["user_id"] == user_id:
                del self.store.state["sessions"][token]
        self.audit.log("LEAK_FREEZE", deal_id=user["deal_id"], org_id=user["org_id"],
                       user_id=user_id, reason=reason, incident_id=incident_id)

    def incident_action(self, user_id, incident_id, action, note=None):
        incident = self.store.state["incidents"][incident_id]
        self._internal(user_id, incident["deal_id"], roles=("DEAL_LEAD", "LEGAL", "ROOM_ADMIN"))
        if action == "REVOKE_ORG":
            with self.store.lock:
                org_id = incident.get("related_org")
                if org_id:
                    self._revoke_subject_grants("ORG", org_id, "INCIDENT_REVOKE_ORG")
                    for member in self.store.state["users"].values():
                        if member["org_id"] == org_id and not member.get("suspended"):
                            self._freeze_subject(member["user_id"], "INCIDENT_ORG_FREEZE",
                                                 incident_id)
                self.store.commit()
        return self.incidents.act(incident_id, action, user_id, note)

    def resolve_incident(self, user_id, incident_id, note=None):
        incident = self.store.state["incidents"][incident_id]
        self._internal(user_id, incident["deal_id"], roles=("DEAL_LEAD", "LEGAL"))
        return self.incidents.resolve(incident_id, user_id, note)

    def list_incidents(self, user_id, deal_id):
        self._internal(user_id, deal_id)
        return self.incidents.list_for_deal(deal_id)

    def get_incident(self, user_id, incident_id):
        incident = self.store.state["incidents"].get(incident_id)
        if incident is None:
            raise NotFoundError(f"事件不存在: {incident_id}")
        self._internal(user_id, incident["deal_id"])
        return self.incidents.get(incident_id)

    # ======================================================= 审计复原（按交易隔离）
    def reconstruct_org_view(self, admin_id, deal_id, org_id):
        """复原某竞标方在某交易中看过的资料集合。管理员必须属于该交易。"""
        self._internal(admin_id, deal_id)
        org = self.store.state["orgs"].get(org_id)
        if org is None or org["deal_id"] != deal_id:
            raise NotFoundError(f"组织不属于该交易: {org_id}")
        collection = self.audit.viewed_collection(deal_id=deal_id, org_id=org_id)
        member_ids = [u["user_id"] for u in self.store.state["users"].values()
                      if u["org_id"] == org_id and u["deal_id"] == deal_id]
        return {"deal_id": deal_id, "org_id": org_id, "org_name": org["name"],
                "member_count": len(member_ids), "viewed_documents": collection,
                "total_distinct_versions": len(collection)}

    def reconstruct_user_view(self, admin_id, user_id):
        user = self._user(user_id)
        self._internal(admin_id, user["deal_id"])
        org = self.store.state["orgs"][user["org_id"]]
        collection = self.audit.viewed_collection(deal_id=user["deal_id"], user_id=user_id)
        return {"deal_id": user["deal_id"], "org_id": user["org_id"],
                "org_name": org["name"], "user_id": user_id, "user_name": user["name"],
                "viewed_documents": collection, "total_distinct_versions": len(collection)}

    def audit_trail(self, admin_id, deal_id, limit=200):
        """导出某交易的审计轨迹；管理员只能取本交易的行。"""
        self._internal(admin_id, deal_id)
        rows = [e for e in self.audit.snapshot() if e.get("deal_id") == deal_id]
        return rows[-limit:]
