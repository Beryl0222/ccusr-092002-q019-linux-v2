"""授权引擎。

每次访问都实时求值，不缓存结论，因此以下事件对“新的查看”立即生效：
NDA 未签/被撤回、人员离职、授撤销、交易终止、阶段未开放、版本被隔离或撤回。

主体层级：交易(DEAL) → 组织(ORG) → 团队(TEAM) → 用户(USER)，
授权在每一层可设角色、材料分类范围与有效期，取并集后再过阶段门与文档状态。
"""

from dataclasses import dataclass, field

from . import contract, models
from .errors import AccessDeniedError, NdaRequiredError, NotFoundError
from .security import utcnow, utcnow_iso


def _ts(now=None):
    """与 security.utcnow_iso 一致的可比较字符串（秒级，Z 结尾）。"""
    return utcnow_iso() if now is None else now.isoformat(timespec="seconds") + "Z"


@dataclass
class Decision:
    allowed: bool
    reason: str = "OK"
    roles: set = field(default_factory=set)
    categories: set = field(default_factory=set)
    internal: bool = False

    def deny(self):
        return not self.allowed


def version_key(key):
    """版本号排序键：主版本整数 + 脱敏子版本序号，如 '1' < '1.1' < '1.2' < '2'。"""
    return tuple(int(part) for part in str(key).split("."))


class Authz:
    def __init__(self, store):
        self.store = store

    # ----------------------------------------------------------- 主体解析
    def _user(self, user_id):
        user = self.store.state["users"].get(user_id)
        if user is None:
            raise NotFoundError(f"用户不存在: {user_id}")
        return user

    def session(self, token):
        session = self.store.state["sessions"].get(token)
        if session is None:
            raise AccessDeniedError("INVALID_SESSION", "会话不存在或已注销")
        if session.get("expires_ts") and session["expires_ts"] <= utcnow_iso():
            raise AccessDeniedError("SESSION_EXPIRED", "会话已过期")
        return session

    def _org(self, org_id):
        return self.store.state["orgs"].get(org_id)

    def _deal(self, deal_id):
        return self.store.state["deals"].get(deal_id)

    # ----------------------------------------------------------- 综合判定
    def effective_roles(self, user, now=None):
        """返回 (角色集合, 可访问分类集合或 None, 是否内部, 阻断原因)。"""
        now = now or utcnow()
        now_s = _ts(now)
        roles = set(user["roles"])  # 档案上的静态角色
        allowed_categories = None
        blocked = None

        matched = False
        grant_categories = []
        for grant in self.store.state["grants"].values():
            if grant["deal_id"] != user["deal_id"] or grant["status"] != models.GRANT_ACTIVE:
                continue
            if grant["valid_from"] > now_s:
                continue
            if grant["valid_until"] and grant["valid_until"] <= now_s:
                continue
            subject_hit = (
                (grant["scope"] == "DEAL" and grant["subject_id"] == user["deal_id"])
                or (grant["scope"] == "ORG" and grant["subject_id"] == user["org_id"])
                or (grant["scope"] == "TEAM" and grant["subject_id"] in user.get("teams", []))
                or (grant["scope"] == "USER" and grant["subject_id"] == user["user_id"])
            )
            if not subject_hit:
                continue
            matched = True
            grant_roles = grant.get("roles") or [grant["role"]]
            roles.update(grant_roles)
            if grant["categories"] is not None:
                grant_categories.append(set(grant["categories"]))

        if not matched:
            blocked = "NO_ACTIVE_GRANT"
        if grant_categories:
            # 多条授权累加授权范围：取并集（每条授予的访问权都成立）。
            allowed_categories = set().union(*grant_categories)
        return roles, allowed_categories, blocked

    def evaluate(self, user_id, deal_id):
        """主体级判定：身份、NDA、交易状态、有效期授权。返回 Decision。"""
        user = self._user(user_id)
        if user["deal_id"] != deal_id:
            # 跨交易：即使 token 有效也绝不放行
            raise AccessDeniedError("CROSS_DEAL", "禁止访问其他交易的资料室")
        deal = self._deal(deal_id)
        if deal is None:
            raise NotFoundError(f"交易不存在: {deal_id}")
        org = self._org(user["org_id"])
        if org is None or org.get("status") != "ACTIVE":
            return Decision(False, "ORG_DISABLED")
        if deal["status"] == models.DEAL_TERMINATED:
            return Decision(False, "DEAL_TERMINATED")
        if user["status"] == models.USER_OFFBOARDED:
            return Decision(False, "USER_OFFBOARDED")
        if user.get("suspended"):
            return Decision(False, "USER_SUSPENDED:" + (user.get("suspend_reason") or ""))
        if not user["nda_signed"]:
            return Decision(False, "NDA_NOT_SIGNED")

        roles, grant_categories, blocked = self.effective_roles(user)
        if blocked:
            return Decision(False, blocked)
        is_internal = org["kind"] == models.ORG_INTERNAL
        return Decision(True, "OK", roles=roles, categories=grant_categories or set(), internal=is_internal)

    def require_deal_access(self, user_id, deal_id):
        decision = self.evaluate(user_id, deal_id)
        if not decision.allowed:
            if decision.reason == "NDA_NOT_SIGNED":
                raise NdaRequiredError()
            raise AccessDeniedError(decision.reason)
        return decision

    # ----------------------------------------------------------- 文档判定
    def visible_version(self, user_id, doc, version_no):
        """文档/版本级判定，返回可访问的版本记录。"""
        decision = self.require_deal_access(user_id, doc["deal_id"])
        if doc["status"] != models.DOC_ACTIVE:
            raise AccessDeniedError("DOC_WITHDRAWN", f"文档已撤回: {doc['doc_id']}")
        version = doc["versions"].get(str(version_no))
        if version is None:
            raise NotFoundError(f"版本不存在: {doc['doc_id']} v{version_no}")
        if version["scan_status"] != models.SCAN_CLEAN:
            raise AccessDeniedError(
                "SCAN_NOT_CLEAN", f"版本未通过病毒扫描: {version['scan_status']}"
            )
        # 外部竞标方永远拿不到原件；分阶段开放只约束外部。
        if not decision.internal:
            if version["tier"] == models.TIER_ORIGINAL:
                raise AccessDeniedError("TIER_FORBIDDEN", "竞标方仅可查看脱敏版本")
            gate = contract.phase_gates()[self._deal(doc["deal_id"])["phase"]]
            if doc["category"] not in gate["open_categories"]:
                raise AccessDeniedError("PHASE_CATEGORY_CLOSED", "当前阶段未开放该材料分类")
            if contract.sensitivity_rank(doc["sensitivity"]) > contract.sensitivity_rank(gate["max_sensitivity"]):
                raise AccessDeniedError("SENSITIVITY_ABOVE_PHASE", "材料敏感级别超出当前阶段上限")
            allowed_by_role = set()
            for role in decision.roles:
                allowed_by_role.update(contract.default_role_rules().get(role, []))
            if doc["category"] not in allowed_by_role:
                raise AccessDeniedError("ROLE_CATEGORY_NOT_ALLOWED", "角色无权查看该材料分类")
            if decision.categories and doc["category"] not in decision.categories:
                raise AccessDeniedError("GRANT_CATEGORY_DENIED", "授权范围不含该材料分类")
        return version

    def list_visible_documents(self, user_id, deal_id):
        """列出主体当前可见的文档（含可见版本号集合），用于目录与问答引用校验。"""
        decision = self.require_deal_access(user_id, deal_id)
        result = []
        gate = contract.phase_gates()[self._deal(deal_id)["phase"]]
        for doc in self.store.state["documents"].values():
            if doc["deal_id"] != deal_id or doc["status"] != models.DOC_ACTIVE:
                continue
            visible_versions = []
            for version_no in sorted(doc["versions"], key=version_key):
                try:
                    self.visible_version(user_id, doc, version_no)
                except (AccessDeniedError, NotFoundError):
                    continue
                visible_versions.append(version_no)
            if visible_versions:
                result.append({
                    "doc_id": doc["doc_id"],
                    "title": doc["title"],
                    "category": doc["category"],
                    "sensitivity": doc["sensitivity"],
                    "latest_version": doc["latest_version"],
                    "visible_versions": visible_versions,
                    "phase_open": decision.internal or doc["category"] in gate["open_categories"],
                })
        return result
