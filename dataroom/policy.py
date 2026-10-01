"""实时鉴权策略。

每个受保护请求都先过 Policy.context(token)：不缓存授权结论，
因此 NDA 失效标记、离职、撤权、授权到期、交易终止、组织冻结、
交易内停权都在下一次请求立即生效（包括进行中的断点续传）。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import taxonomy as T
from .errors import Forbidden, Unauthorized
from .store import Store


@dataclass
class Context:
    token: str
    deal_id: str
    user_id: str
    user_name: str
    org_id: str | None
    team_ids: set = field(default_factory=set)
    roles: set = field(default_factory=set)
    internal: bool = False
    is_deal_admin: bool = False
    is_deal_owner: bool = False

    def has_role(self, role: str) -> bool:
        return role in self.roles


class Policy:
    def __init__(self, store: Store):
        self.store = store

    # ---- 会话与当前授权快照 ----
    def context(self, token: str | None) -> Context:
        if not token:
            raise Unauthorized("missing_token", "缺少访问令牌")
        s = self.store.query_one("SELECT * FROM sessions WHERE token=?", (token,))
        if s is None:
            raise Unauthorized("bad_token", "令牌无效")
        ctx = self._load_context(s["deal_id"], s["user_id"], token)
        # 会话吊销放在用户/交易状态之后判定：离职、交易终止给出精确原因
        if s["revoked"]:
            raise Forbidden("session_revoked", "会话已吊销", 403)
        return ctx

    def context_for_user(self, deal_id: str, user_id: str) -> Context:
        """以指定用户身份构造上下文（用于发布前替提问方复核引用权限）。"""
        return self._load_context(deal_id, user_id, token=None)

    def _load_context(self, deal_id: str, user_id: str, token: str | None) -> Context:
        now = self.store.now()

        user = self.store.query_one("SELECT * FROM users WHERE user_id=?", (user_id,))
        if user is None or not user["active"]:
            # 离职：立即阻断新的查看
            raise Forbidden("user_deactivated", "人员已离职/停用", 403)

        deal = self.store.query_one("SELECT * FROM deals WHERE deal_id=?", (deal_id,))
        if deal is None:
            raise Unauthorized("bad_deal", "交易不存在")
        if deal["status"] != "active":
            raise Forbidden("deal_terminated", "交易已终止，访问已关闭", 403)

        # 当前时刻仍有效的授权（期限 + 未撤权）
        grants = self.store.query(
            "SELECT * FROM access_grants WHERE deal_id=? AND user_id=? "
            "AND revoked=0 AND valid_from<=? AND valid_until>=?",
            (deal_id, user_id, now, now),
        )
        if not grants:
            raise Forbidden("no_valid_grant", "当前无有效授权（可能已到期或被撤权）", 403)

        roles = {g["role"] for g in grants}
        internal = bool(roles & T.INTERNAL_ROLES)
        org_ids = {g["org_id"] for g in grants if g["org_id"]}
        team_ids = {g["team_id"] for g in grants if g["team_id"]}
        org_id = sorted(org_ids)[0] if org_ids else None

        if not internal:
            if org_id is None:
                raise Forbidden("grant_misconfigured", "竞标方授权缺少组织归属", 403)
            org = self.store.query_one(
                "SELECT * FROM organizations WHERE org_id=? AND deal_id=?",
                (org_id, deal_id),
            )
            if org is None:
                raise Forbidden("org_gone", "组织不存在", 403)
            # NDA 未签署：立即阻断
            if not org["nda_signed_at"]:
                raise Forbidden("nda_unsigned", "保密协议尚未签署", 403)
            # 安全冻结（泄露事件处置）：立即阻断
            if org["frozen"]:
                raise Forbidden("org_frozen", "组织因安全事件被冻结", 403)
        else:
            org = None

        # 交易内用户级停权（异常批量访问自动处置）
        st = self.store.query_one(
            "SELECT suspended FROM deal_user_state WHERE deal_id=? AND user_id=?",
            (deal_id, user_id),
        )
        if st is not None and st["suspended"]:
            raise Forbidden("user_suspended_in_deal", "因异常访问已被暂停本交易权限", 403)

        return Context(
            token=token, deal_id=deal_id, user_id=user_id,
            user_name=user["name"], org_id=org_id, team_ids=team_ids,
            roles=roles, internal=internal,
            is_deal_admin=T.ROLE_DEAL_ADMIN in roles,
            is_deal_owner=T.ROLE_DEAL_OWNER in roles,
        )

    # ---- 交易隔离 ----
    def assert_deal_scope(self, ctx: Context, deal_id: str):
        if ctx.deal_id != deal_id:
            # 结构性隔离：不承认别的交易的任何资源
            raise Forbidden("cross_deal_denied", "不能访问其他交易的信息", 403)

    # ---- 文档级鉴权 ----
    def can_view_version(self, ctx: Context, doc, version, *, action="preview"):
        """doc/version 为 sqlite Row。失败抛 Forbidden。返回角色判定说明。"""
        self.assert_deal_scope(ctx, doc["deal_id"])

        if doc["status"] == T.DOC_QUARANTINED:
            raise Forbidden("doc_quarantined", "文件病毒扫描失败，已隔离", 403)
        if doc["status"] == T.DOC_WITHDRAWN:
            raise Forbidden("doc_withdrawn", "文件已撤回", 403)
        if version["scan_status"] != "clean":
            raise Forbidden("version_infected", "版本病毒扫描失败，已隔离", 403)
        if version["deal_id"] != ctx.deal_id or version["doc_id"] != doc["doc_id"]:
            raise Forbidden("cross_deal_denied", "版本与文档不匹配", 403)

        deal = self.store.query_one("SELECT phase FROM deals WHERE deal_id=?", (ctx.deal_id,))
        # 阶段门：材料只在交易/组织到达其 min_phase 后开放
        if T.PHASES.index(deal["phase"]) < T.PHASES.index(doc["min_phase"]):
            raise Forbidden("phase_not_open", "该材料尚未进入开放阶段", 403)

        # 患者级：竞标方只能看脱敏件；原件仅负责人/管理员
        is_original = not version["is_redacted"]
        if doc["patient_level"] and is_original and action != "original_admin":
            if not (ctx.is_deal_owner or ctx.is_deal_admin):
                raise Forbidden(
                    "patient_original_blocked",
                    "患者级材料原件不开放，仅可查看脱敏版本", 403,
                )
        if action == "original_admin" and not (ctx.is_deal_owner or ctx.is_deal_admin):
            raise Forbidden("original_admin_only", "仅交易负责人/管理员可调取原件", 403)

        sens = doc["sensitivity"]
        allowed_role = None
        for role in ctx.roles:
            cap = T.ROLE_MAX_SENSITIVITY.get(role)
            if cap is None:
                continue
            level = cap if isinstance(cap, int) else T.SENSITIVITY_ORDER[cap]
            if level >= T.SENSITIVITY_ORDER[sens]:
                # 医学尽调对患者级只能通过脱敏件访问（上面已拦截原件）
                allowed_role = role
                break
        if allowed_role is None:
            raise Forbidden("sensitivity_denied", f"角色无权接触{sens}级材料", 403)
        return {"role_used": allowed_role, "sensitivity": sens}

    # ---- 问答可见性 ----
    def can_see_qa(self, ctx: Context, qa) -> bool:
        self.assert_deal_scope(ctx, qa["deal_id"])
        if ctx.internal:
            return True
        return qa["org_id"] == ctx.org_id and qa["status"] == T.QA_PUBLISHED
