"""资源开通与生命周期：交易、组织、团队、用户、授权、会话。

所有改变访问状态的动作都追加哈希链事件；撤权类动作（离职/撤权/
终止/冻结/停权）写入后由策略层在下一次请求实时读到，立即阻断。
"""

from __future__ import annotations

import uuid

from . import taxonomy as T
from .store import Store


def _id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


FAR_PAST = "2000-01-01T00:00:00Z"
FAR_FUTURE = "2999-12-31T23:59:59Z"


class Provisioning:
    def __init__(self, store: Store):
        self.store = store

    # ---- 交易 ----
    def create_deal(self, name, phase=T.PHASE_INITIAL, deal_id=None):
        deal_id = deal_id or _id("DEAL")
        now = self.store.now()
        with self.store.tx():
            self.store.execute(
                "INSERT INTO deals(deal_id,name,status,phase,created_at) VALUES(?,?,?,?,?)",
                (deal_id, name, "active", phase, now),
            )
            self.store.append_event(
                deal_id, "deal_created", target_type="deal", target_id=deal_id,
                detail={"name": name, "phase": phase}, commit=False,
            )
            self.store.commit()
        return deal_id

    def set_phase(self, deal_id, phase):
        assert phase in T.PHASES
        with self.store.tx():
            self.store.execute(
                "UPDATE deals SET phase=? WHERE deal_id=?", (phase, deal_id)
            )
            self.store.append_event(
                deal_id, "deal_phase_changed", target_type="deal", target_id=deal_id,
                detail={"phase": phase}, commit=False,
            )
            self.store.commit()

    def terminate_deal(self, deal_id):
        """交易终止：立即阻断该交易全部新查看（策略层读 status）。"""
        with self.store.tx():
            self.store.execute(
                "UPDATE deals SET status='terminated' WHERE deal_id=?", (deal_id,)
            )
            self.store.execute(
                "UPDATE sessions SET revoked=1 WHERE deal_id=?", (deal_id,)
            )
            self.store.append_event(
                deal_id, "deal_terminated", target_type="deal", target_id=deal_id,
                detail={"sessions_revoked": True}, commit=False,
            )
            self.store.commit()

    # ---- 组织（竞标方） ----
    def create_org(self, deal_id, name, nda_signed=False, org_id=None):
        org_id = org_id or _id("ORG")
        now = self.store.now()
        nda_at = now if nda_signed else None
        with self.store.tx():
            self.store.execute(
                "INSERT INTO organizations(org_id,deal_id,name,nda_signed_at,created_at)"
                " VALUES(?,?,?,?,?)",
                (org_id, deal_id, name, nda_at, now),
            )
            self.store.append_event(
                deal_id, "org_created", target_type="org", target_id=org_id,
                detail={"name": name, "nda_signed": nda_signed}, commit=False,
            )
            self.store.commit()
        return org_id

    def sign_nda(self, deal_id, org_id):
        with self.store.tx():
            self.store.execute(
                "UPDATE organizations SET nda_signed_at=? WHERE org_id=? AND deal_id=?",
                (self.store.now(), org_id, deal_id),
            )
            self.store.append_event(
                deal_id, "nda_signed", org_id=org_id,
                target_type="org", target_id=org_id, commit=False,
            )
            self.store.commit()

    def set_org_frozen(self, deal_id, org_id, frozen, reason):
        with self.store.tx():
            self.store.execute(
                "UPDATE organizations SET frozen=? WHERE org_id=? AND deal_id=?",
                (1 if frozen else 0, org_id, deal_id),
            )
            if frozen:
                self.store.execute(
                    "UPDATE sessions SET revoked=1 WHERE deal_id=? AND user_id IN "
                    "(SELECT user_id FROM access_grants WHERE deal_id=? AND org_id=?)",
                    (deal_id, deal_id, org_id),
                )
            self.store.append_event(
                deal_id, "org_frozen" if frozen else "org_unfrozen",
                org_id=org_id, target_type="org", target_id=org_id,
                detail={"reason": reason}, commit=False,
            )
            self.store.commit()

    # ---- 团队 / 用户 ----
    def create_team(self, deal_id, org_id, name, team_id=None):
        team_id = team_id or _id("TEAM")
        with self.store.tx():
            self.store.execute(
                "INSERT INTO teams(team_id,deal_id,org_id,name) VALUES(?,?,?,?)",
                (team_id, deal_id, org_id, name),
            )
            self.store.append_event(
                deal_id, "team_created", org_id=org_id,
                target_type="team", target_id=team_id, detail={"name": name},
                commit=False,
            )
            self.store.commit()
        return team_id

    def create_user(self, user_id, name):
        now = self.store.now()
        with self.store.tx():
            self.store.execute(
                "INSERT INTO users(user_id,name,active,created_at) VALUES(?,?,1,?)",
                (user_id, name, now),
            )
            self.store.commit()
        return user_id

    def deactivate_user(self, user_id, reason):
        """人员离职：跨所有交易立即阻断。"""
        deals = self.store.query(
            "SELECT DISTINCT deal_id FROM access_grants WHERE user_id=?", (user_id,)
        )
        with self.store.tx():
            self.store.execute(
                "UPDATE users SET active=0, deactivated_at=? WHERE user_id=?",
                (self.store.now(), user_id),
            )
            self.store.execute("UPDATE sessions SET revoked=1 WHERE user_id=?", (user_id,))
            for d in deals:
                self.store.append_event(
                    d["deal_id"], "user_deactivated", actor_user_id=user_id,
                    target_type="user", target_id=user_id,
                    detail={"reason": reason, "sessions_revoked": True}, commit=False,
                )
            self.store.commit()

    # ---- 授权（期限） ----
    def grant(self, deal_id, user_id, role, org_id=None, team_id=None,
              valid_from=FAR_PAST, valid_until=FAR_FUTURE):
        grant_id = _id("GRANT")
        with self.store.tx():
            self.store.execute(
                "INSERT INTO access_grants(grant_id,deal_id,org_id,team_id,user_id,"
                "role,valid_from,valid_until) VALUES(?,?,?,?,?,?,?,?)",
                (grant_id, deal_id, org_id, team_id, user_id, role, valid_from, valid_until),
            )
            self.store.append_event(
                deal_id, "grant_created", actor_user_id=user_id, org_id=org_id,
                target_type="grant", target_id=grant_id,
                detail={"role": role, "valid_from": valid_from,
                        "valid_until": valid_until}, commit=False,
            )
            self.store.commit()
        return grant_id

    def revoke_grant(self, deal_id, user_id=None, grant_id=None, role=None, reason=""):
        """撤权：立即阻断新查看，并吊销受影响会话。"""
        where = ["deal_id=?"]
        args = [deal_id]
        if grant_id:
            where.append("grant_id=?"); args.append(grant_id)
        if user_id:
            where.append("user_id=?"); args.append(user_id)
        if role:
            where.append("role=?"); args.append(role)
        sql = "SELECT grant_id, user_id, org_id FROM access_grants WHERE " + " AND ".join(where)
        rows = self.store.query(sql, tuple(args))
        with self.store.tx():
            ids = [r["grant_id"] for r in rows]
            affected_users = {r["user_id"] for r in rows}
            if ids:
                qmarks = ",".join("?" * len(ids))
                self.store.execute(
                    f"UPDATE access_grants SET revoked=1, revoked_at=? "
                    f"WHERE grant_id IN ({qmarks})",
                    (self.store.now(), *ids),
                )
                umarks = ",".join("?" * len(affected_users))
                self.store.execute(
                    f"UPDATE sessions SET revoked=1 WHERE deal_id=? "
                    f"AND user_id IN ({umarks})",
                    (deal_id, *affected_users),
                )
            for r in rows:
                self.store.append_event(
                    deal_id, "grant_revoked", actor_user_id=r["user_id"],
                    org_id=r["org_id"], target_type="grant", target_id=r["grant_id"],
                    detail={"reason": reason}, commit=False,
                )
            self.store.commit()
        return len(rows)

    # ---- 会话 ----
    def issue_session(self, deal_id, user_id):
        token = uuid.uuid4().hex
        now = self.store.now()
        with self.store.tx():
            self.store.execute(
                "INSERT INTO sessions(token,deal_id,user_id,created_at) VALUES(?,?,?,?)",
                (token, deal_id, user_id, now),
            )
            self.store.append_event(
                deal_id, "session_created", actor_user_id=user_id,
                target_type="session", target_id=token[:12], commit=False,
            )
            self.store.commit()
        return token

    def revoke_sessions(self, deal_id, user_id, reason):
        with self.store.tx():
            self.store.execute(
                "UPDATE sessions SET revoked=1 WHERE deal_id=? AND user_id=?",
                (deal_id, user_id),
            )
            self.store.append_event(
                deal_id, "session_revoked", actor_user_id=user_id,
                target_type="user", target_id=user_id,
                detail={"reason": reason}, commit=False,
            )
            self.store.commit()
