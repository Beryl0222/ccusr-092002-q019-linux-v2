"""受限问答：提问与答案只能引用提问方“当前有权查看”的版本；
法务与医学双重审核通过后才可发布，发布瞬间再次校验引用可见性。

问答按竞标方组织隔离：外部仅见本组织的问题与已发布答案。
"""

from . import models
from .errors import AccessDeniedError, NotFoundError, WorkflowStateError
from .security import utcnow_iso

REVIEW_KINDS = ("legal", "medical")
INTERNAL_ANSWER_ROLES = {"DEAL_LEAD", "ROOM_ADMIN"}
REVIEWER_ROLES = {"legal": "LEGAL", "medical": "MEDICAL"}


class QAService:
    def __init__(self, store, authz, audit):
        self.store = store
        self.authz = authz
        self.audit = audit

    # ----------------------------------------------------------- 校验
    def _question(self, q_id):
        q = self.store.state["questions"].get(q_id)
        if q is None:
            raise NotFoundError(f"问题不存在: {q_id}")
        return q

    def _validate_refs(self, asker_id, refs):
        """每个引用必须指向该用户当前可见的具体文档版本；返回规范化引用。"""
        if not refs:
            raise WorkflowStateError("问答必须至少引用一份当前可查看的材料")
        normalized = []
        docs = self.store.state["documents"]
        for ref in refs:
            doc = docs.get(ref["doc_id"])
            if doc is None:
                raise NotFoundError(f"引用文档不存在: {ref['doc_id']}")
            # visible_version 会实时执行 NDA/撤权/阶段/脱敏层级全部判定。
            self.authz.visible_version(asker_id, doc, ref["version_no"])
            normalized.append({"doc_id": doc["doc_id"], "version_no": ref["version_no"],
                               "fingerprint": doc["versions"][str(ref["version_no"])]["fingerprint"]})
        return normalized

    def _internal(self, user_id, deal_id, roles):
        decision = self.authz.require_deal_access(user_id, deal_id)
        if not decision.internal or not (set(roles) & decision.roles):
            raise AccessDeniedError("INTERNAL_ONLY", "需要内部相应角色")
        return decision

    # ----------------------------------------------------------- 提问
    def ask(self, asker_id, text, refs):
        user = self.store.state["users"][asker_id]
        decision = self.authz.require_deal_access(asker_id, user["deal_id"])
        if decision.internal:
            raise AccessDeniedError("EXTERNAL_ONLY", "问答由竞标方提出")
        normalized = self._validate_refs(asker_id, refs)
        with self.store.lock:
            q = models.new_question(user["deal_id"], user["org_id"], asker_id, text, normalized)
            self.store.state["questions"][q["q_id"]] = q
            self.store.commit()
            self.audit.log("QA_ASKED", deal_id=user["deal_id"], org_id=user["org_id"],
                           user_id=asker_id, q_id=q["q_id"],
                           refs=[f'{r["doc_id"]}@v{r["version_no"]}' for r in normalized])
            return self._view(q, internal=False)

    def draft_answer(self, user_id, q_id, answer, refs=None):
        with self.store.lock:
            q = self._question(q_id)
            self._internal(user_id, q["deal_id"], INTERNAL_ANSWER_ROLES)
            if q["status"] == models.Q_PUBLISHED:
                raise WorkflowStateError("答案已发布，不可修改")
            # 答案引用同样只能用提问方当前可见的版本。
            effective_refs = self._validate_refs(q["asker_id"], refs if refs is not None else q["refs"])
            q["answer"] = {"text": answer, "refs": effective_refs,
                           "drafted_by": user_id, "drafted_ts": utcnow_iso()}
            # 重新起草后重置双审状态。
            for kind in REVIEW_KINDS:
                q["reviews"][kind] = {"verdict": models.REVIEW_PENDING, "by": None,
                                      "ts": None, "comment": None}
            q["status"] = models.Q_SUBMITTED
            q["publish_blocked_reason"] = None
            self.store.commit()
            self.audit.log("QA_ANSWER_DRAFTED", deal_id=q["deal_id"], user_id=user_id,
                           q_id=q_id, refs=[f'{r["doc_id"]}@v{r["version_no"]}' for r in effective_refs])
            return self._view(q, internal=True)

    def review(self, user_id, q_id, kind, verdict, comment=None):
        if kind not in REVIEW_KINDS:
            raise NotFoundError(f"审核类型必须是 legal/medical: {kind}")
        with self.store.lock:
            q = self._question(q_id)
            self._internal(user_id, q["deal_id"], (REVIEWER_ROLES[kind],))
            if q["answer"] is None:
                raise WorkflowStateError("尚无答案草稿可审")
            if q["status"] == models.Q_PUBLISHED:
                raise WorkflowStateError("答案已发布")
            if verdict not in (models.REVIEW_APPROVED, models.REVIEW_REJECTED):
                raise WorkflowStateError("审核结论必须为 APPROVED/REJECTED")
            slot = q["reviews"][kind]
            slot.update({"verdict": verdict, "by": user_id,
                         "ts": utcnow_iso(), "comment": comment})
            if verdict == models.REVIEW_REJECTED:
                q["status"] = models.Q_REJECTED
            self.store.commit()
            self.audit.log(f"QA_REVIEW_{kind.upper()}", deal_id=q["deal_id"], user_id=user_id,
                           q_id=q_id, verdict=verdict, result=verdict)
            # 双审通过即尝试发布。
            if verdict == models.REVIEW_APPROVED and self._both_approved(q):
                self._try_publish(q, user_id)
            return self._view(q, internal=True)

    @staticmethod
    def _both_approved(q):
        return all(q["reviews"][k]["verdict"] == models.REVIEW_APPROVED for k in REVIEW_KINDS)

    def _try_publish(self, q, actor):
        """发布瞬间以授权层实时结论复核全部答案引用。"""
        reason = None
        try:
            self._validate_refs(q["asker_id"], q["answer"]["refs"])
        except (AccessDeniedError, NotFoundError) as exc:
            reason = f"{getattr(exc, 'code', 'ACCESS_DENIED')}: {exc}"
        if reason:
            q["publish_blocked_reason"] = reason
            self.audit.log("QA_PUBLISH_BLOCKED", deal_id=q["deal_id"], user_id=actor,
                           q_id=q["q_id"], result="DENIED", reason=reason)
            return False
        q["status"] = models.Q_PUBLISHED
        q["publish_blocked_reason"] = None
        q["published_ts"] = utcnow_iso()
        self.audit.log("QA_PUBLISHED", deal_id=q["deal_id"], user_id=actor, q_id=q["q_id"])
        return True

    def publish(self, user_id, q_id):
        """显式发布：用于双审通过但因撤权被阻断、恢复后再发布。"""
        with self.store.lock:
            q = self._question(q_id)
            self._internal(user_id, q["deal_id"], INTERNAL_ANSWER_ROLES)
            if not self._both_approved(q):
                raise WorkflowStateError("法务与医学双审尚未全部通过")
            if q["answer"] is None:
                raise WorkflowStateError("尚无答案")
            published = self._try_publish(q, user_id)
            self.store.commit()
            if not published:
                raise AccessDeniedError("PUBLISH_BLOCKED",
                                        f"引用已不可见，无法发布: {q['publish_blocked_reason']}")
            return self._view(q, internal=True)

    # ----------------------------------------------------------- 查询
    def list_for_user(self, user_id):
        user = self.store.state["users"][user_id]
        result = []
        for q in self.store.state["questions"].values():
            if q["deal_id"] != user["deal_id"]:
                continue
            org = self.store.state["orgs"][user["org_id"]]
            internal = org["kind"] == models.ORG_INTERNAL
            if not internal and q["org_id"] != user["org_id"]:
                continue  # 竞标方互不可见
            view = self._view(q, internal=internal)
            if not internal and q["status"] != models.Q_PUBLISHED:
                # 竞标方可见自己问题的处理状态，但未发布时不展示答案正文。
                view["answer"] = None
            result.append(view)
        return result

    def get(self, user_id, q_id):
        q = self._question(q_id)
        user = self.store.state["users"][user_id]
        org = self.store.state["orgs"][user["org_id"]]
        internal = org["kind"] == models.ORG_INTERNAL
        self.authz.require_deal_access(user_id, q["deal_id"])
        if not internal and q["org_id"] != user["org_id"]:
            raise AccessDeniedError("CROSS_ORG", "不可查看其他竞标方的问答")
        view = self._view(q, internal=internal)
        if not internal and q["status"] != models.Q_PUBLISHED:
            view["answer"] = None
        return view

    @staticmethod
    def _view(q, internal):
        view = {
            "q_id": q["q_id"], "deal_id": q["deal_id"], "org_id": q["org_id"],
            "asker_id": q["asker_id"], "text": q["text"], "refs": list(q["refs"]),
            "status": q["status"], "created_ts": q["created_ts"],
            "published_ts": q.get("published_ts"),
            "publish_blocked_reason": q.get("publish_blocked_reason"),
            "reviews": q["reviews"] if internal else None,
            "answer": q["answer"],
        }
        return view
