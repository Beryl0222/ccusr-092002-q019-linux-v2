"""受控问答。

- 提问与答案的每条引用都必须是「提问方此刻有权查看」的具体文档版本：
  提交答案时校验一次，发布前再校验一次——期间撤权/离职/交易终止/
  阶段调整会让引用失效，发布被拒绝；
- 答案必须经法务、医学两名不同审核人分别批准，才能发布；
- 竞标方只能读到本组织、已发布的问答；内部可见全量与状态。
"""

from __future__ import annotations

import json
import uuid

from . import taxonomy as T
from .errors import DomainError, Forbidden, NotFound
from .policy import Context, Policy
from .store import Store


def _qid():
    return f"QA-{uuid.uuid4().hex[:12]}"


class QAService:
    def __init__(self, store: Store, policy: Policy):
        self.store = store
        self.policy = policy

    # ---- 引用校验：以提问方身份判定 ----
    def _validate_citations_for_asker(self, deal_id, asker_id, citations):
        asker_ctx = self.policy.context_for_user(deal_id, asker_id)
        resolved = []
        for doc_id, version_id in citations:
            v = self.store.query_one(
                "SELECT * FROM document_versions WHERE version_id=?", (version_id,)
            )
            if v is None or v["doc_id"] != doc_id:
                raise DomainError("bad_citation", f"引用不存在或版本不匹配: {doc_id}")
            doc = self.store.query_one(
                "SELECT * FROM documents WHERE doc_id=? AND deal_id=?",
                (doc_id, deal_id),
            )
            if doc is None:
                raise DomainError("bad_citation", f"引用文档不属于本交易: {doc_id}")
            # 以提问方权限判定；患者级原件等在此被拦截
            self.policy.can_view_version(asker_ctx, doc, v, action="preview")
            resolved.append([doc_id, version_id])
        return resolved

    # ---- 提问 ----
    def ask(self, ctx: Context, text, citations=None):
        if ctx.internal:
            raise Forbidden("bidder_only", "只有竞标方可以提问")
        citations = citations or []
        # 提问自带的引用同样必须是其当前可见的
        self._validate_citations_for_asker(ctx.deal_id, ctx.user_id, citations)
        qa_id = _qid()
        now = self.store.now()
        with self.store.tx():
            self.store.execute(
                "INSERT INTO questions(qa_id,deal_id,org_id,asked_by,question_text,"
                "status,created_at) VALUES(?,?,?,?,?,?,?)",
                (qa_id, ctx.deal_id, ctx.org_id, ctx.user_id, text, T.QA_DRAFT, now),
            )
            self.store.append_event(
                ctx.deal_id, "qa_asked", actor_user_id=ctx.user_id, org_id=ctx.org_id,
                target_type="qa", target_id=qa_id,
                detail={"citations": citations}, commit=False,
            )
            self.store.commit()
        return qa_id

    # ---- 答复（内部）----
    def answer(self, ctx: Context, qa_id, text, citations):
        qa = self._get(qa_id)
        self.policy.assert_deal_scope(ctx, qa["deal_id"])
        if not ctx.internal:
            raise Forbidden("internal_only", "只有内部人员可以答复")
        if qa["status"] not in (T.QA_DRAFT, T.QA_REJECTED):
            raise DomainError("qa_not_answerable",
                              f"问答状态 {qa['status']} 不可答复", 409)
        # 以提问方身份校验答案引用：只能引用其当前有权查看的内容
        resolved = self._validate_citations_for_asker(
            qa["deal_id"], qa["asked_by"], citations
        )
        now = self.store.now()
        with self.store.tx():
            self.store.execute(
                "UPDATE questions SET answer_text=?, answer_citations=?, answered_by=?,"
                "answered_at=?, status=?, reject_reason=NULL,"
                "legal_approver=NULL,legal_approved_at=NULL,"
                "medical_approver=NULL,medical_approved_at=NULL,published_at=NULL "
                "WHERE qa_id=?",
                (text, json.dumps(resolved, ensure_ascii=False), ctx.user_id, now,
                 T.QA_ANSWERED, qa_id),
            )
            self.store.append_event(
                ctx.deal_id, "qa_answered", actor_user_id=ctx.user_id,
                target_type="qa", target_id=qa_id,
                detail={"citations": resolved}, commit=False,
            )
            self.store.commit()
        return qa_id

    # ---- 双审 ----
    def _approve(self, ctx, qa_id, which_role, column_user, column_ts, event, already_col):
        qa = self._get(qa_id)
        self.policy.assert_deal_scope(ctx, qa["deal_id"])
        if not ctx.has_role(which_role):
            raise Forbidden("approver_role_required", f"需要 {which_role} 角色")
        if qa["status"] not in (T.QA_ANSWERED, T.QA_APPROVED):
            raise DomainError("qa_not_in_review", "答案尚未提交或已定稿", 409)
        other = qa["medical_approver"] if column_user == "legal_approver" else qa["legal_approver"]
        if other and other == ctx.user_id:
            raise Forbidden("dual_approval_distinct_persons",
                            "法务与医学审核必须由两名不同人员完成")
        if qa[already_col]:
            return qa_id  # 幂等
        now = self.store.now()
        with self.store.tx():
            self.store.execute(
                f"UPDATE questions SET {column_user}=?, {column_ts}=? WHERE qa_id=?",
                (ctx.user_id, now, qa_id),
            )
            row = self.store.query_one("SELECT * FROM questions WHERE qa_id=?", (qa_id,))
            new_status = T.QA_APPROVED if (row["legal_approver"] and row["medical_approver"]) \
                else T.QA_ANSWERED
            self.store.execute(
                "UPDATE questions SET status=? WHERE qa_id=?", (new_status, qa_id)
            )
            self.store.append_event(
                ctx.deal_id, event, actor_user_id=ctx.user_id,
                target_type="qa", target_id=qa_id,
                detail={"new_status": new_status}, commit=False,
            )
            self.store.commit()
        return qa_id

    def approve_legal(self, ctx, qa_id):
        return self._approve(ctx, qa_id, T.ROLE_LEGAL_REVIEW,
                             "legal_approver", "legal_approved_at",
                             "qa_legal_approved", "legal_approver")

    def approve_medical(self, ctx, qa_id):
        return self._approve(ctx, qa_id, T.ROLE_MEDICAL_REVIEW,
                             "medical_approver", "medical_approved_at",
                             "qa_medical_approved", "medical_approver")

    def reject(self, ctx, qa_id, reason):
        qa = self._get(qa_id)
        self.policy.assert_deal_scope(ctx, qa["deal_id"])
        if not (ctx.has_role(T.ROLE_LEGAL_REVIEW) or ctx.has_role(T.ROLE_MEDICAL_REVIEW)):
            raise Forbidden("approver_role_required", "需要法务或医学审核角色")
        with self.store.tx():
            self.store.execute(
                "UPDATE questions SET status=?, reject_reason=? WHERE qa_id=?",
                (T.QA_REJECTED, reason, qa_id),
            )
            self.store.append_event(
                ctx.deal_id, "qa_rejected", actor_user_id=ctx.user_id,
                target_type="qa", target_id=qa_id, detail={"reason": reason},
                commit=False,
            )
            self.store.commit()
        return qa_id

    # ---- 发布：双审齐备 + 发布前再次按提问方现权校验引用 ----
    def publish(self, ctx: Context, qa_id):
        qa = self._get(qa_id)
        self.policy.assert_deal_scope(ctx, qa["deal_id"])
        if not ctx.internal:
            raise Forbidden("internal_only", "只有内部人员可以发布")
        if not (qa["legal_approver"] and qa["medical_approver"]):
            raise Forbidden("dual_approval_required",
                            "法务与医学共同审核通过后才能发布")
        if qa["legal_approver"] == qa["medical_approver"]:
            raise Forbidden("dual_approval_distinct_persons",
                            "两名审核人不得为同一人")
        citations = json.loads(qa["answer_citations"] or "[]")
        # 发布前第二道校验：期间撤权/阶段变化会在此暴露
        self._validate_citations_for_asker(qa["deal_id"], qa["asked_by"], citations)
        now = self.store.now()
        with self.store.tx():
            self.store.execute(
                "UPDATE questions SET status=?, published_at=? WHERE qa_id=?",
                (T.QA_PUBLISHED, now, qa_id),
            )
            self.store.append_event(
                ctx.deal_id, "qa_published", actor_user_id=ctx.user_id,
                org_id=qa["org_id"], target_type="qa", target_id=qa_id,
                detail={"citations": citations}, commit=False,
            )
            self.store.commit()
        return qa_id

    # ---- 读取 ----
    def _get(self, qa_id):
        qa = self.store.query_one("SELECT * FROM questions WHERE qa_id=?", (qa_id,))
        if qa is None:
            raise NotFound("问答不存在")
        return qa

    def read(self, ctx: Context, qa_id):
        qa = self._get(qa_id)
        if not self.policy.can_see_qa(ctx, qa):
            raise Forbidden("qa_not_visible", "该问答对当前身份不可见")
        return qa

    def list_for(self, ctx: Context):
        if ctx.internal:
            return self.store.query(
                "SELECT * FROM questions WHERE deal_id=? ORDER BY created_at",
                (ctx.deal_id,),
            )
        return self.store.query(
            "SELECT * FROM questions WHERE deal_id=? AND org_id=? AND status=? "
            "ORDER BY published_at",
            (ctx.deal_id, ctx.org_id, T.QA_PUBLISHED),
        )
