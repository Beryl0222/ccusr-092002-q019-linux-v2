"""领域实体工厂与状态机常量。所有时间统一 UTC ISO-8601 字符串。"""

from .security import short_id, utcnow_iso

# 交易与主体状态
DEAL_ACTIVE = "ACTIVE"
DEAL_TERMINATED = "TERMINATED"

ORG_INTERNAL = "INTERNAL"
ORG_BIDDER = "BIDDER"

USER_ACTIVE = "ACTIVE"
USER_OFFBOARDED = "OFFBOARDED"

GRANT_ACTIVE = "ACTIVE"
GRANT_REVOKED = "REVOKED"

# 文档与版本状态
DOC_ACTIVE = "ACTIVE"
DOC_WITHDRAWN = "WITHDRAWN"

SCAN_PENDING = "PENDING"
SCAN_CLEAN = "CLEAN"
SCAN_INFECTED = "INFECTED"

# 脱敏层级
TIER_ORIGINAL = "ORIGINAL"
TIER_STANDARD = "STANDARD"
TIER_AGGREGATED = "AGGREGATED"
EXTERNAL_TIERS = {TIER_STANDARD, TIER_AGGREGATED}

# 上传/导出会话
US_INIT = "INIT"
US_UPLOADING = "UPLOADING"
US_ASSEMBLED = "ASSEMBLED"
US_ABORTED = "ABORTED"

EXPORT_ACTIVE = "ACTIVE"
EXPORT_COMPLETED = "COMPLETED"
EXPORT_INTERRUPTED = "INTERRUPTED"

# 问答状态
Q_SUBMITTED = "SUBMITTED"
Q_PUBLISHED = "PUBLISHED"
Q_REJECTED = "REJECTED"

REVIEW_PENDING = "PENDING"
REVIEW_APPROVED = "APPROVED"
REVIEW_REJECTED = "REJECTED"

# 事件状态
INC_OPEN = "OPEN"
INC_CONTAINED = "CONTAINED"
INC_RESOLVED = "RESOLVED"


def new_deal(name, created_by):
    return {
        "deal_id": short_id("DEAL"),
        "name": name,
        "phase": 1,
        "status": DEAL_ACTIVE,
        "created_by": created_by,
        "created_ts": utcnow_iso(),
        "terminated_ts": None,
        "terminate_reason": None,
    }


def new_org(deal_id, name, kind):
    return {
        "org_id": short_id("ORG"),
        "deal_id": deal_id,
        "name": name,
        "kind": kind,
        "status": "ACTIVE",
        "created_ts": utcnow_iso(),
    }


def new_user(org_id, deal_id, name, email, roles, teams=None):
    return {
        "user_id": short_id("USR"),
        "org_id": org_id,
        "deal_id": deal_id,
        "name": name,
        "email": email,
        "roles": list(roles),
        "teams": list(teams or []),
        "status": USER_ACTIVE,
        "nda_signed": False,
        "nda_ts": None,
        "suspended": False,
        "suspend_reason": None,
        "created_ts": utcnow_iso(),
        "offboarded_ts": None,
    }


def new_grant(deal_id, scope, subject_id, role, valid_from=None, valid_until=None, categories=None):
    """scope: DEAL / ORG / TEAM / USER。subject_id 对应交易、组织、团队或用户。"""
    return {
        "grant_id": short_id("GRT"),
        "deal_id": deal_id,
        "scope": scope,
        "subject_id": subject_id,
        "role": role,
        "categories": list(categories) if categories else None,
        "valid_from": valid_from or utcnow_iso(),
        "valid_until": valid_until,
        "status": GRANT_ACTIVE,
        "created_ts": utcnow_iso(),
        "revoked_ts": None,
        "revoked_reason": None,
    }


def new_team(org_id, name):
    return {"team_id": short_id("TEAM"), "org_id": org_id, "name": name, "created_ts": utcnow_iso()}


def new_document(deal_id, title, category, sensitivity, created_by):
    return {
        "doc_id": short_id("DOC"),
        "deal_id": deal_id,
        "title": title,
        "category": category,
        "sensitivity": sensitivity,
        "status": DOC_ACTIVE,
        "latest_version": 0,
        "created_by": created_by,
        "created_ts": utcnow_iso(),
        "withdrawn_ts": None,
        "versions": {},
    }


def new_version(version_no, fingerprint, size, filename, tier, uploaded_by,
                parent_version_no=None, scan_status=SCAN_PENDING):
    return {
        "version_no": version_no,
        "fingerprint": fingerprint,
        "size": size,
        "filename": filename,
        "tier": tier,
        "parent_version_no": parent_version_no,
        "children": [],
        "scan_status": scan_status,
        "scanned_ts": None,
        "uploaded_by": uploaded_by,
        "uploaded_ts": utcnow_iso(),
    }


def new_question(deal_id, org_id, asker_id, text, refs):
    return {
        "q_id": short_id("Q"),
        "deal_id": deal_id,
        "org_id": org_id,
        "asker_id": asker_id,
        "text": text,
        "refs": list(refs),
        "status": Q_SUBMITTED,
        "created_ts": utcnow_iso(),
        "answer": None,
        "reviews": {
            "legal": {"verdict": REVIEW_PENDING, "by": None, "ts": None, "comment": None},
            "medical": {"verdict": REVIEW_PENDING, "by": None, "ts": None, "comment": None},
        },
        "publish_blocked_reason": None,
        "published_ts": None,
    }
