"""分类法与常量：敏感级别、阶段门、角色矩阵（源自 contracts/diligence_document.json）。"""

from __future__ import annotations

import json
from pathlib import Path

# 材料类别
CAT_CLINICAL = "临床数据"
CAT_PATENT = "专利分析"
CAT_CMC = "生产工艺"
CAT_REGULATORY = "监管往来"
CATEGORIES = (CAT_CLINICAL, CAT_PATENT, CAT_CMC, CAT_REGULATORY)

# 敏感级别（级别越高越敏感，患者级最特殊：仅脱敏件可浏览）
SENS_PUBLIC = "公开"
SENS_GENERAL = "一般"
SENS_CONFIDENTIAL = "机密"
SENS_HIGH = "高敏"
SENS_PATIENT = "患者级"
SENSITIVITY_ORDER = {
    SENS_PUBLIC: 0,
    SENS_GENERAL: 1,
    SENS_CONFIDENTIAL: 2,
    SENS_HIGH: 3,
    SENS_PATIENT: 4,
}

# 阶段（材料从该阶段起开放；组织/交易处于同一或更靠后阶段才看得到）
PHASE_INITIAL = "初始披露"
PHASE_EXTENDED = "扩展尽调"
PHASE_DETAILED = "详细尽调"
PHASE_QA = "开放问答"
PHASE_DONE = "完成"
PHASES = (PHASE_INITIAL, PHASE_EXTENDED, PHASE_DETAILED, PHASE_QA, PHASE_DONE)

# 角色
ROLE_OBSERVER = "观察方"
ROLE_TECH_DD = "技术尽调"
ROLE_LEGAL_DD = "法律尽调"
ROLE_MEDICAL_DD = "医学尽调"
ROLE_QA_EDITOR = "问答编辑"
ROLE_DEAL_OWNER = "交易负责人"
ROLE_DEAL_ADMIN = "交易管理员"
ROLE_LEGAL_REVIEW = "法务审核"
ROLE_MEDICAL_REVIEW = "医学审核"
BIDDER_ROLES = {ROLE_TECH_DD, ROLE_LEGAL_DD, ROLE_MEDICAL_DD, ROLE_QA_EDITOR, ROLE_OBSERVER}
INTERNAL_ROLES = {ROLE_DEAL_OWNER, ROLE_DEAL_ADMIN, ROLE_LEGAL_REVIEW, ROLE_MEDICAL_REVIEW}

# 角色可接触的最高敏感级别（患者级只给医学尽调且仅限脱敏件）
ROLE_MAX_SENSITIVITY = {
    ROLE_OBSERVER: SENS_PUBLIC,
    ROLE_QA_EDITOR: SENS_GENERAL,
    ROLE_TECH_DD: SENS_HIGH,
    ROLE_LEGAL_DD: SENS_HIGH,
    ROLE_MEDICAL_DD: SENS_PATIENT,
    ROLE_DEAL_OWNER: SENS_PATIENT,
    ROLE_DEAL_ADMIN: 5,  # 数值 5 = 通配，包含患者级
    ROLE_LEGAL_REVIEW: 5,
    ROLE_MEDICAL_REVIEW: 5,
}

# 默认阶段门：交易阶段必须达到该敏感级别的要求
PHASE_REQUIRED_SENSITIVITY = {
    SENS_PUBLIC: PHASE_INITIAL,
    SENS_GENERAL: PHASE_INITIAL,
    SENS_CONFIDENTIAL: PHASE_EXTENDED,
    SENS_HIGH: PHASE_DETAILED,
    SENS_PATIENT: PHASE_DETAILED,
}

PATIENT_LEVEL_CAN_VIEW_ORIGINAL = {ROLE_DEAL_OWNER, ROLE_DEAL_ADMIN}

# 文档状态
DOC_AVAILABLE = "available"
DOC_QUARANTINED = "quarantined"  # 病毒扫描失败
DOC_WITHDRAWN = "withdrawn"      # 撤回（交易终止等）

# 下载会话状态
DL_OPEN = "open"
DL_COMPLETED = "completed"
DL_INTERRUPTED = "interrupted"
DL_REVOKED = "revoked"

# 问答状态机
QA_DRAFT = "draft"            # 提问方创建，等待答复
QA_ANSWERED = "answered"      # 已提交答案，等待双审
QA_APPROVED = "approved"      # 双审通过，待发布
QA_PUBLISHED = "published"    # 已发布，对该组织可见
QA_REJECTED = "rejected"

# 安全事件
EVT_BULK_ANOMALY = "bulk_access_anomaly"
EVT_LEAK = "suspected_leak"
INC_OPEN = "open"
INC_REMEDIATED = "remediated"
INC_CLOSED = "closed"


def load_contract_taxonomy(path: str | Path | None = None) -> dict:
    """读取 contracts/diligence_document.json，供启动时校验代码内分类法一致。"""
    root = Path(__file__).resolve().parent.parent
    p = Path(path) if path else root / "contracts" / "diligence_document.json"
    return json.loads(p.read_text(encoding="utf-8"))
