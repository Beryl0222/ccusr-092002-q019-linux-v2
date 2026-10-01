"""加载 contracts/diligence_document.json 中的领域约定。"""

import json
from functools import lru_cache
from pathlib import Path

_CONTRACT_PATH = Path(__file__).resolve().parent.parent / "contracts" / "diligence_document.json"

# 敏感级别序数，越大越敏感，用于阶段上限比较。
SENSITIVITY_ORDER = {"L1": 1, "L2": 2, "L3": 3, "L4": 4}


@lru_cache(maxsize=1)
def load_contract():
    """读取并缓存领域契约（材料分类、敏感级别、角色、阶段门）。"""
    data = json.loads(_CONTRACT_PATH.read_text(encoding="utf-8"))
    return data


def categories():
    return {c["code"]: c for c in load_contract()["material_categories"]}


def sensitivity_levels():
    return {s["code"]: s for s in load_contract()["sensitivity_levels"]}


def redaction_tiers():
    return {t["code"]: t for t in load_contract()["redaction_tiers"]}


def roles():
    return {r["code"]: r for r in load_contract()["roles"]}


def phase_gates():
    return {g["phase"]: g for g in load_contract()["phase_gates"]}


def default_role_rules():
    return load_contract()["default_role_rules"]


def validate_category(code):
    if code not in categories():
        raise ValueError(f"未知材料分类: {code}")
    return code


def validate_sensitivity(code):
    if code not in sensitivity_levels():
        raise ValueError(f"未知敏感级别: {code}")
    return code


def validate_role(code):
    if code not in roles():
        raise ValueError(f"未知角色: {code}")
    return code


def validate_redaction_tier(code):
    if code not in redaction_tiers():
        raise ValueError(f"未知脱敏层级: {code}")
    return code


def sensitivity_rank(code):
    return SENSITIVITY_ORDER[code]
