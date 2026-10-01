"""安全基础工具：指纹、水印码、随机令牌、原子写入、时间源。

指纹采用 SHA-256；每次预览/导出的唯一水印码使用密钥化 HMAC，
即使相同用户重复查看同一文档也各不相同，且可离线验证真伪。
"""

import hashlib
import hmac
import os
import secrets
import tempfile
from datetime import datetime, timezone


def utcnow():
    """统一的 UTC 时间源（naive UTC，便于 JSON 序列化）。"""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def utcnow_iso():
    return utcnow().isoformat(timespec="seconds") + "Z"


def sha256_fingerprint(content: bytes) -> str:
    """文档内容指纹（十六进制）。"""
    return hashlib.sha256(content).hexdigest()


def short_id(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(6).upper()}"


def new_token(nbytes: int = 24) -> str:
    """入会/会话令牌，URL 安全随机串。"""
    return secrets.token_urlsafe(nbytes)


def watermark_code(secret: str, payload: str) -> str:
    """由水印密钥对负载（访问事件标识）生成可验证的唯一码。"""
    return hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()[:24].upper()


def verify_watermark(secret: str, payload: str, code: str) -> bool:
    return hmac.compare_digest(watermark_code(secret, payload), code)


def render_watermark(identity: dict) -> str:
    """生成叠加在预览/导出件上的可见水印文本。"""
    return (
        f"CONFIDENTIAL | {identity['deal']} | {identity['org']} | "
        f"{identity['user']} | {identity['when']} | {identity['code']}"
    )


def atomic_write(path, data: bytes):
    """同目录临时文件 + fsync + 原子替换，避免半截状态落盘。"""
    directory = os.path.dirname(os.fspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=directory)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, os.fspath(path))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
