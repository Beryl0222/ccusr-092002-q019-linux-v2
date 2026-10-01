"""领域错误类型。每个错误携带稳定的原因码，便于审计与 API 映射。"""


class DataRoomError(Exception):
    """所有受控资料室错误的基类。"""

    code = "DATA_ROOM_ERROR"
    http_status = 400

    def __init__(self, message=None, **context):
        super().__init__(message or self.code)
        self.context = context

    def to_dict(self):
        return {"error": self.code, "message": str(self), "context": self.context}


class NotFoundError(DataRoomError):
    code = "NOT_FOUND"
    http_status = 404


class ConflictError(DataRoomError):
    code = "CONFLICT"
    http_status = 409


class VersionConflictError(ConflictError):
    """并发上传版本冲突（乐观锁失败），须持久化处置。"""

    code = "VERSION_CONFLICT"
    http_status = 409


class AccessDeniedError(DataRoomError):
    code = "ACCESS_DENIED"
    http_status = 403

    def __init__(self, reason, message=None, **context):
        context.setdefault("reason", reason)
        super().__init__(message or reason, **context)
        self.reason = reason


class NdaRequiredError(AccessDeniedError):
    code = "NDA_REQUIRED"

    def __init__(self):
        super().__init__("NDA_NOT_SIGNED", "保密协议尚未签署，访问被阻断")


class ScanFailureError(DataRoomError):
    code = "SCAN_REJECTED"
    http_status = 422


class WorkflowStateError(ConflictError):
    code = "WORKFLOW_STATE"


class RateLimitSuspended(AccessDeniedError):
    """异常批量访问触发的自动停权。"""

    code = "ACCESS_SUSPENDED_ANOMALY"
    http_status = 403
