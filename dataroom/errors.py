"""受控资料室领域错误。"""


class DomainError(Exception):
    """所有可预期的业务拒绝，携带机器可读 code 与 HTTP 状态。"""

    def __init__(self, code, message, http_status=400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status


class NotFound(DomainError):
    def __init__(self, message="资源不存在"):
        super().__init__("not_found", message, 404)


class Unauthorized(DomainError):
    def __init__(self, code="unauthorized", message="未认证", http_status=401):
        super().__init__(code, message, http_status)


class Forbidden(DomainError):
    def __init__(self, code="forbidden", message="无权访问", http_status=403):
        super().__init__(code, message, http_status)


class Conflict(DomainError):
    def __init__(self, code, message, http_status=409):
        super().__init__(code, message, http_status)
