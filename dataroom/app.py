"""应用门面：组合存储、策略与各领域服务。"""

from __future__ import annotations

from pathlib import Path

from .access import Access
from .documents import Documents
from .forensics import Forensics
from .policy import Policy
from .provisioning import Provisioning
from .qa import QAService
from .security import Security
from .store import Store


class DataRoom:
    def __init__(self, db_path="data/dataroom.db", blob_dir="data/blobs",
                 bulk_window=60, bulk_threshold=8):
        self.store = Store(db_path, blob_dir)
        self.policy = Policy(self.store)
        self.provisioning = Provisioning(self.store)
        self.documents = Documents(self.store)
        self.access = Access(self.store, self.policy)
        self.qa = QAService(self.store, self.policy)
        self.security = Security(self.store, bulk_window, bulk_threshold)
        self.forensics = Forensics(self.store)

    # 便捷封装：查看后喂给异常检测器
    def preview(self, ctx, version_id):
        res = self.access.preview(ctx, version_id)
        self.security.note_access(ctx.deal_id, ctx.user_id, ctx.org_id, res["doc_id"])
        return res

    def start_export(self, ctx, version_id):
        res = self.access.start_export(ctx, version_id)
        # 导出生成时即记一次接触（同一文档续传不重复计数）
        v = self.store.query_one(
            "SELECT doc_id FROM document_versions WHERE version_id=?", (version_id,)
        )
        self.security.note_access(ctx.deal_id, ctx.user_id, ctx.org_id, v["doc_id"])
        return res

    def read_chunk(self, ctx, download_id, max_chunk=1 << 20, start=None, end=None):
        return self.access.read_chunk(ctx, download_id, max_chunk,
                                      start=start, end=end)

    def context(self, token):
        return self.policy.context(token)

    def verify_chain(self, deal_id):
        return self.store.verify_chain(deal_id)

    def close(self):
        self.store.close()
