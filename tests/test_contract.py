"""核对服务身份和领域样例。"""

import json
import unittest
from pathlib import Path

from service import SERVICE_ID, health_payload


class ContractTest(unittest.TestCase):
    def test_service_identity(self):
        self.assertEqual(health_payload()["service"], SERVICE_ID)

    def test_domain_sample(self):
        data = json.loads(Path("contracts/diligence_document.json").read_text(encoding="utf-8"))
        self.assertEqual(data["service"], SERVICE_ID)
        self.assertTrue(data["sample"])


if __name__ == "__main__":
    unittest.main()
