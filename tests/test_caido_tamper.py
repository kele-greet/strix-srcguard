from __future__ import annotations

import unittest

from srcguard.caido_tamper_guard import SOURCE_VALUES, httpql_method


class CaidoTamperTests(unittest.TestCase):
    def test_httpql_uses_req_prefix(self) -> None:
        code = httpql_method({"DELETE"})
        self.assertEqual(code, 'req.method.eq:"DELETE"')

    def test_multiple_methods_are_ored(self) -> None:
        code = httpql_method({"DELETE", "TRACE"})
        self.assertIn('req.method.eq:"DELETE"', code)
        self.assertIn('req.method.eq:"TRACE"', code)
        self.assertIn(" or ", code)

    def test_sources_are_limited_to_working_caido_values(self) -> None:
        self.assertEqual(SOURCE_VALUES, ["INTERCEPT", "REPLAY", "AUTOMATE"])


if __name__ == "__main__":
    unittest.main()
