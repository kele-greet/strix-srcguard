from __future__ import annotations

import unittest

from srcguard.method_guard import blocked_method, post_violation


class MethodGuardTests(unittest.TestCase):
    def test_detects_common_curl_forms(self) -> None:
        for cmd in (
            "curl -X DELETE http://target/",
            "curl -XDELETE http://target/",
            "curl --request DELETE http://target/",
            "curl --request=DELETE http://target/",
            "curl -X 'DELETE' http://target/",
        ):
            self.assertEqual(blocked_method(cmd, {"DELETE"}), "DELETE", cmd)

    def test_does_not_block_get_or_post(self) -> None:
        self.assertIsNone(blocked_method("curl -X GET http://target/", {"DELETE"}))
        self.assertIsNone(blocked_method("curl -X POST http://target/", {"DELETE"}))
        self.assertIsNone(blocked_method("echo 'DELETE'", {"DELETE"}))

    def test_respects_policy_set(self) -> None:
        self.assertEqual(blocked_method("curl -X TRACE http://x/", {"TRACE"}), "TRACE")
        self.assertIsNone(blocked_method("curl -X TRACE http://x/", {"DELETE"}))
        self.assertIsNone(blocked_method("curl -X DELETE http://x/", set()))


class PostPathGuardTests(unittest.TestCase):
    def test_allowed_post_path_passes(self) -> None:
        cmd = (
            "curl -s -X POST 'https://www.example.com/search/queryPage' "
            "-H 'Content-Type: application/json' --data '{\"keyWord\":\"x\"}'"
        )
        self.assertIsNone(post_violation(cmd, allow_paths=("/search/",)))

    def test_post_outside_allowlist_is_blocked(self) -> None:
        cmd = "curl -X POST https://www.example.com/admin/delete --data 'id=1'"
        self.assertIn("not allowed", post_violation(cmd, allow_paths=("/search/",)))

    def test_denied_path_wins_over_allowlist(self) -> None:
        cmd = "curl -X POST https://www.example.com/search/manage/save -d 'x=1'"
        reason = post_violation(cmd, allow_paths=("/search/",), deny_paths=("/search/manage/",))
        self.assertIn("denied path", reason)

    def test_post_without_url_is_blocked(self) -> None:
        self.assertIsNotNone(post_violation("curl -X POST -d 'x=1'", allow_paths=("/search/",)))

    def test_dot_segments_and_encoding_cannot_escape_the_allowlist(self) -> None:
        allow = ("/aop_component//webber/search/",)
        for url in (
            "https://www.example.edu.cn/aop_component//webber/search/../../manage/x",
            "https://www.example.edu.cn/aop_component//webber/search/%2e%2e/%2e%2e/manage/x",
            "https://www.example.edu.cn/aop_component//webber/search/%252e%252e/%252e%252e/manage/x",
        ):
            cmd = f"curl -X POST '{url}' -d '{{}}'"
            self.assertIn("not allowed", post_violation(cmd, allow_paths=allow), url)

    def test_wget_post_data_is_checked(self) -> None:
        cmd = "wget --post-data='a=1' 'https://www.example.edu.cn/admin/x'"
        self.assertIn("not allowed", post_violation(cmd, allow_paths=("/search/",)))

    def test_get_is_not_affected(self) -> None:
        self.assertIsNone(post_violation("curl https://www.example.com/admin", allow_paths=("/search/",)))
        self.assertIsNone(post_violation("curl -X GET https://www.example.com/admin", allow_paths=("/search/",)))


if __name__ == "__main__":
    unittest.main()
