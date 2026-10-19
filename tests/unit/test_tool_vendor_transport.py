"""Transport DATA parser/redirect tests only; NO sockets/TLS/live transfer."""
import io
import time
import unittest

from mobile_release._tool_acquisition_spec import AcquisitionError
from mobile_release._tool_vendor_transport import PublicVendorTransfer, read_head, redirect_target


class ToolVendorTransportTests(unittest.TestCase):
    def head(self, data):
        calls = []
        result = read_head(io.BytesIO(data).readline, lambda: calls.append(None))
        self.assertGreater(len(calls), 0)
        return result

    def test_exact_length_and_no_implicit_decoding(self):
        value = self.head(b"HTTP/1.1 200 OK\r\nContent-Length: 123\r\nContent-Encoding: identity\r\n\r\n")
        self.assertEqual((value.status, value.length, value.location), (200, 123, None))

    def test_duplicate_length_te_gzip_folding_lf_and_oversized_fields_refuse(self):
        for fields in (b"Content-Length: 1\r\nContent-Length: 1\r\n", b"Transfer-Encoding: chunked\r\n",
                       b"Content-Encoding: gzip\r\n", b" Content-Length: 1\r\n", b"Content-Length: +1\r\n",
                       b"Content-Length: 1, 1\r\n", b"X: " + b"a" * 8192 + b"\r\n", b"X: y\r\n" * 65,
                       b"Location: https://example.invalid\r\nLocation: https://example.invalid\r\n"):
            with self.subTest(fields=fields[:45]), self.assertRaises(AcquisitionError):
                self.head(b"HTTP/1.1 200 OK\r\n" + fields + b"\r\n")
        with self.assertRaises(AcquisitionError):
            self.head(b"HTTP/1.1 200 OK\n\n")

    def test_only_one_exact_github_release_assets_redirect_without_credential_forwarding(self):
        location = "https://release-assets.githubusercontent.com/github-production-release-asset/123/abc-def?synthetic=value"
        self.assertEqual(redirect_target("github.com", location, 0),
            ("release-assets.githubusercontent.com", "/github-production-release-asset/123/abc-def?synthetic=value"))
        for host, target, count in (("dl.google.com", location, 0), ("github.com", location, 1),
            ("github.com", location.replace("https:", "http:"), 0),
            ("github.com", location.replace("release-assets.githubusercontent.com", "release-assets.githubusercontent.com.evil.invalid"), 0),
            ("github.com", location.replace("https://", "https://user:pass@"), 0),
            ("github.com", location.replace("123/abc-def", "../abc-def"), 0),
            ("github.com", location.replace("123/abc-def", "%2e%2e/abc-def"), 0),
            ("github.com", location.replace("123/abc-def", "123%2fabc-def"), 0),
            ("github.com", location + "#fragment", 0),
            ("github.com", location.replace(".com/", ".com:444/"), 0),
            ("github.com", "/relative", 0)):
            with self.subTest(target=target), self.assertRaises(AcquisitionError):
                redirect_target(host, target, count)

    def test_constructor_is_acquisition_free_and_rejects_bad_profile_ca_or_deadline(self):
        transfer = PublicVendorTransfer(profile="macos-arm64", ca_pem=b"synthetic not loaded here",
            deadline=time.monotonic() + 30, checkpoint=lambda: None)
        self.assertEqual(transfer.originals, [])
        self.assertEqual(transfer.used, set())
        for fields in ({"profile": "linux-x64"}, {"ca_pem": b""}, {"ca_pem": b"x" * (512 * 1024 + 1)},
                       {"deadline": float("nan")}, {"deadline": time.monotonic() + 3600}):
            args = dict(profile="macos-arm64", ca_pem=b"synthetic", deadline=time.monotonic() + 30, checkpoint=lambda: None)
            args.update(fields)
            with self.assertRaises(AcquisitionError):
                PublicVendorTransfer(**args)


if __name__ == "__main__":
    unittest.main()
