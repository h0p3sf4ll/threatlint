"""Functional tests for the sample shop, run against the deployed app (APP_URL) or in-process."""
import json
import os
import sys
import threading
import unittest
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class SampleShopTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = os.environ.get("APP_URL", "")
        if not cls.base:
            import app
            from http.server import ThreadingHTTPServer
            cls.server = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
            threading.Thread(target=cls.server.serve_forever, daemon=True).start()
            cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    def get(self, path):
        with urllib.request.urlopen(self.base + path, timeout=10) as response:
            return response.status, response.read().decode()

    def test_health(self):
        self.assertEqual(self.get("/health"), (200, '{"status": "ok"}'))

    def test_search_page(self):
        status, body = self.get("/search?q=kettle")
        self.assertEqual(status, 200)
        self.assertIn("Results for kettle", body)

    def test_greet(self):
        self.assertIn("Hello, Ada!", self.get("/greet?name=Ada")[1])

    def test_product_lookup(self):
        self.assertEqual(json.loads(self.get("/product?id=2")[1]), [{"id": 2, "name": "teapot"}])


if __name__ == "__main__":
    unittest.main()
