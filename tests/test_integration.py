import unittest
import json
from app import create_app, db
from config import Config


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"


class WebVulnXIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.app = create_app(TestConfig)
        self.client = self.app.test_client()
        self.headers = {
            "X-WebVulnX-Key": TestConfig.BURP_API_KEY,
            "Content-Type": "application/json",
        }

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def test_status_endpoint_requires_api_key(self):
        res_unauth = self.client.get("/api/v1/status")
        self.assertEqual(res_unauth.status_code, 401)

        res_auth = self.client.get("/api/v1/status", headers=self.headers)
        self.assertEqual(res_auth.status_code, 200)
        data = res_auth.get_json()
        self.assertEqual(data["status"], "online")

    def test_scope_blocks_external_urls(self):
        payload = {
            "method": "GET",
            "url": "https://example.com/login",
            "request_headers": {},
            "status_code": 200,
            "response_headers": {},
        }
        res = self.client.post("/api/v1/traffic", headers=self.headers, data=json.dumps(payload))
        self.assertEqual(res.status_code, 403)

    def test_traffic_ingestion_analysis_and_reports(self):
        payload = {
            "method": "GET",
            "url": "http://127.0.0.1:3000/rest/products/search?q=apple",
            "request_headers": {"Authorization": "Bearer super_secret_jwt"},
            "status_code": 200,
            "response_headers": {"Server": "Express", "Content-Type": "application/json"},
            "response_body": "{\"status\":\"success\"}",
        }
        res = self.client.post("/api/v1/traffic", headers=self.headers, data=json.dumps(payload))
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.assertGreater(data["new_findings"], 0)

        # Verify PDF and HTML report generation
        pdf_res = self.client.get("/reports/1/pdf")
        self.assertEqual(pdf_res.status_code, 200)
        self.assertEqual(pdf_res.mimetype, "application/pdf")
        self.assertTrue(pdf_res.data.startswith(b"%PDF"))

        html_res = self.client.get("/reports/1/html")
        self.assertEqual(html_res.status_code, 200)
        self.assertIn(b"WebVulnX VAPT Assessment Report", html_res.data)


if __name__ == "__main__":
    unittest.main()
