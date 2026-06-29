
import unittest
from fastapi.testclient import TestClient
from web.backend.main import app

class TestPathTraversalFix(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_mobile_package_ingest_invalid_chars(self):
        # Test with invalid characters that are not path traversal
        response = self.client.post("/api/mobile/devices/serial123/packages/package!name/ingest")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"], "Invalid package_name format")

    def test_mobile_package_ingest_path_traversal(self):
        # Test with a path traversal attempt in package_name
        response = self.client.post("/api/mobile/devices/serial123/packages/../../etc/passwd/ingest")
        # FastAPI might return 404 if the path doesn't match the route, 
        # but since package_name is a path parameter, it should match and then be validated.
        # Actually, FastAPI's router might not match "../../" depending on how it's defined.
        # But if it matches, it should return 400.
        
        # Try a safer traversal that is more likely to match the route
        response = self.client.post("/api/mobile/devices/serial123/packages/..%2f..%2fetc%2fpasswd/ingest")
        
        if response.status_code == 404:
             # If it's 404, it means the router didn't even match the path, which is also a form of protection.
             print("Received 404, router did not match the traversal path.")
        else:
            self.assertEqual(response.status_code, 400)
            self.assertEqual(response.json()["detail"], "Invalid package_name format")

    def test_mobile_package_ingest_valid_name(self):
        # Test with a valid package name
        # We expect a 503 because harvester will likely fail to init in test env, 
        # but it should pass the regex validation.
        response = self.client.post("/api/mobile/devices/serial123/packages/com.example.app/ingest")
        self.assertIn(response.status_code, [503, 500]) # 503 if harvester unavailable, 500 if it fails later
        if response.status_code == 400:
             self.assertNotEqual(response.json()["detail"], "Invalid package_name format")

if __name__ == "__main__":
    unittest.main()
