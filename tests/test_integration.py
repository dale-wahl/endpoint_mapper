"""
Integration tests for the Intelligent Endpoint Mapper.
"""

from unittest.mock import patch, Mock
from src.crawler import WebCrawler
from src.endpoint_detector import EndpointDetector
from src.relationship_mapper import RelationshipMapper
from src.output_formatter import OutputFormatter


class TestIntegration:
    """Integration test cases."""

    def test_full_pipeline(self):
        """Test the complete analysis pipeline."""
        # Create sample page data
        pages_data = [
            {
                "url": "https://example.com",
                "title": "Home Page",
                "content": """
                <html>
                    <head><title>Home</title></head>
                    <body>
                        <h1>Welcome</h1>
                        <script>
                            fetch('/api/users').then(r => r.json());
                        </script>
                    </body>
                </html>
                """,
                "status_code": 200,
                "content_type": "text/html",
            },
            {
                "url": "https://example.com/login",
                "title": "Login Page",
                "content": """
                <html>
                    <head><title>Login</title></head>
                    <body>
                        <form action="/api/auth/login" method="POST">
                            <input type="text" name="username">
                            <input type="password" name="password">
                        </form>
                        <script>
                            // Also call users API from login page
                            fetch('/api/users');
                        </script>
                    </body>
                </html>
                """,
                "status_code": 200,
                "content_type": "text/html",
            },
        ]

        # Test endpoint detection
        detector = EndpointDetector()
        for page_data in pages_data:
            result = detector.detect_endpoints(page_data["content"], page_data["url"])
            page_data["api_endpoints"] = result["endpoints"]

        # Test relationship mapping
        mapper = RelationshipMapper()
        relationship_data = mapper.map_relationships(pages_data)

        # Test output formatting
        formatter = OutputFormatter()
        output = formatter.format_output(
            base_url="https://example.com",
            pages_data=pages_data,
            relationship_data=relationship_data,
            crawl_time=1.5,
        )

        # Verify output structure
        assert "crawl_summary" in output
        assert "pages" in output
        assert "api_summary" in output
        assert "insights" in output

        # Verify crawl summary
        summary = output["crawl_summary"]
        assert summary["base_url"] == "https://example.com"
        assert summary["pages_discovered"] == 2
        assert summary["crawl_duration_seconds"] == 1.5

        # Verify pages data
        pages = output["pages"]
        assert len(pages) == 2

        # Home page should have /api/users
        home_page = next(p for p in pages if p["url"] == "https://example.com")
        home_endpoints = [ep["endpoint"] for ep in home_page["api_endpoints"]]
        assert "/api/users" in home_endpoints

        # Login page should have both endpoints
        login_page = next(p for p in pages if p["url"] == "https://example.com/login")
        login_endpoints = [ep["endpoint"] for ep in login_page["api_endpoints"]]
        assert "/api/auth/login" in login_endpoints
        assert "/api/users" in login_endpoints

        # Verify API summary
        api_summary = output["api_summary"]
        assert "/api/users" in api_summary
        assert "/api/auth/login" in api_summary

        # /api/users should be used by both pages
        users_api = api_summary["/api/users"]
        assert len(users_api["used_by_pages"]) == 2

        # /api/auth/login should be used by only login page
        auth_api = api_summary["/api/auth/login"]
        assert len(auth_api["used_by_pages"]) == 1
        assert "https://example.com/login" in auth_api["used_by_pages"]

    @patch("src.crawler.requests.Session.get")
    def test_crawler_with_real_response(self, mock_get):
        """Test crawler with mocked HTTP responses."""
        # Mock the home page response
        home_response = Mock()
        home_response.text = """
        <html>
            <head><title>Test Site</title></head>
            <body>
                <a href="/about">About</a>
                <a href="/contact">Contact</a>
                <script>fetch('/api/data');</script>
            </body>
        </html>
        """
        home_response.status_code = 200
        home_response.headers = {"content-type": "text/html"}
        home_response.raise_for_status.return_value = None

        # Mock the about page response
        about_response = Mock()
        about_response.text = """
        <html>
            <head><title>About Us</title></head>
            <body>
                <h1>About</h1>
                <script>axios.get('/api/info');</script>
            </body>
        </html>
        """
        about_response.status_code = 200
        about_response.headers = {"content-type": "text/html"}
        about_response.raise_for_status.return_value = None

        # Configure mock to return different responses for different URLs
        def mock_get_response(url, **kwargs):
            if url == "https://test.com":
                return home_response
            elif url == "https://test.com/about":
                return about_response
            else:
                raise Exception(f"Unexpected URL: {url}")

        mock_get.side_effect = mock_get_response

        # Test crawling
        crawler = WebCrawler(delay=0, verbose=False)
        pages_data = crawler.crawl_site("https://test.com", max_pages=5)

        # Should have crawled multiple pages
        assert len(pages_data) >= 1

        # Verify home page was crawled
        home_page = next(
            (p for p in pages_data if p["url"] == "https://test.com"), None
        )
        assert home_page is not None
        assert home_page["title"] == "Test Site"
