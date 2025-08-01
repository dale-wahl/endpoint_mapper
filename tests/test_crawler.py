"""
Tests for the Web Crawler module.
"""

from unittest.mock import Mock, patch
from src.crawler import WebCrawler


class TestWebCrawler:
    """Test cases for WebCrawler class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.crawler = WebCrawler(delay=0, verbose=False)

    def test_init(self):
        """Test crawler initialization."""
        crawler = WebCrawler(delay=1.0, timeout=15, verbose=True)
        assert crawler.delay == 1.0
        assert crawler.timeout == 15
        assert crawler.verbose is True

    def test_is_valid_url(self):
        """Test URL validation logic."""
        base_domain = "example.com"

        # Valid URLs
        assert self.crawler._is_valid_url("https://example.com/page", base_domain)
        assert self.crawler._is_valid_url("https://example.com/about", base_domain)
        assert self.crawler._is_valid_url("http://example.com/", base_domain)

        # Invalid URLs
        assert not self.crawler._is_valid_url("https://other.com/page", base_domain)
        assert not self.crawler._is_valid_url(
            "https://example.com/file.pdf", base_domain
        )
        assert not self.crawler._is_valid_url(
            "https://example.com/image.jpg", base_domain
        )
        assert not self.crawler._is_valid_url("ftp://example.com/file", base_domain)
        assert not self.crawler._is_valid_url("https://example.com/admin", base_domain)
        
    def test_extract_links(self):
        """Test link extraction from HTML."""
        html_content = """
        <html>
            <body>
                <a href="/page1">Page 1</a>
                <a href="https://example.com/page2">Page 2</a>
                <a href="https://other.com/external">External</a>
                <a href="#fragment">Fragment</a>
                <a href="/file.pdf">PDF</a>
                <script>
                    path: '/api/data'
                </script>
            </body>
        </html>
        """

        base_url = "https://example.com"
        links = self.crawler._extract_links(html_content, base_url)

        # Should include internal pages but exclude external, fragments, files, and API paths
        expected_links = {"https://example.com/page1", "https://example.com/page2"}

        assert links == expected_links

    @patch("src.crawler.requests.Session.get")
    def test_fetch_page_success(self, mock_get):
        """Test successful page fetching."""
        # Mock response
        mock_response = Mock()
        mock_response.text = "<html><title>Test Page</title><body>Content</body></html>"
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "text/html; charset=utf-8"}
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        result = self.crawler._fetch_page("https://example.com/test")

        assert result is not None
        assert result["url"] == "https://example.com/test"
        assert result["title"] == "Test Page"
        assert result["status_code"] == 200
        assert "text/html" in result["content_type"]

    @patch("src.crawler.requests.Session.get")
    def test_fetch_page_non_html(self, mock_get):
        """Test fetching non-HTML content."""
        # Mock response
        mock_response = Mock()
        mock_response.headers = {"content-type": "application/json"}
        mock_response.status_code = 200
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        result = self.crawler._fetch_page("https://example.com/api")

        assert result is not None
        assert result["crawl_successful"] is False
        assert "Non-HTML content" in result["error"]

    @patch("src.crawler.requests.Session.get")
    def test_fetch_page_error(self, mock_get):
        """Test error handling during page fetch."""
        mock_get.side_effect = Exception("Network error")

        result = self.crawler._fetch_page("https://example.com/error")

        assert result is not None
        assert result["crawl_successful"] is False
        assert result["error"] == "Network error"

    @patch.object(WebCrawler, "_fetch_page")
    @patch.object(WebCrawler, "_extract_links")
    def test_crawl_site(self, mock_extract_links, mock_fetch_page):
        """Test site crawling logic."""
        # Mock page data
        mock_page_data = {
            "url": "https://example.com",
            "title": "Home Page",
            "content": "<html>Content</html>",
            "status_code": 200,
            "content_type": "text/html",
            "crawl_successful": True,
            "error": None,
        }

        mock_fetch_page.return_value = mock_page_data
        mock_extract_links.return_value = {"https://example.com/page1"}

        # Test crawling
        result = self.crawler.crawl_site("https://example.com", max_pages=2)

        assert len(result) >= 1
        assert result[0]["url"] == "https://example.com"
        mock_fetch_page.assert_called()
        mock_extract_links.assert_called()
