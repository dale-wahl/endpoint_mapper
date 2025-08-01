"""
Tests for the Endpoint Detector module.
"""

from src.endpoint_detector import EndpointDetector


class TestEndpointDetector:
    """Test cases for EndpointDetector class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.detector = EndpointDetector(verbose=False)

    def test_is_api_endpoint(self):
        """Test API endpoint identification."""
        # Positive cases
        assert self.detector._is_api_endpoint("/api/users")
        assert self.detector._is_api_endpoint("/v1/data")
        assert self.detector._is_api_endpoint("/graphql")
        assert self.detector._is_api_endpoint("/rest/endpoint")
        assert self.detector._is_api_endpoint("/data.json")

        # Negative cases
        assert not self.detector._is_api_endpoint("/about")
        assert not self.detector._is_api_endpoint("/contact.html")
        assert not self.detector._is_api_endpoint("/images/logo.png")

    def test_extract_from_javascript(self):
        """Test endpoint extraction from JavaScript."""
        js_content = """
        fetch('/api/users')
            .then(response => response.json());
        
        axios.post('/api/auth/login', data);
        
        $.get('/v1/data', function(data) {
            console.log(data);
        });
        
        // This should be ignored
        fetch('/regular/page');
        """

        endpoints = self.detector._extract_from_javascript(
            js_content, "https://example.com"
        )

        # Should find API endpoints
        api_endpoints = [
            ep["endpoint"]
            for ep in endpoints
            if self.detector._is_api_endpoint(ep["endpoint"])
        ]

        assert "/api/users" in api_endpoints
        assert "/api/auth/login" in api_endpoints
        assert "/v1/data" in api_endpoints

    def test_detect_endpoints_html(self):
        """Test endpoint detection from HTML content."""
        html_content = """
        <html>
            <head><title>Test Page</title></head>
            <body>
                <form action="/api/submit" method="POST">
                    <input type="text" name="data">
                </form>
                
                <div data-api="/api/config"></div>
                
                <script>
                    fetch('/api/data')
                        .then(response => response.json());
                    
                    axios.post('/api/auth', {username: 'test'});
                </script>
            </body>
        </html>
        """

        result = self.detector.detect_endpoints(html_content, "https://example.com")
        endpoints = result["endpoints"]

        # Extract endpoint URLs
        endpoint_urls = [ep["endpoint"] for ep in endpoints]

        assert "/api/submit" in endpoint_urls
        assert "/api/config" in endpoint_urls
        assert "/api/data" in endpoint_urls
        assert "/api/auth" in endpoint_urls

        # Check methods
        methods = {ep["endpoint"]: ep["method"] for ep in endpoints}
        assert methods.get("/api/submit") == "POST"
        assert methods.get("/api/data") == "GET"

    def test_detect_endpoints_empty_html(self):
        """Test endpoint detection with HTML containing no APIs."""
        html_content = """
        <html>
            <head><title>Static Page</title></head>
            <body>
                <h1>Welcome</h1>
                <p>This is a static page with no API calls.</p>
                <a href="/about">About</a>
            </body>
        </html>
        """

        result = self.detector.detect_endpoints(html_content, "https://example.com")
        endpoints = result["endpoints"]

        assert len(endpoints) == 0
