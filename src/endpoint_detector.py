"""
Endpoint Detection Module

Analyzes HTML content and JavaScript to identify API endpoints
that are used by web pages.
"""

import re
import requests
from typing import List, Dict
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup


class EndpointDetector:
    """Detects API endpoints from HTML and JavaScript content."""

    def __init__(
        self,
        verbose: bool = False,
        session: requests.Session = None,
        timeout: int = 10,
        fetch_external_scripts: bool = False,
        include_external_apis: bool = True,
    ):
        """
        Initialize the endpoint detector.

        Args:
            verbose: Enable verbose logging
            session: Optional requests session (to reuse authentication headers)
            timeout: Request timeout for external script fetching
            fetch_external_scripts: Whether to fetch and analyze external scripts
            include_external_apis: Whether to include external API endpoints in results
        """
        self.verbose = verbose
        self.session = session or requests.Session()
        self.timeout = timeout
        self.fetch_external_scripts = fetch_external_scripts
        self.include_external_apis = include_external_apis

        # Script cache to avoid re-analyzing the same external scripts
        self._script_cache = {}  # {script_url: {'content': str, 'endpoints': List[Dict], 'analyzed': bool, 'error': str}}

        # Common API path patterns
        self.api_patterns = [
            r'/api/[^\s\'"<>]+',
            r'/v\d+/[^\s\'"<>]+',
            r'/graphql[^\s\'"<>]*',
            r'/rest/[^\s\'"<>]+',
            r'/services/[^\s\'"<>]+',
            r'/endpoint/[^\s\'"<>]+',
        ]

        # HTTP method patterns in JavaScript
        self.method_patterns = {
            "GET": [
                r'\.get\s*\(\s*["\']([^"\']+)["\']',
                r'method:\s*["\']GET["\'].*?["\']([^"\']+)["\']',
                r'fetch\s*\(\s*["\']([^"\']+)["\'](?:\s*,\s*\{[^}]*method:\s*["\']GET["\'][^}]*\})?',
                r'\.getJSON\s*\(\s*\{[^}]*url:\s*["\']([^"\']+)["\']',
                r'\.getJSON\s*\(\s*["\']([^"\']+)["\']',
                r'getRelativeURL\s*\(\s*["\']([^"\']+)["\']',
                r'url:\s*["\']([^"\']+)["\']',
                r'\.get\s*\(\s*\{[^}]*["\']?url["\']?\s*:\s*["\']([^"\']+)["\']',
            ],
            "POST": [
                r'\.post\s*\(\s*["\']([^"\']+)["\']',
                r'method:\s*["\']POST["\'].*?["\']([^"\']+)["\']',
                r'fetch\s*\(\s*["\']([^"\']+)["\'].*?method:\s*["\']POST["\']',
                r'\.post\s*\(\s*\{[^}]*url:\s*["\']([^"\']+)["\']',
            ],
            "PUT": [
                r'\.put\s*\(\s*["\']([^"\']+)["\']',
                r'method:\s*["\']PUT["\'].*?["\']([^"\']+)["\']',
                r'fetch\s*\(\s*["\']([^"\']+)["\'].*?method:\s*["\']PUT["\']',
            ],
            "DELETE": [
                r'\.delete\s*\(\s*["\']([^"\']+)["\']',
                r'method:\s*["\']DELETE["\'].*?["\']([^"\']+)["\']',
                r'fetch\s*\(\s*["\']([^"\']+)["\'].*?method:\s*["\']DELETE["\']',
                r'method:\s*["\']DELETE["\']',
            ],
            "PATCH": [
                r'\.patch\s*\(\s*["\']([^"\']+)["\']',
                r'method:\s*["\']PATCH["\'].*?["\']([^"\']+)["\']',
                r'fetch\s*\(\s*["\']([^"\']+)["\'].*?method:\s*["\']PATCH["\']',
            ],
        }

    def _process_template_literal(self, template: str) -> str:
        """
        Process template literal to extract meaningful URL pattern.

        Args:
            template: Template literal string

        Returns:
            Processed URL with variables replaced by placeholders
        """
        # Replace common variable patterns with placeholders
        processed = template

        # Replace ${variable} with {variable} for pattern recognition
        processed = re.sub(r"\$\{([^}]+)\}", r"{\1}", processed)

        # Replace common variable names with meaningful placeholders
        common_vars = {
            "id": "{id}",
            "userId": "{user_id}",
            "user_id": "{user_id}",
            "resourceId": "{resource_id}",
            "resource_id": "{resource_id}",
            "datasetId": "{dataset_id}",
            "dataset_id": "{dataset_id}",
            "queryId": "{query_id}",
            "query_id": "{query_id}",
            "taskId": "{task_id}",
            "task_id": "{task_id}",
        }

        for var, placeholder in common_vars.items():
            processed = processed.replace(f"{{{var}}}", placeholder)

        return processed

    def _detect_method_from_context(self, js_content: str, url_match: str) -> str:
        """
        Detect HTTP method from surrounding context in JavaScript.

        Args:
            js_content: Full JavaScript content
            url_match: The URL that was matched

        Returns:
            Detected HTTP method (defaults to GET)
        """
        # Find the context around the URL match
        url_index = js_content.find(url_match)
        if url_index == -1:
            return "GET"

        # Look for method indicators in the surrounding context (±200 characters)
        start = max(0, url_index - 200)
        end = min(len(js_content), url_index + len(url_match) + 200)
        context = js_content[start:end].lower()

        # Check for explicit method declarations
        method_patterns = {
            "DELETE": [
                r'method\s*:\s*["\']delete["\']',
                r"\.delete\s*\(",
                r'type\s*:\s*["\']delete["\']',
            ],
            "POST": [
                r'method\s*:\s*["\']post["\']',
                r"\.post\s*\(",
                r'type\s*:\s*["\']post["\']',
            ],
            "PUT": [
                r'method\s*:\s*["\']put["\']',
                r"\.put\s*\(",
                r'type\s*:\s*["\']put["\']',
            ],
            "PATCH": [
                r'method\s*:\s*["\']patch["\']',
                r"\.patch\s*\(",
                r'type\s*:\s*["\']patch["\']',
            ],
        }

        for method, patterns in method_patterns.items():
            for pattern in patterns:
                if re.search(pattern, context):
                    return method

        # Check for contextual clues
        if any(word in context for word in ["delete", "remove", "destroy"]):
            return "DELETE"
        elif any(word in context for word in ["create", "add", "submit", "save"]):
            return "POST"
        elif any(word in context for word in ["update", "edit", "modify"]):
            return "PUT"

        return "GET"

    def _track_dynamic_urls(self, js_content: str, base_url: str) -> List[Dict]:
        """
        Track dynamic URL construction patterns.

        Args:
            js_content: JavaScript content to analyze
            base_url: Base URL for resolving relative URLs

        Returns:
            List of dynamically constructed endpoint dictionaries
        """
        endpoints = []

        # Pattern for variable-based URL construction
        construction_patterns = [
            # var url = baseUrl + "/api/" + resource + "/" + id
            r'(\w+)\s*=\s*["\']([^"\']*\/api\/[^"\']*)["\'].*?\+.*?(\w+)',
            # var endpoint = "/api/" + service + "/action"
            r'(\w+)\s*=\s*["\']([^"\']*\/api\/[^"\']*)["\'].*?\+',
            # Building URLs with string concatenation
            r'["\']([^"\']*\/api\/[^"\']*)["\'].*?\+.*?["\']([^"\']*)["\']',
            # Dynamic endpoint assignment
            r'endpoint\s*=\s*["\']([^"\']*\/api\/[^"\']*)["\']',
            # URL building functions
            r'buildUrl\s*\(\s*["\']([^"\']*\/api\/[^"\']*)["\']',
            r'getApiUrl\s*\(\s*["\']([^"\']*\/api\/[^"\']*)["\']',
        ]

        for pattern in construction_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    url = match[1] if len(match) > 1 else match[0]
                else:
                    url = match

                if url and self._is_api_endpoint(url):
                    # Resolve relative URLs
                    if url.startswith("/"):
                        full_url = urljoin(base_url, url)
                    else:
                        full_url = url

                    endpoints.append(
                        {
                            "endpoint": url,
                            "full_url": full_url,
                            "method": self._detect_method_from_context(js_content, url),
                            "detected_in": "dynamic_construction",
                        }
                    )

        return endpoints

    def _is_api_endpoint(self, url: str) -> bool:
        """
        Check if a URL looks like an API endpoint.

        Args:
            url: URL to check

        Returns:
            True if URL appears to be an API endpoint
        """
        url_lower = url.lower()

        # Check for common API indicators
        api_indicators = [
            "/api/",
            "/v1/",
            "/v2/",
            "/v3/",
            "/graphql",
            "/rest/",
            "/services/",
            "/endpoint/",
            "/data/",
            "/ajax/",
            # Additional common API patterns
            "/admin/api/",
            "/public/api/",
            "/internal/api/",
            "/webhook/",
            "/callback/",
            "/oauth/",
            "/auth/",
            "/upload/",
            "/download/",
            "/export/",
            "/import/",
            "/search/",
            "/query/",
            "/filter/",
            "/analytics/",
            "/metrics/",
            "/health/",
            "/status/",
            "/ping/",
            "/config/",
            "/settings/",
            "/preferences/",
            # RESTful resource patterns
            "/users/",
            "/accounts/",
            "/profiles/",
            "/sessions/",
            "/posts/",
            "/comments/",
            "/messages/",
            "/notifications/",
            "/files/",
            "/documents/",
            "/media/",
            "/orders/",
            "/payments/",
            "/transactions/",
            "/billing/",
            "/products/",
            "/categories/",
            "/inventory/",
            "/catalog/",
        ]

        for indicator in api_indicators:
            if indicator in url_lower:
                return True

        # Check file extensions that suggest APIs
        api_extensions = [".json", ".xml", ".api"]
        for ext in api_extensions:
            if url_lower.endswith(ext):
                return True

        # Check for RESTful patterns (resource/id operations)
        restful_patterns = [
            r"/[a-zA-Z]+/\d+/?$",  # /resource/123
            r"/[a-zA-Z]+/[a-zA-Z0-9-]+/?$",  # /resource/identifier
            r"/[a-zA-Z]+/[a-zA-Z0-9-]+/[a-zA-Z]+/?$",  # /resource/id/action
            r"/[a-zA-Z]+/[a-zA-Z0-9-]+/[a-zA-Z]+/[a-zA-Z0-9-]+/?$",  # /resource/id/subresource/id
            # Common API CRUD patterns
            r"/[a-zA-Z]+/(create|read|update|delete|edit|remove)/?$",
            r"/[a-zA-Z]+/\d+/(edit|update|delete|remove)/?$",
            # Query and search patterns
            r"/[a-zA-Z]+/(search|query|filter|find)/?$",
            r"/[a-zA-Z]+/(list|all|index)/?$",
            # Batch operations
            r"/[a-zA-Z]+/(bulk|batch)/?$",
            r"/[a-zA-Z]+/(import|export)/?$",
        ]

        import re

        for pattern in restful_patterns:
            if re.search(pattern, url):
                return True

        return False

    def _normalize_script_content(self, content: str) -> str:
        """
        Prepare script content for better pattern matching.

        Args:
            content: Raw JavaScript content

        Returns:
            Normalized content for pattern matching
        """
        # Remove single-line comments but preserve URLs
        # First, protect URLs by temporarily replacing them
        url_placeholders = {}
        url_counter = 0

        # Find and protect URLs
        url_pattern = r'https?://[^\s\'"<>]+'

        def replace_url(match):
            nonlocal url_counter
            placeholder = f"__URL_PLACEHOLDER_{url_counter}__"
            url_placeholders[placeholder] = match.group(0)
            url_counter += 1
            return placeholder

        content = re.sub(url_pattern, replace_url, content)

        # Now safely remove comments
        content = re.sub(r"//.*?$", "", content, flags=re.MULTILINE)
        content = re.sub(r"/\*.*?\*/", "", content, flags=re.DOTALL)

        # Restore URLs
        for placeholder, url in url_placeholders.items():
            content = content.replace(placeholder, url)

        # Normalize whitespace but preserve structure for multi-line patterns
        content = re.sub(r"\s+", " ", content)

        # Join lines that are clearly continuations (helps with multi-line fetch calls)
        content = re.sub(r",\s*\n\s*", ", ", content)
        content = re.sub(r"\{\s*\n\s*", "{ ", content)
        content = re.sub(r"\s*\n\s*\}", " }", content)

        return content

    def _should_include_endpoint(self, url: str) -> bool:
        """
        Enhanced endpoint validation including external APIs.

        Args:
            url: URL to validate

        Returns:
            True if endpoint should be included in results
        """
        if not url or url.strip() == "":
            return False

        # Enhanced validation to prevent false positives
        if not self._is_valid_endpoint_format(url):
            return False

        # Check if it's a traditional API endpoint
        if self._is_api_endpoint(url):
            return True

        # Check for external API patterns (like jsonplaceholder)
        if self._should_include_external_api(url):
            return True

        return False

    def _is_valid_endpoint_format(self, url: str) -> bool:
        """
        Validate that a URL has a reasonable format and isn't malformed content.

        Args:
            url: URL to validate

        Returns:
            True if URL format appears valid
        """
        # Basic length check
        if len(url) > 500:
            return False

        # Check for template literal syntax or HTML fragments
        invalid_patterns = [
            r"\$\{[^}]*\}",  # Template literal syntax
            r"<[^>]+>",  # HTML tags
            r"&gt;|&lt;|&amp;",  # HTML entities
            r"post\.[a-zA-Z]+\.[a-zA-Z]+",  # Template object notation like post.name.first
            r"const\s+\w+\s*=",  # JavaScript variable declarations
            r"function\s*\(",  # JavaScript function declarations
            r"\)\s*\{",  # JavaScript function/object syntax
            r"\.push\s*\(",  # JavaScript method calls
            r"\.innerHTML\s*=",  # DOM manipulation
        ]

        for pattern in invalid_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return False

        # Check for excessive special characters (likely minified JS)
        special_chars = re.findall(r"[(){}[\]<>.,;:!@#$%^&*+=|\\]", url)
        if len(special_chars) > len(url) * 0.4:  # More than 40% special chars
            return False

        # URL should start with http/https or / for relative URLs
        if not (url.startswith(("http://", "https://", "/"))):
            return False

        # If it's a full URL, validate the basic structure
        if url.startswith(("http://", "https://")):
            try:
                from urllib.parse import urlparse

                parsed = urlparse(url)
                # Must have a valid domain
                if not parsed.netloc or "." not in parsed.netloc:
                    return False
            except Exception:
                return False

        return True

    def _should_include_external_api(self, url: str) -> bool:
        """
        Decide whether to include external API endpoints.

        Args:
            url: URL to check

        Returns:
            True if external URL appears to be an API and should be included
        """
        # Check configuration setting first
        if not self.include_external_apis:
            return False

        url_lower = url.lower()

        # Patterns that suggest external APIs worth including
        external_api_patterns = [
            r"api\.",  # api.example.com
            r"jsonplaceholder",  # jsonplaceholder.typicode.com
            r"/api/",  # any /api/ path
            r"/v\d+/",  # versioned APIs
            r"graphql",  # GraphQL endpoints
            r"rest",  # REST APIs
            r"\.json$",  # JSON endpoints
            r"/posts",  # Common REST resource
            r"/users",  # Common REST resource
            r"/data",  # Data endpoints
            r"webhook",  # Webhook endpoints
            r"callback",  # Callback endpoints
        ]

        return any(re.search(pattern, url_lower) for pattern in external_api_patterns)

    def _extract_endpoint_context(self, script_content: str, endpoint: str) -> Dict:
        """
        Extract additional context around endpoint usage.

        Args:
            script_content: Full JavaScript content
            endpoint: The endpoint URL

        Returns:
            Dictionary with context information
        """
        context = {
            "content_type": None,
            "authentication": None,
            "request_body_type": None,
            "function_context": None,
        }

        # Find the function containing this endpoint
        escaped_endpoint = re.escape(endpoint)
        func_pattern = r"function\s+(\w+)[^{]*\{[^}]*" + escaped_endpoint
        func_match = re.search(func_pattern, script_content, re.IGNORECASE | re.DOTALL)
        if func_match:
            context["function_context"] = func_match.group(1)

        # Look for context around the endpoint (±200 characters)
        endpoint_index = script_content.find(endpoint)
        if endpoint_index != -1:
            start = max(0, endpoint_index - 200)
            end = min(len(script_content), endpoint_index + len(endpoint) + 200)
            surrounding_context = script_content[start:end]

            # Detect content type
            content_type_pattern = r'["\']Content-Type["\']\s*:\s*["\']([^"\']+)["\']'
            ct_match = re.search(
                content_type_pattern, surrounding_context, re.IGNORECASE
            )
            if ct_match:
                context["content_type"] = ct_match.group(1)

            # Detect authentication headers
            auth_patterns = [
                r'["\']Authorization["\']\s*:\s*["\']([^"\']+)["\']',
                r'["\']X-API-Key["\']\s*:\s*["\']([^"\']+)["\']',
                r'["\']Bearer["\']',
                r'["\']Token["\']',
            ]
            for pattern in auth_patterns:
                if re.search(pattern, surrounding_context, re.IGNORECASE):
                    context["authentication"] = "detected"
                    break

            # Detect request body type
            if "JSON.stringify" in surrounding_context:
                context["request_body_type"] = "json"
            elif "FormData" in surrounding_context:
                context["request_body_type"] = "form_data"
            elif "URLSearchParams" in surrounding_context:
                context["request_body_type"] = "url_encoded"

        return context

    def _classify_endpoint(self, endpoint: str, context: Dict) -> Dict:
        """
        Classify endpoint type and likelihood.

        Args:
            endpoint: The endpoint URL
            context: Additional context information

        Returns:
            Dictionary with classification information
        """
        classification = {
            "api_likelihood": "unknown",
            "endpoint_type": "unknown",
            "external_domain": False,
        }

        # Parse URL to check domain
        try:
            parsed = urlparse(endpoint)
            if parsed.netloc:
                # This is a full URL, check if it's external
                classification["external_domain"] = True
        except Exception:
            # If URL parsing fails, assume it's not external
            pass

        # API likelihood scoring
        endpoint_lower = endpoint.lower()

        # High likelihood indicators
        high_indicators = [
            r"/api/",
            r"\.json$",
            r"/v\d+/",
            r"jsonplaceholder",
            r"graphql",
            r"/posts$",
            r"/posts/\d+$",
            r"/users$",
            r"/users/\d+$",
            r"/auth",
            r"/login",
            r"/oauth",
            r"webhook",
            r"callback",
        ]

        # Medium likelihood indicators
        medium_indicators = [
            r"/data",
            r"/search",
            r"/query",
            r"/submit",
            r"/save",
            r"/update",
            r"/delete",
            r"/create",
            r"/process",
        ]

        # Check indicators
        for pattern in high_indicators:
            if re.search(pattern, endpoint_lower):
                classification["api_likelihood"] = "high"
                break
        else:
            for pattern in medium_indicators:
                if re.search(pattern, endpoint_lower):
                    classification["api_likelihood"] = "medium"
                    break
            else:
                # If it has any API-like characteristics, mark as low
                if any(
                    char in endpoint_lower for char in ["/api", "json", "rest", "ajax"]
                ):
                    classification["api_likelihood"] = "low"

        # Endpoint type classification
        if re.search(r"/posts", endpoint_lower):
            classification["endpoint_type"] = "content_management"
        elif re.search(r"/users", endpoint_lower):
            classification["endpoint_type"] = "user_management"
        elif re.search(r"/auth|/login|/oauth", endpoint_lower):
            classification["endpoint_type"] = "authentication"
        elif re.search(r"/search|/query|/filter", endpoint_lower):
            classification["endpoint_type"] = "search"
        elif re.search(r"/upload|/download|/file", endpoint_lower):
            classification["endpoint_type"] = "file_management"
        elif re.search(r"/webhook|/callback|/notify", endpoint_lower):
            classification["endpoint_type"] = "notification"
        elif re.search(r"jsonplaceholder", endpoint_lower):
            classification["endpoint_type"] = "testing_api"

        return classification

    def _fetch_external_script(self, script_url: str) -> str:
        """
        Fetch external JavaScript file content.

        Args:
            script_url: URL of the JavaScript file to fetch

        Returns:
            JavaScript content or empty string if failed
        """
        try:
            if self.verbose:
                print(f"      📥 Fetching external script: {script_url}")

            response = self.session.get(script_url, timeout=self.timeout)
            response.raise_for_status()

            # Only process JavaScript content
            content_type = response.headers.get("content-type", "").lower()
            if (
                "javascript" in content_type
                or "text/plain" in content_type
                or script_url.endswith(".js")
            ):
                return response.text
            else:
                if self.verbose:
                    print(f"        ⚠️  Skipping non-JavaScript content: {content_type}")
                return ""

        except requests.RequestException as e:
            if self.verbose:
                print(f"        ❌ Failed to fetch {script_url}: {e}")
            return ""
        except Exception as e:
            if self.verbose:
                print(f"        ❌ Unexpected error fetching {script_url}: {e}")
            return ""

    def _extract_from_javascript(self, js_content: str, base_url: str) -> List[Dict]:
        """
        Extract API endpoints from JavaScript content.

        Args:
            js_content: JavaScript code to analyze
            base_url: Base URL for resolving relative URLs

        Returns:
            List of endpoint dictionaries
        """
        endpoints = []

        # Normalize script content for better pattern matching
        js_content = self._normalize_script_content(js_content)

        # Enhanced fetch API patterns including external domains
        modern_fetch_patterns = [
            # Modern fetch with method in options (multi-line support)
            r'fetch\s*\(\s*["\']([^"\']+)["\']\s*,\s*\{[^}]*method\s*:\s*["\'](\w+)["\']',
            # Fetch with template literals
            r'fetch\s*\(\s*`([^`]+)`\s*,\s*\{[^}]*method\s*:\s*["\'](\w+)["\']',
            # Basic fetch without explicit method (defaults to GET)
            r'fetch\s*\(\s*["\']([^"\']+)["\'](?:\s*,\s*\{[^}]*\})?',
            # Axios patterns
            r'axios\.(\w+)\s*\(\s*["\']([^"\']+)["\']',
            # jQuery AJAX patterns
            r'\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\'][^}]*type\s*:\s*["\'](\w+)["\']',
            r'\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']',
            # jQuery shorthand methods
            r'\$\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
            r'\$\.getJSON\s*\(\s*["\']([^"\']+)["\']',
        ]

        # Process modern fetch patterns
        for pattern in modern_fetch_patterns:
            matches = re.finditer(pattern, js_content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                groups = match.groups()

                if len(groups) == 2:
                    # Pattern with method and URL
                    if "axios." in pattern:
                        method, url = groups
                        method = method.upper()
                    else:
                        url, method = groups
                        method = method.upper()
                elif len(groups) == 1:
                    # Pattern with only URL
                    url = groups[0]
                    if r"\$\." in pattern and any(
                        m in pattern for m in ["post", "put", "delete", "patch"]
                    ):
                        # Extract method from jQuery pattern
                        method_match = re.search(r"\$\.(\w+)", pattern)
                        method = (
                            method_match.group(1).upper() if method_match else "GET"
                        )
                    else:
                        method = self._detect_method_from_context(js_content, url)
                else:
                    continue

                # Enhanced endpoint validation including external APIs
                if self._should_include_endpoint(url):
                    classification = self._classify_endpoint(url, {})
                    context = self._extract_endpoint_context(js_content, url)

                    # Resolve relative URLs
                    if url.startswith("/"):
                        full_url = urljoin(base_url, url)
                    else:
                        full_url = url

                    endpoints.append(
                        {
                            "endpoint": url,
                            "full_url": full_url,
                            "method": method,
                            "detected_in": "modern_fetch",
                            "pattern_type": "fetch_api",
                            "api_likelihood": classification.get(
                                "api_likelihood", "unknown"
                            ),
                            "external_domain": classification.get(
                                "external_domain", False
                            ),
                            "endpoint_type": classification.get(
                                "endpoint_type", "unknown"
                            ),
                            "context": context,
                        }
                    )

        # Extract endpoints by HTTP method (existing patterns)
        for method, patterns in self.method_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, js_content, re.IGNORECASE | re.DOTALL)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0]

                    if match and self._should_include_endpoint(match):
                        classification = self._classify_endpoint(match, {})

                        # Resolve relative URLs
                        if match.startswith("/"):
                            full_url = urljoin(base_url, match)
                        else:
                            full_url = match

                        endpoints.append(
                            {
                                "endpoint": match,
                                "full_url": full_url,
                                "method": method,
                                "detected_in": "method_pattern",
                                "api_likelihood": classification.get(
                                    "api_likelihood", "unknown"
                                ),
                                "external_domain": classification.get(
                                    "external_domain", False
                                ),
                                "endpoint_type": classification.get(
                                    "endpoint_type", "unknown"
                                ),
                            }
                        )

        # Extract GraphQL operations from JavaScript
        graphql_operations = self._extract_graphql_operations(js_content, base_url)
        endpoints.extend(graphql_operations)

        # Enhanced template literal patterns
        template_literal_patterns = [
            r"`([^`]*\/api\/[^`]*)`",  # Template literals with /api/
            r"`([^`]*\/v\d+\/[^`]*)`",  # Template literals with versioned APIs
            r"`([^`]*\$\{[^}]*\}[^`]*\/[a-zA-Z0-9/_-]*)`",  # Template literals with variables
            r"`([^`]*\/[a-zA-Z0-9/_-]*\$\{[^}]*\}[^`]*)`",  # Template literals with variables at end
            r"`([^`]*https?://[^`]*)`",  # Template literals with full URLs
            r"`([^`]*jsonplaceholder[^`]*)`",  # Specific pattern for test APIs
        ]

        # Process template literals
        for pattern in template_literal_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                # Clean up template literal variables for pattern recognition
                template_url = self._process_template_literal(match)
                if template_url and self._should_include_endpoint(template_url):
                    classification = self._classify_endpoint(template_url, {})

                    # Resolve relative URLs
                    if template_url.startswith("/"):
                        full_url = urljoin(base_url, template_url)
                    else:
                        full_url = template_url

                    endpoints.append(
                        {
                            "endpoint": template_url,
                            "full_url": full_url,
                            "method": self._detect_method_from_context(
                                js_content, match
                            ),
                            "detected_in": "template_literal",
                            "original_template": match,
                            "api_likelihood": classification.get(
                                "api_likelihood", "unknown"
                            ),
                            "external_domain": classification.get(
                                "external_domain", False
                            ),
                            "endpoint_type": classification.get(
                                "endpoint_type", "unknown"
                            ),
                        }
                    )

        # Variable tracking for dynamic URL construction
        dynamic_endpoints = self._track_dynamic_urls(js_content, base_url)
        endpoints.extend(dynamic_endpoints)

        return endpoints

    def _extract_graphql_operations(self, js_content: str, base_url: str) -> List[Dict]:
        """
        Extract GraphQL operations (queries, mutations, subscriptions) from JavaScript content.

        Args:
            js_content: JavaScript content to analyze
            base_url: Base URL for resolving relative URLs

        Returns:
            List of GraphQL operation dictionaries
        """
        operations = []

        # GraphQL operation patterns
        graphql_patterns = [
            # Template literals with GraphQL queries
            r"gql`\s*(query|mutation|subscription)\s+(\w+)?\s*[^`]*`",
            r"graphql`\s*(query|mutation|subscription)\s+(\w+)?\s*[^`]*`",
            # String literals with GraphQL operations
            r'["\'](\s*(?:query|mutation|subscription)\s+\w+[^"\']*)["\']',
            # GraphQL operation in fetch/request calls
            r'(?:query|mutation|subscription)\s*:\s*["\']([^"\']*)["\']',
            # Apollo Client operations
            r"useQuery\s*\(\s*gql`([^`]*)`",
            r"useMutation\s*\(\s*gql`([^`]*)`",
            r"useSubscription\s*\(\s*gql`([^`]*)`",
            # Variables containing GraphQL operations
            r"const\s+\w+\s*=\s*gql`\s*((?:query|mutation|subscription)[^`]*)`",
            r'(?:const|let|var)\s+\w+\s*=\s*["\'](\s*(?:query|mutation|subscription)[^"\']*)["\']',
        ]

        for pattern in graphql_patterns:
            matches = re.finditer(pattern, js_content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                groups = match.groups()

                # Extract operation type and details
                if len(groups) >= 2 and groups[0] and groups[1]:
                    operation_type = groups[0].lower()
                    operation_name = groups[1] if groups[1] else "unnamed"
                    operation_content = match.group(0)
                elif len(groups) >= 1 and groups[0]:
                    # Parse the GraphQL content to extract type and name
                    content = groups[0]
                    operation_details = self._parse_graphql_operation(content)
                    operation_type = operation_details["type"]
                    operation_name = operation_details["name"]
                    operation_content = content
                else:
                    continue

                # Try to find the endpoint URL this operation targets
                endpoint_url = self._find_graphql_endpoint_for_operation(
                    js_content, match.start(), base_url
                )

                # Extract field information from the operation
                fields = self._extract_graphql_fields(operation_content)

                operation_data = {
                    "endpoint": endpoint_url["endpoint"]
                    if endpoint_url
                    else "/graphql",
                    "full_url": endpoint_url["full_url"]
                    if endpoint_url
                    else urljoin(base_url, "/graphql"),
                    "method": "POST",
                    "detected_in": "graphql_operation",
                    "pattern_type": "graphql_operation",
                    "api_likelihood": "high",
                    "external_domain": endpoint_url["external_domain"]
                    if endpoint_url
                    else False,
                    "endpoint_type": "graphql",
                    "graphql_context": {
                        "operation_type": operation_type,
                        "operation_name": operation_name,
                        "fields_accessed": fields,
                        "operation_pattern": pattern,
                        "raw_operation": operation_content[:200] + "..."
                        if len(operation_content) > 200
                        else operation_content,
                    },
                }

                operations.append(operation_data)

        return operations

    def _parse_graphql_operation(self, content: str) -> Dict:
        """
        Parse GraphQL operation content to extract type and name.

        Args:
            content: GraphQL operation content

        Returns:
            Dictionary with operation details
        """
        # Extract operation type
        operation_match = re.search(
            r"\b(query|mutation|subscription)\b", content, re.IGNORECASE
        )
        operation_type = (
            operation_match.group(1).lower() if operation_match else "query"
        )

        # Extract operation name
        name_match = re.search(
            r"(?:query|mutation|subscription)\s+(\w+)", content, re.IGNORECASE
        )
        operation_name = name_match.group(1) if name_match else "unnamed"

        return {"type": operation_type, "name": operation_name}

    def _find_graphql_endpoint_for_operation(
        self, js_content: str, operation_position: int, base_url: str
    ) -> Dict:
        """
        Find the GraphQL endpoint URL that an operation targets.

        Args:
            js_content: Full JavaScript content
            operation_position: Position of the operation in the content
            base_url: Base URL for resolving relative URLs

        Returns:
            Dictionary with endpoint information or None
        """
        # Look for GraphQL endpoints in surrounding context (±500 characters)
        start = max(0, operation_position - 500)
        end = min(len(js_content), operation_position + 500)
        context = js_content[start:end]

        # Common GraphQL endpoint patterns
        endpoint_patterns = [
            r'(?:uri|url|endpoint)\s*:\s*["\']([^"\']*graphql[^"\']*)["\']',
            r'fetch\s*\(\s*["\']([^"\']*graphql[^"\']*)["\']',
            r'apollo.*?uri\s*:\s*["\']([^"\']*)["\']',
            r'new\s+ApolloClient.*?uri\s*:\s*["\']([^"\']*)["\']',
            r'createHttpLink.*?uri\s*:\s*["\']([^"\']*)["\']',
        ]

        for pattern in endpoint_patterns:
            match = re.search(pattern, context, re.IGNORECASE)
            if match:
                endpoint = match.group(1)

                # Resolve relative URLs
                if endpoint.startswith("/"):
                    full_url = urljoin(base_url, endpoint)
                else:
                    full_url = endpoint

                # Check if external domain
                try:
                    endpoint_domain = urlparse(full_url).netloc
                    base_domain = urlparse(base_url).netloc
                    external_domain = (
                        endpoint_domain != base_domain and endpoint_domain != ""
                    )
                except Exception:
                    external_domain = False

                return {
                    "endpoint": endpoint,
                    "full_url": full_url,
                    "external_domain": external_domain,
                }

        # Default to common GraphQL endpoint
        return {
            "endpoint": "/graphql",
            "full_url": urljoin(base_url, "/graphql"),
            "external_domain": False,
        }

    def _extract_graphql_fields(self, operation_content: str) -> List[str]:
        """
        Extract field names from GraphQL operation.

        Args:
            operation_content: GraphQL operation content

        Returns:
            List of field names accessed in the operation
        """
        fields = []

        # Simple field extraction (basic implementation)
        # This could be made more sophisticated with a proper GraphQL parser
        field_patterns = [
            r"\{\s*(\w+)",  # Opening field
            r"(\w+)\s*\{",  # Field with sub-selection
            r"(\w+)\s*(?:\([^)]*\))?\s*(?:\{|$)",  # Field with optional args
        ]

        for pattern in field_patterns:
            matches = re.findall(pattern, operation_content)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                if match and match.lower() not in ["query", "mutation", "subscription"]:
                    fields.append(match)

        # Remove duplicates while preserving order
        seen = set()
        unique_fields = []
        for field in fields:
            if field not in seen:
                seen.add(field)
                unique_fields.append(field)

        return unique_fields[:10]  # Limit to first 10 fields for brevity

    def _extract_from_html_attributes(
        self, soup: BeautifulSoup, base_url: str
    ) -> List[Dict]:
        """
        Extract API endpoints from HTML attributes.

        Args:
            soup: BeautifulSoup parsed HTML
            base_url: Base URL for resolving relative URLs

        Returns:
            List of endpoint dictionaries
        """
        endpoints = []

        # Enhanced form action analysis
        forms = soup.find_all("form", action=True)
        for form in forms:
            action = form.get("action", "").strip()
            if action:
                method = form.get("method", "GET").upper()
                full_url = urljoin(base_url, action)

                # Analyze form for additional context
                form_info = self._analyze_form_submission(form)

                # Determine if this is likely an API endpoint based on context
                is_likely_api = self._is_form_likely_api(form, action, form_info)

                endpoint_data = {
                    "endpoint": action,
                    "full_url": full_url,
                    "method": method,
                    "detected_in": "form_action",
                    "form_analysis": form_info,
                    "api_likelihood": is_likely_api,
                    "traditional_api_pattern": self._is_api_endpoint(action),
                }

                endpoints.append(endpoint_data)

        # Check for AJAX forms and async submissions
        ajax_forms = soup.find_all("form", attrs={"data-async": True})
        ajax_forms.extend(soup.find_all("form", attrs={"data-remote": True}))
        ajax_forms.extend(
            soup.find_all("form", class_=re.compile(r"ajax|async|remote"))
        )

        for form in ajax_forms:
            action = form.get("action", "").strip()
            if action:
                method = form.get("method", "POST").upper()  # AJAX forms often POST
                full_url = urljoin(base_url, action)

                form_info = self._analyze_form_submission(form)
                form_info["is_ajax"] = True

                # AJAX forms are highly likely to be API endpoints
                is_likely_api = "high"  # AJAX forms are almost always API calls

                endpoints.append(
                    {
                        "endpoint": action,
                        "full_url": full_url,
                        "method": method,
                        "detected_in": "ajax_form",
                        "form_analysis": form_info,
                        "api_likelihood": is_likely_api,
                        "traditional_api_pattern": self._is_api_endpoint(action),
                    }
                )

        # Check data attributes that might contain API URLs
        elements_with_data = soup.find_all(attrs={"data-api": True})
        elements_with_data.extend(soup.find_all(attrs={"data-url": True}))
        elements_with_data.extend(soup.find_all(attrs={"data-endpoint": True}))
        elements_with_data.extend(soup.find_all(attrs={"data-action": True}))
        elements_with_data.extend(soup.find_all(attrs={"data-async-action": True}))

        for element in elements_with_data:
            for attr in [
                "data-api",
                "data-url",
                "data-endpoint",
                "data-action",
                "data-async-action",
            ]:
                url = element.get(attr)
                if url and self._is_api_endpoint(url):
                    full_url = urljoin(base_url, url)

                    # Try to detect method from element context
                    method = self._detect_method_from_element(element)

                    endpoints.append(
                        {
                            "endpoint": url,
                            "full_url": full_url,
                            "method": method,
                            "detected_in": f"html_attribute_{attr}",
                            "element_context": {
                                "tag": element.name,
                                "classes": element.get("class", []),
                                "id": element.get("id"),
                            },
                        }
                    )

        return endpoints

    def _analyze_form_submission(self, form) -> Dict:
        """
        Analyze form for submission patterns and data types.

        Args:
            form: BeautifulSoup form element

        Returns:
            Dictionary with form analysis
        """
        analysis = {
            "input_count": 0,
            "file_uploads": False,
            "hidden_fields": [],
            "csrf_token": False,
            "submit_buttons": [],
        }

        # Count inputs and analyze types
        inputs = form.find_all(["input", "textarea", "select"])
        analysis["input_count"] = len(inputs)

        for input_elem in inputs:
            input_type = input_elem.get("type", "text").lower()
            input_name = input_elem.get("name", "")

            if input_type == "file":
                analysis["file_uploads"] = True
            elif input_type == "hidden":
                analysis["hidden_fields"].append(input_name)
                # Check for CSRF tokens
                if any(
                    csrf_term in input_name.lower()
                    for csrf_term in ["csrf", "token", "_token", "authenticity"]
                ):
                    analysis["csrf_token"] = True

        # Find submit buttons and their text
        submit_buttons = form.find_all(["input", "button"], type="submit")
        submit_buttons.extend(form.find_all("button", type=lambda x: x != "button"))

        for button in submit_buttons:
            button_text = button.get("value") or button.get_text(strip=True) or ""
            if button_text:
                analysis["submit_buttons"].append(button_text.lower())

        return analysis

    def _is_form_likely_api(self, form, action: str, form_info: Dict) -> str:
        """
        Determine if a form is likely submitting to an API endpoint based on context.

        Args:
            form: BeautifulSoup form element
            action: Form action URL
            form_info: Analysis of the form structure

        Returns:
            Likelihood level: 'high', 'medium', 'low'
        """
        score = 0
        reasons = []

        # High confidence indicators
        if self._is_api_endpoint(action):
            score += 3
            reasons.append("traditional_api_pattern")

        if form_info.get("csrf_token"):
            score += 2
            reasons.append("csrf_protection")

        if form_info.get("file_uploads"):
            score += 2
            reasons.append("file_upload")

        # Medium confidence indicators
        if any("async" in cls.lower() for cls in form.get("class", [])):
            score += 2
            reasons.append("async_class")

        if form.get("data-async") or form.get("data-remote"):
            score += 2
            reasons.append("async_attributes")

        if len(form_info.get("hidden_fields", [])) > 1:
            score += 1
            reasons.append("multiple_hidden_fields")

        # Check for API-like actions in button text
        button_texts = form_info.get("submit_buttons", [])
        api_button_words = [
            "save",
            "submit",
            "delete",
            "remove",
            "update",
            "create",
            "process",
        ]
        if any(word in " ".join(button_texts) for word in api_button_words):
            score += 1
            reasons.append("api_action_buttons")

        # Check for non-page-navigation actions
        action_lower = action.lower()
        if any(
            word in action_lower
            for word in [
                "save",
                "submit",
                "delete",
                "update",
                "create",
                "process",
                "handle",
            ]
        ):
            score += 1
            reasons.append("action_verb_in_url")

        # Exclude obvious static page submissions
        static_patterns = [
            "contact",
            "newsletter",
            "subscribe",
            "login",
            "register",
            "search",
        ]
        if any(pattern in action_lower for pattern in static_patterns):
            score -= 1
            reasons.append("static_form_pattern")

        # Determine likelihood
        if score >= 4:
            return "high"
        elif score >= 2:
            return "medium"
        else:
            return "low"

    def _detect_method_from_element(self, element) -> str:
        """
        Detect HTTP method from HTML element context.

        Args:
            element: BeautifulSoup element

        Returns:
            Detected HTTP method
        """
        # Check element attributes for method hints
        method_attr = element.get("data-method", "").upper()
        if method_attr in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
            return method_attr

        # Check classes for method hints
        classes = " ".join(element.get("class", [])).lower()
        if "delete" in classes:
            return "DELETE"
        elif "post" in classes or "create" in classes:
            return "POST"
        elif "put" in classes or "update" in classes:
            return "PUT"

        # Check element text content for clues
        text = element.get_text(strip=True).lower()
        if any(word in text for word in ["delete", "remove", "destroy"]):
            return "DELETE"
        elif any(word in text for word in ["create", "add", "submit"]):
            return "POST"
        elif any(word in text for word in ["update", "edit", "modify"]):
            return "PUT"

        return "GET"

    def detect_endpoints(self, html_content: str, page_url: str) -> Dict:
        """
        Detect API endpoints from HTML content.

        Args:
            html_content: HTML content to analyze
            page_url: URL of the page being analyzed

        Returns:
            Dictionary with endpoints and script analysis information
        """
        endpoints = []
        endpoint_urls = set()  # Track duplicates
        scripts_found = []
        scripts_analyzed = []

        try:
            soup = BeautifulSoup(html_content, "html.parser")

            # Extract from HTML attributes
            html_endpoints = self._extract_from_html_attributes(soup, page_url)
            for endpoint in html_endpoints:
                key = (endpoint["endpoint"], endpoint["method"])
                if key not in endpoint_urls:
                    endpoints.append(endpoint)
                    endpoint_urls.add(key)

            # Extract from inline JavaScript
            script_tags = soup.find_all("script")
            for script in script_tags:
                if script.string:
                    script_info = {
                        "type": "inline",
                        "content_length": len(script.string),
                        "analyzed": True,
                    }
                    scripts_found.append(script_info)

                    js_endpoints = self._extract_from_javascript(
                        script.string, page_url
                    )
                    script_info["endpoints_found"] = len(js_endpoints)

                    for endpoint in js_endpoints:
                        key = (endpoint["endpoint"], endpoint["method"])
                        if key not in endpoint_urls:
                            endpoint["detected_in"] = "inline_script"
                            endpoints.append(endpoint)
                            endpoint_urls.add(key)

            # Extract from external JavaScript files (if enabled)
            external_scripts = soup.find_all("script", src=True)
            for script in external_scripts:
                src = script.get("src")
                if src:
                    # Resolve relative URLs
                    full_script_url = urljoin(page_url, src)

                    script_info = {
                        "type": "external",
                        "src": src,
                        "full_url": full_script_url,
                        "analyzed": False,
                        "endpoints_found": 0,
                        "fetch_attempted": False,
                        "fetch_successful": False,
                        "error": None,
                    }
                    scripts_found.append(script_info)

                    if self.fetch_external_scripts:
                        # Only fetch scripts from the same domain (or CDNs we trust)
                        script_domain = urlparse(full_script_url).netloc
                        page_domain = urlparse(page_url).netloc

                        script_info["fetch_attempted"] = True

                        # Check cache first
                        if full_script_url in self._script_cache:
                            cached = self._script_cache[full_script_url]
                            script_info["fetch_successful"] = cached.get(
                                "analyzed", False
                            )
                            script_info["analyzed"] = cached.get("analyzed", False)
                            script_info["content_length"] = cached.get(
                                "content_length", 0
                            )
                            script_info["error"] = cached.get("error")

                            # Use cached endpoints
                            if cached.get("analyzed") and cached.get("endpoints"):
                                script_info["endpoints_found"] = len(
                                    cached["endpoints"]
                                )
                                for endpoint in cached["endpoints"]:
                                    key = (endpoint["endpoint"], endpoint["method"])
                                    if key not in endpoint_urls:
                                        # Create a copy and update detected_in for this page
                                        endpoint_copy = endpoint.copy()
                                        endpoint_copy["detected_in"] = (
                                            f"external_script_{src}"
                                        )
                                        endpoints.append(endpoint_copy)
                                        endpoint_urls.add(key)

                            if self.verbose:
                                print(
                                    f"    📄 Using cached analysis for: {full_script_url}"
                                )

                        # Fetch and analyze external scripts from same domain
                        # TODO: add a --fetch-external-scripts-all to include non same domain scripts
                        elif script_domain == page_domain or not script_domain:
                            script_content = self._fetch_external_script(
                                full_script_url
                            )
                            if script_content:
                                script_info["fetch_successful"] = True
                                script_info["analyzed"] = True
                                script_info["content_length"] = len(script_content)
                                scripts_analyzed.append(full_script_url)

                                js_endpoints = self._extract_from_javascript(
                                    script_content, page_url
                                )
                                script_info["endpoints_found"] = len(js_endpoints)

                                # Cache the results
                                self._script_cache[full_script_url] = {
                                    "content": script_content,
                                    "endpoints": js_endpoints,
                                    "analyzed": True,
                                    "content_length": len(script_content),
                                    "error": None,
                                }

                                for endpoint in js_endpoints:
                                    key = (endpoint["endpoint"], endpoint["method"])
                                    if key not in endpoint_urls:
                                        endpoint["detected_in"] = (
                                            f"external_script_{src}"
                                        )
                                        endpoints.append(endpoint)
                                        endpoint_urls.add(key)
                            else:
                                error_msg = "Failed to fetch or parse script content"
                                script_info["error"] = error_msg
                                # Cache the failure
                                self._script_cache[full_script_url] = {
                                    "content": None,
                                    "endpoints": [],
                                    "analyzed": False,
                                    "content_length": 0,
                                    "error": error_msg,
                                }
                        else:
                            error_msg = f"Skipped external domain: {script_domain}"
                            script_info["error"] = error_msg
                            # Cache the skip
                            self._script_cache[full_script_url] = {
                                "content": None,
                                "endpoints": [],
                                "analyzed": False,
                                "content_length": 0,
                                "error": error_msg,
                            }
                            if self.verbose:
                                print(
                                    f"    📄 Skipping external domain script: {full_script_url}"
                                )
                    else:
                        script_info["error"] = "External script fetching disabled"

            if self.verbose and external_scripts and not self.fetch_external_scripts:
                print(
                    f"    📄 Found {len(external_scripts)} external scripts (use --fetch-external-scripts to analyze)"
                )

            # Summary for verbose mode
            if self.verbose and endpoints:
                print(f"    🔍 Found {len(endpoints)} API endpoints on page")
                for ep in endpoints:
                    print(
                        f"      {ep['method']} {ep['endpoint']} ({ep['detected_in']})"
                    )

            if self.verbose and scripts_found:
                print(
                    f"    📄 Found {len(scripts_found)} scripts ({len([s for s in scripts_found if s['analyzed']])} analyzed)"
                )

        except Exception as e:
            if self.verbose:
                print(f"    ❌ Error detecting endpoints: {e}")

        return {
            "endpoints": endpoints,
            "scripts_found": scripts_found,
            "scripts_analyzed_count": len(scripts_analyzed),
            "total_scripts_found": len(scripts_found),
        }

    def get_script_cache_stats(self) -> Dict:
        """
        Get statistics about the script cache for analysis efficiency reporting.

        Returns:
            Dictionary with cache statistics
        """
        total_scripts = len(self._script_cache)
        analyzed_scripts = len(
            [s for s in self._script_cache.values() if s.get("analyzed", False)]
        )
        failed_scripts = len([s for s in self._script_cache.values() if s.get("error")])

        return {
            "total_cached_scripts": total_scripts,
            "successfully_analyzed": analyzed_scripts,
            "failed_to_analyze": failed_scripts,
            "cache_hit_rate": f"{((total_scripts - analyzed_scripts) / max(total_scripts, 1) * 100):.1f}%"
            if total_scripts > 0
            else "0%",
        }
