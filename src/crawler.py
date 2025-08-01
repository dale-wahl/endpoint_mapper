"""
Web Crawler Module

Handles the crawling of websites to discover internal pages and links.
Implements polite crawling with rate limiting and respects robots.txt.
"""

import requests
from urllib.parse import urljoin, urlparse
import time
from typing import List, Dict, Set, Optional
from bs4 import BeautifulSoup
import re


class WebCrawler:
    """Web crawler for discovering website structure and internal pages."""

    def __init__(
        self,
        delay: float = 0.5,
        timeout: int = 10,
        verbose: bool = False,
        api_key: Optional[str] = None,
        auth_header: Optional[str] = None,
        enable_spa: bool = False,
    ):
        """
        Initialize the web crawler.

        Args:
            delay: Delay between requests in seconds
            timeout: Request timeout in seconds
            verbose: Enable verbose logging
            api_key: API key for authentication
            auth_header: Custom authorization header name (default: Authorization)
            enable_spa: Enable enhanced SPA route discovery
        """
        self.delay = delay
        self.timeout = timeout
        self.verbose = verbose
        self.enable_spa = enable_spa
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "IntelligentEndpointMapper/1.0 (+https://github.com/assessment/endpoint-mapper)",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
            }
        )

        # Add authentication headers if API key is provided
        if api_key:
            header_name = auth_header or "Authorization"
            # Always use raw API key - let users specify exact format they need
            self.session.headers[header_name] = api_key

            if self.verbose:
                print(f"🔐 Authentication configured: {header_name} header set")

    def _is_same_domain(self, domain1: str, domain2: str) -> bool:
        """
        Check if two domains are the same, accounting for subdomains.

        Args:
            domain1: First domain to compare
            domain2: Second domain to compare

        Returns:
            True if domains are considered the same
        """
        if domain1 == domain2:
            return True

        # Handle www subdomain - treat www.example.com and example.com as same
        if domain1.startswith("www.") and domain1[4:] == domain2:
            return True
        if domain2.startswith("www.") and domain2[4:] == domain1:
            return True

        # Both domains should be subdomains of the same root
        # For now, we'll be conservative and only handle www
        return False

    def _normalize_url(self, url: str) -> str:
        """
        Normalize URL by removing query parameters and fragments.

        Args:
            url: URL to normalize

        Returns:
            Normalized URL
        """
        parsed = urlparse(url)
        # Remove query parameters and fragments
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    def _is_valid_url(self, url: str, base_domain: str) -> bool:
        """
        Check if URL is valid for crawling.

        Args:
            url: URL to validate
            base_domain: Base domain to stay within

        Returns:
            True if URL should be crawled
        """
        try:
            parsed = urlparse(url)

            # Skip non-HTTP(S) URLs
            if parsed.scheme not in ["http", "https"]:
                return False

            # Skip external domains
            if parsed.netloc and not self._is_same_domain(parsed.netloc, base_domain):
                return False

            # Skip common non-page files
            excluded_extensions = {
                ".pdf",
                ".doc",
                ".docx",
                ".xls",
                ".xlsx",
                ".ppt",
                ".pptx",
                ".zip",
                ".rar",
                ".tar",
                ".gz",
                ".7z",
                ".jpg",
                ".jpeg",
                ".png",
                ".gif",
                ".bmp",
                ".svg",
                ".webp",
                ".mp3",
                ".mp4",
                ".avi",
                ".mov",
                ".wmv",
                ".flv",
                ".css",
                ".js",
                ".xml",
                ".json",
                ".rss",
                ".atom",
            }

            path_lower = parsed.path.lower()
            if any(path_lower.endswith(ext) for ext in excluded_extensions):
                return False

            # Skip common non-content paths
            excluded_paths = {
                "/admin",
                "/login",
                "/logout",
                "/register",
                "/signup",
                "/password",
                "/forgot",
                "/reset",
                "/auth",
                "/wp-admin",
                "/wp-content",
                "/wp-includes",
            }

            if any(path_lower.startswith(path) for path in excluded_paths):
                return False

            return True

        except Exception:
            return False

    def _extract_links(self, html_content: str, base_url: str) -> Set[str]:
        """
        Extract internal links from HTML content for crawling.

        Args:
            html_content: HTML content to parse
            base_url: Base URL for resolving relative links

        Returns:
            Set of discovered internal URLs suitable for crawling
        """
        links = set()

        try:
            soup = BeautifulSoup(html_content, "html.parser")
            base_domain = urlparse(base_url).netloc

            # Extract traditional HTML anchor links
            traditional_links = self._extract_html_links(soup, base_url, base_domain)
            links.update(traditional_links)

            # Extract SPA routes from JavaScript (now that HTML hash routes are excluded,
            # all discovered SPA routes are valid for crawling)
            spa_routes = self._extract_spa_routes(
                html_content, base_url, base_domain, for_crawling=True
            )
            links.update(spa_routes)

            if self.verbose and spa_routes:
                print(f"    🎯 Found {len(spa_routes)} SPA routes for crawling")

        except Exception as e:
            if self.verbose:
                print(f"Error extracting links: {e}")

        return links

    def _extract_html_links(
        self, soup: BeautifulSoup, base_url: str, base_domain: str
    ) -> Set[str]:
        """Extract traditional HTML anchor tag links."""
        links = set()

        for link in soup.find_all("a", href=True):
            href = link["href"].strip()
            if href and not href.startswith("#"):
                absolute_url = urljoin(base_url, href)
                clean_url = self._normalize_url(absolute_url)

                if self._is_valid_url(clean_url, base_domain):
                    links.add(clean_url)

        return links

    def _extract_spa_routes(
        self, html_content: str, base_url: str, base_domain: str, for_crawling: bool = False
    ) -> Set[str]:
        """
        Extract SPA routes from JavaScript code using comprehensive pattern matching.

        Args:
            html_content: HTML content containing JavaScript
            base_url: Base URL for resolving relative routes
            base_domain: Domain to validate against
            for_crawling: If True, excludes hash routes that shouldn't be crawled separately

        Returns:
            Set of discovered SPA route URLs
        """
        routes = set()

        try:
            # First detect what SPA framework is being used
            framework = self._detect_spa_framework(html_content)

            if self.verbose and framework:
                print(f"    🔧 Detected SPA framework: {framework}")

            # Extract all JavaScript content
            soup = BeautifulSoup(html_content, "html.parser")
            js_content = ""

            # Combine all script tag content
            for script in soup.find_all("script"):
                if script.string:
                    js_content += script.string + "\n"

            # Get framework-specific routes
            if framework:
                framework_routes = self._extract_framework_routes(
                    js_content, framework, base_url, base_domain
                )
                routes.update(framework_routes)

            # Get generic SPA patterns (works for any framework)
            generic_routes = self._extract_generic_spa_routes(
                js_content, base_url, base_domain
            )
            routes.update(generic_routes)

            # Get hash-based routes (only from JavaScript - true SPA hash routing like #/users/123)
            # Skip hash routes if this is for crawling (they represent fragments of the same page)
            if not for_crawling:
                hash_routes = self._extract_hash_routes(js_content, base_url, base_domain)
                routes.update(hash_routes)

            # Get History API routes
            history_routes = self._extract_history_api_routes(
                js_content, base_url, base_domain
            )
            routes.update(history_routes)

            # NOTE: HTML hash anchors (#portfolio, #about) are NOT included
            # as they represent page fragments, not separate routes

        except Exception as e:
            if self.verbose:
                print(f"Error extracting SPA routes: {e}")

        return routes

    def _detect_spa_framework(self, html_content: str) -> str:
        """
        Detect which SPA framework is being used on the page.

        Args:
            html_content: HTML content to analyze

        Returns:
            Framework name or None if not detected
        """
        frameworks = {
            "react": [
                r"react\.js",
                r"ReactDOM",
                r"react-router",
                r"_react",
                r"React\.",
                r"createRoot",
                r"react/jsx",
                r"jsx-runtime",
            ],
            "vue": [
                r"vue\.js",
                r"Vue\.",
                r"vue-router",
                r"_vue",
                r"createApp",
                r"Vue\.createApp",
                r"@vue/",
            ],
            "angular": [
                r"angular\.js",
                r"@angular/",
                r"\bng-[a-zA-Z]",
                r"_angular",
                r"\bAngular[^a-zA-Z]",
                r"platformBrowserDynamic",
                r"NgModule",
            ],
            "svelte": [r"svelte", r"_svelte", r"SvelteComponent"],
            "nextjs": [r"next\.js", r"_next", r"next/router", r"next/navigation"],
            "nuxtjs": [r"nuxt\.js", r"_nuxt", r"$nuxt"],
            "gatsby": [r"gatsby", r"_gatsby", r"gatsby-link"],
            "ember": [r"ember\.js", r"Ember\.", r"ember-cli"],
        }

        for framework, patterns in frameworks.items():
            if any(
                re.search(pattern, html_content, re.IGNORECASE) for pattern in patterns
            ):
                return framework

        return None

    def _extract_framework_routes(
        self, js_content: str, framework: str, base_url: str, base_domain: str
    ) -> Set[str]:
        """
        Extract routes specific to detected SPA framework.

        Args:
            js_content: JavaScript content to analyze
            framework: Detected framework name
            base_url: Base URL for resolving routes
            base_domain: Domain to validate against

        Returns:
            Set of framework-specific route URLs
        """
        routes = set()

        if framework == "react":
            routes.update(self._extract_react_routes(js_content, base_url, base_domain))
        elif framework == "vue":
            routes.update(self._extract_vue_routes(js_content, base_url, base_domain))
        elif framework == "angular":
            routes.update(
                self._extract_angular_routes(js_content, base_url, base_domain)
            )
        elif framework in ["nextjs", "gatsby"]:
            routes.update(
                self._extract_react_routes(js_content, base_url, base_domain)
            )  # Next.js uses React Router patterns
        elif framework == "nuxtjs":
            routes.update(
                self._extract_vue_routes(js_content, base_url, base_domain)
            )  # Nuxt.js uses Vue Router patterns

        return routes

    def _extract_react_routes(
        self, js_content: str, base_url: str, base_domain: str
    ) -> Set[str]:
        """Extract React Router specific route patterns."""
        routes = set()

        react_patterns = [
            r'<Route\s+path=["\']([^"\']+)["\']',  # <Route path="/users/:id" />
            r'path:\s*["\']([^"\']+)["\']',  # { path: "/dashboard" }
            r'history\.push\(["\']([^"\']+)["\']',  # history.push("/users")
            r'navigate\(["\']([^"\']+)["\']',  # navigate("/home")
            r'useNavigate\(\).*?["\']([^"\']+)["\']',  # const navigate = useNavigate()
            r'Link\s+to=["\']([^"\']+)["\']',  # <Link to="/about" />
            r'NavLink\s+to=["\']([^"\']+)["\']',  # <NavLink to="/contact" />
            r'router\.push\(["\']([^"\']+)["\']',  # router.push('/path')
            r'createBrowserRouter\(\s*\[.*?path:\s*["\']([^"\']+)["\']',  # createBrowserRouter routes
            r'Routes.*?Route.*?path=["\']([^"\']+)["\']',  # Routes with Route children
        ]

        for pattern in react_patterns:
            matches = re.finditer(pattern, js_content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                route = match.group(1)
                if self._is_valid_spa_route(route):
                    full_url = self._resolve_spa_route(route, base_url)
                    if self._is_valid_url(full_url, base_domain):
                        routes.add(full_url)

        return routes

    def _extract_vue_routes(
        self, js_content: str, base_url: str, base_domain: str
    ) -> Set[str]:
        """Extract Vue Router specific route patterns."""
        routes = set()

        vue_patterns = [
            r'path:\s*["\']([^"\']+)["\']',  # { path: '/users/:id' }
            r'\$router\.push\(["\']([^"\']+)["\']',  # this.$router.push('/home')
            r'router\.push\(["\']([^"\']+)["\']',  # router.push('/users')
            r'<router-link\s+to=["\']([^"\']+)["\']',  # <router-link to="/about">
            r'createRouter\(\s*{.*?routes:.*?path:\s*["\']([^"\']+)["\']',  # createRouter config
            r'const\s+routes\s*=.*?path:\s*["\']([^"\']+)["\']',  # const routes = [...]
            r'@click.*?router\.push\(["\']([^"\']+)["\']',  # @click="router.push('/path')"
        ]

        for pattern in vue_patterns:
            matches = re.finditer(pattern, js_content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                route = match.group(1)
                if self._is_valid_spa_route(route):
                    full_url = self._resolve_spa_route(route, base_url)
                    if self._is_valid_url(full_url, base_domain):
                        routes.add(full_url)

        return routes

    def _extract_angular_routes(
        self, js_content: str, base_url: str, base_domain: str
    ) -> Set[str]:
        """Extract Angular Router specific route patterns."""
        routes = set()

        angular_patterns = [
            r'path:\s*["\']([^"\']+)["\']',  # { path: 'users/:id' }
            r'router\.navigate\(\[["\']([^"\']+)["\']\]',  # router.navigate(['/users'])
            r'routerLink=["\']([^"\']+)["\']',  # [routerLink]="/dashboard"
            r'RouterModule\.forRoot\(.*?path:\s*["\']([^"\']+)["\']',  # RouterModule.forRoot config
            r'const\s+routes.*?path:\s*["\']([^"\']+)["\']',  # const routes: Routes = [...]
            r'@Component.*?template.*?routerLink=["\']([^"\']+)["\']',  # Component template routerLinks
        ]

        for pattern in angular_patterns:
            matches = re.finditer(pattern, js_content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                route = match.group(1)
                if self._is_valid_spa_route(route):
                    full_url = self._resolve_spa_route(route, base_url)
                    if self._is_valid_url(full_url, base_domain):
                        routes.add(full_url)

        return routes

    def _extract_generic_spa_routes(
        self, js_content: str, base_url: str, base_domain: str
    ) -> Set[str]:
        """Extract generic SPA route patterns that work across frameworks."""
        routes = set()

        generic_patterns = [
            r'navigate\(["\']([^"\']+)["\']',  # Generic navigate calls
            r'location\.pathname\s*=\s*["\']([^"\']+)["\']',  # location.pathname assignments
            r'window\.location\s*=\s*["\']([^"\']+)["\']',  # window.location assignments
            r'href:\s*["\']([^"\']+)["\']',  # href property assignments
            r'url:\s*["\']([^"\']+)["\']',  # url property assignments
            r'route:\s*["\']([^"\']+)["\']',  # route property assignments
            r'link.*?href=["\']([^"\']+)["\']',  # Dynamic link href
            r'redirect\(["\']([^"\']+)["\']',  # Redirect function calls
            r'goto\(["\']([^"\']+)["\']',  # Goto function calls (Svelte)
        ]

        for pattern in generic_patterns:
            matches = re.finditer(pattern, js_content, re.IGNORECASE)
            for match in matches:
                route = match.group(1)
                if self._is_valid_spa_route(route):
                    full_url = self._resolve_spa_route(route, base_url)
                    if self._is_valid_url(full_url, base_domain):
                        routes.add(full_url)

        return routes

    def _extract_hash_routes(
        self, js_content: str, base_url: str, base_domain: str
    ) -> Set[str]:
        """Extract JavaScript-based hash routing patterns (e.g., #/users/123, not HTML anchors like #portfolio)."""
        routes = set()

        hash_patterns = [
            r'#/([^"\'?\s\)]+)',  # #/users/123
            r'location\.hash\s*=\s*["\']#/([^"\']+)["\']',  # location.hash = "#/home"
            r'window\.location\.hash\s*=\s*["\']#/([^"\']+)["\']',  # window.location.hash = "#/users"
            r'hashchange.*?#/([^"\'?\s\)]+)',  # hashchange event handlers
        ]

        for pattern in hash_patterns:
            matches = re.finditer(pattern, js_content, re.IGNORECASE)
            for match in matches:
                route = match.group(1)
                # Ensure route starts with /
                if not route.startswith("/"):
                    route = "/" + route
                if self._is_valid_spa_route(route):
                    full_url = self._resolve_spa_route(route, base_url)
                    if self._is_valid_url(full_url, base_domain):
                        routes.add(full_url)

        return routes

    def _extract_history_api_routes(
        self, js_content: str, base_url: str, base_domain: str
    ) -> Set[str]:
        """Extract History API based routing patterns."""
        routes = set()

        history_patterns = [
            r'pushState\([^,]*,\s*[^,]*,\s*["\']([^"\']+)["\']',  # pushState(null, '', '/users')
            r'replaceState\([^,]*,\s*[^,]*,\s*["\']([^"\']+)["\']',  # replaceState(null, '', '/home')
            r'history\.pushState.*?["\']([^"\']+)["\']',  # history.pushState calls
            r'history\.replaceState.*?["\']([^"\']+)["\']',  # history.replaceState calls
        ]

        for pattern in history_patterns:
            matches = re.finditer(pattern, js_content, re.IGNORECASE)
            for match in matches:
                route = match.group(1)
                if self._is_valid_spa_route(route):
                    full_url = self._resolve_spa_route(route, base_url)
                    if self._is_valid_url(full_url, base_domain):
                        routes.add(full_url)

        return routes

    def _is_valid_spa_route(self, route: str) -> bool:
        """
        Validate if a route looks like a valid SPA route.

        Args:
            route: Route string to validate

        Returns:
            True if route appears valid
        """
        if not route or not route.strip():
            return False

        route = route.strip()

        # Skip obvious non-routes
        invalid_patterns = [
            r"^(https?|ftp|mailto|tel|sms):",  # External URLs/protocols
            r"\.(js|css|png|jpg|jpeg|gif|svg|pdf|zip|mp4|mp3|woff|woff2|ttf|eot)(\?.*)?$",  # Static assets with optional query params
            r"^[a-zA-Z]+:",  # Other protocols
            r"^\s*$",  # Empty strings
            r"^[#?]",  # Fragments or query strings only
            r"^\*",  # Wildcard routes
            r"javascript:",  # JavaScript protocols
            r"^data:",  # Data URLs
            r"^\+\d+",  # Phone numbers
            r"^www\.",  # Bare domain names
            r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",  # Domain names without protocol
        ]

        for pattern in invalid_patterns:
            if re.search(pattern, route, re.IGNORECASE):
                return False

        # Must start with / or be a valid relative path (Angular-style routes without leading /)
        # But reject relative paths with hyphens (these are likely not route names)
        if route.startswith("/"):
            # Absolute path - always ok if it passes other checks
            pass
        elif route and not route.startswith(".") and not route.startswith("#"):
            # Relative path - reject if it contains hyphens (likely not a route name)
            #TODO: how true is this?
            if "-" in route:
                return False
        else:
            return False

        # Check for reasonable length (avoid very long strings that are likely not routes)
        # TODO: necessary? dislike heuristics
        if len(route) > 200:
            return False

        # Final check: only allow alphanumeric, hyphens, underscores, forward slashes, and parameter patterns
        # But reject paths with double slashes or other malformed patterns
        if not re.match(r"^/?[a-zA-Z0-9\-_/{:}]*$", route) or "//" in route:
            return False

        return True

    def _resolve_spa_route(self, route: str, base_url: str) -> str:
        """
        Resolve a SPA route to a full URL.

        Args:
            route: SPA route (e.g., "/users/:id", "dashboard")
            base_url: Base URL to resolve against

        Returns:
            Full resolved URL
        """
        # Clean up route parameters for URL construction
        cleaned_route = route

        # Replace common route parameters with placeholder values for crawling
        param_replacements = {
            ":id": "1",
            ":userId": "1",
            ":user_id": "1",
            ":productId": "1",
            ":reviewId": "1",
            ":slug": "example",
            ":name": "example",
            "{id}": "1",
            "{userId}": "1",
            "{user_id}": "1",
            "{productId}": "1",
            "{reviewId}": "1",
            "{postId}": "1",
            "{version}": "example",
            "{slug}": "example",
            "{name}": "example",
        }

        for param, replacement in param_replacements.items():
            cleaned_route = cleaned_route.replace(param, replacement)

        # Generic parameter pattern replacement (for any unmatched parameters)
        cleaned_route = re.sub(
            r":([a-zA-Z][a-zA-Z0-9_]*)", "1", cleaned_route
        )  # :paramName -> 1
        cleaned_route = re.sub(
            r"\{([a-zA-Z][a-zA-Z0-9_]*)\}", "1", cleaned_route
        )  # {paramName} -> 1

        # Resolve to full URL
        if cleaned_route.startswith("/"):
            return urljoin(base_url, cleaned_route)
        else:
            return urljoin(base_url, "/" + cleaned_route)

    def _extract_all_links(self, html_content: str, base_url: str) -> Dict:
        """
        Extract ALL links from HTML content, categorized as internal or external.

        Args:
            html_content: HTML content to parse
            base_url: Base URL for resolving relative links

        Returns:
            Dictionary with internal_links and external_links lists
        """
        internal_links = set()
        external_links = set()

        try:
            soup = BeautifulSoup(html_content, "html.parser")
            base_domain = urlparse(base_url).netloc

            # Extract links from anchor tags
            for link in soup.find_all("a", href=True):
                href = link["href"].strip()
                if href and not href.startswith("#"):
                    absolute_url = urljoin(base_url, href)
                    # Normalize URL (remove query params and fragments)
                    clean_url = self._normalize_url(absolute_url)

                    parsed = urlparse(clean_url)

                    # Skip non-HTTP(S) URLs
                    if parsed.scheme not in ["http", "https"]:
                        continue

                    # Categorize as internal or external using subdomain-aware comparison
                    if parsed.netloc == "" or self._is_same_domain(
                        parsed.netloc, base_domain
                    ):
                        if self._is_valid_url(clean_url, base_domain):
                            internal_links.add(clean_url)
                    else:
                        external_links.add(clean_url)

            # Extract links from JavaScript (basic patterns) - these are typically internal
            script_tags = soup.find_all("script")
            for script in script_tags:
                if script.string:
                    # Look for route definitions or navigation calls
                    route_patterns = [
                        r'["\']([/][^"\']*)["\']',  # Quoted paths starting with /
                        r'path:\s*["\']([^"\']+)["\']',  # React Router style
                        r'route\(["\']([^"\']+)["\']',  # Route function calls
                    ]

                    for pattern in route_patterns:
                        matches = re.findall(pattern, script.string)
                        for match in matches:
                            if match.startswith("/") and len(match) > 1:
                                absolute_url = urljoin(base_url, match)
                                normalized_url = self._normalize_url(absolute_url)
                                if self._is_valid_url(normalized_url, base_domain):
                                    internal_links.add(normalized_url)

        except Exception as e:
            if self.verbose:
                print(f"Error extracting all links: {e}")

        return {
            "internal_links": sorted(list(internal_links)),
            "external_links": sorted(list(external_links)),
        }

    def _fetch_page(self, url: str) -> Dict:
        """
        Fetch a single page and return its data.

        Args:
            url: URL to fetch

        Returns:
            Dictionary with page data (always returns a dict, even for failures)
        """
        try:
            if self.verbose:
                print(f"  📄 Fetching: {url}")

            response = self.session.get(url, timeout=self.timeout)

            # Only process HTML content for successful responses
            content_type = response.headers.get("content-type", "").lower()

            # Handle non-2xx status codes
            if not (200 <= response.status_code < 300):
                if self.verbose:
                    print(f"    ⚠️  HTTP {response.status_code}: {url}")
                return {
                    "url": url,
                    "title": None,
                    "content": None,
                    "status_code": response.status_code,
                    "content_type": content_type,
                    "error": f"HTTP {response.status_code}",
                    "crawl_successful": False,
                }

            if "text/html" not in content_type:
                if self.verbose:
                    print(f"    ⚠️  Skipping non-HTML content: {content_type}")
                return {
                    "url": url,
                    "title": None,
                    "content": None,
                    "status_code": response.status_code,
                    "content_type": content_type,
                    "error": f"Non-HTML content: {content_type}",
                    "crawl_successful": False,
                }

            soup = BeautifulSoup(response.text, "html.parser")
            title = soup.find("title")
            title_text = title.get_text().strip() if title else ""

            return {
                "url": url,
                "title": title_text,
                "content": response.text,
                "status_code": response.status_code,
                "content_type": content_type,
                "error": None,
                "crawl_successful": True,
            }

        except requests.RequestException as e:
            if self.verbose:
                print(f"    ❌ Failed to fetch {url}: {e}")
            return {
                "url": url,
                "title": None,
                "content": None,
                "status_code": getattr(e.response, "status_code", None)
                if hasattr(e, "response") and e.response
                else None,
                "content_type": None,
                "error": str(e),
                "crawl_successful": False,
            }
        except Exception as e:
            if self.verbose:
                print(f"    ❌ Unexpected error fetching {url}: {e}")
            return {
                "url": url,
                "title": None,
                "content": None,
                "status_code": None,
                "content_type": None,
                "error": str(e),
                "crawl_successful": False,
            }

    def crawl_site(self, base_url: str, max_pages: int = 100) -> List[Dict]:
        """
        Crawl a website starting from the base URL.

        Args:
            base_url: Starting URL for crawling
            max_pages: Maximum number of pages to crawl

        Returns:
            List of page data dictionaries (includes both successful and failed attempts)
        """
        base_url = base_url.rstrip("/")
        visited = set()
        to_visit = {base_url}
        pages_data = []
        successful_pages = 0  # Track successful pages separately
        page_discovery_map = {}  # Track which page discovered which URL
        all_links_found = {}  # Track ALL links found (internal and external)

        if self.verbose:
            print(f"🚀 Starting crawl from: {base_url}")

        while to_visit and successful_pages < max_pages:
            current_url = to_visit.pop()

            if current_url in visited:
                continue

            visited.add(current_url)

            # Add delay to be polite
            if len(visited) > 1:
                time.sleep(self.delay)

            # Fetch page (always returns a dict, even for failures)
            page_data = self._fetch_page(current_url)

            # Add discovery information
            page_data["discovered_from"] = page_discovery_map.get(current_url, None)

            # Always add page data to results (successful or failed)
            pages_data.append(page_data)

            # Only process links and count toward successful pages if crawl was successful
            if page_data.get("crawl_successful", False) and page_data.get("content"):
                successful_pages += 1

                # Extract ALL links (both internal and external)
                all_links = self._extract_all_links(page_data["content"], current_url)
                page_data["all_links_found"] = all_links

                # Track all links found from this page
                all_links_found[current_url] = all_links

                # Add SPA analysis if enabled
                if self.enable_spa:
                    spa_analysis = self._analyze_spa_features(
                        page_data["content"], current_url
                    )
                    page_data["spa_analysis"] = spa_analysis

                    if self.verbose and spa_analysis.get("spa_routes"):
                        spa_count = len(spa_analysis["spa_routes"])
                        framework = spa_analysis.get("framework", "Unknown")
                        print(
                            f"    🎯 SPA Analysis: {framework} framework, {spa_count} routes detected"
                        )
                else:
                    page_data["spa_analysis"] = None

                # Extract only internal links for further crawling
                internal_links = self._extract_links(page_data["content"], current_url)
                unvisited_links = internal_links - visited

                # Track which page discovered these links
                for link in unvisited_links:
                    if link not in page_discovery_map:
                        page_discovery_map[link] = current_url

                to_visit.update(unvisited_links)

                if self.verbose:
                    internal_count = len(internal_links)
                    external_count = len(all_links["external_links"])
                    print(
                        f"    🔗 Found {internal_count} internal + {external_count} external links ({len(unvisited_links)} new internal)"
                    )
            else:
                # For failed pages, add empty link data
                page_data["all_links_found"] = {
                    "internal_links": [],
                    "external_links": [],
                }
                if self.verbose:
                    # TODO: this should only appear if page was also not skipped (e.g., due to non-HTML content)
                    print("    ❌ Failed to process links due to crawl failure")

        # Add all discovered links to successful pages
        for page_data in pages_data:
            if page_data.get("crawl_successful", False):
                page_data["all_discovered_links"] = all_links_found

        if self.verbose:
            print(
                f"✅ Crawl completed: {successful_pages} successful pages, {len(pages_data)} total attempts"
            )

        return pages_data

    def _analyze_spa_features(self, html_content: str, base_url: str) -> Dict:
        """
        Comprehensive SPA analysis of a page.

        Args:
            html_content: HTML content to analyze
            base_url: Base URL of the page

        Returns:
            Dictionary with comprehensive SPA analysis data
        """
        if not self.enable_spa:
            return {}

        from urllib.parse import urlparse

        parsed_url = urlparse(base_url)
        base_domain = parsed_url.netloc

        # Detect SPA framework
        framework = self._detect_spa_framework(html_content)

        # Extract all SPA routes
        spa_routes = self._extract_spa_routes(html_content, base_url, base_domain)

        # Analyze route patterns
        route_patterns = self._analyze_route_patterns(list(spa_routes))

        # Extract SPA-specific features
        features = self._extract_spa_specific_features(html_content, framework)

        analysis = {
            "framework": framework,
            "spa_routes": list(spa_routes),
            "route_count": len(spa_routes),
            "route_patterns": route_patterns,
            "features": features,
            "has_spa_indicators": framework is not None
            or len(spa_routes) > 0
            or any(features.values()),
        }

        return analysis

    def _analyze_route_patterns(self, routes: List[str]) -> Dict:
        """
        Analyze patterns in discovered SPA routes.

        Args:
            routes: List of route URLs

        Returns:
            Dictionary with route pattern analysis
        """
        if not routes:
            return {}

        patterns = {
            "dynamic_routes": [],
            "nested_routes": [],
            "hash_routes": [],
            "parameter_routes": [],
            "route_segments": {},
        }

        for route in routes:
            parsed = urlparse(route)

            # Check for hash routes
            if parsed.fragment:
                patterns["hash_routes"].append(route)

            # Analyze path segments
            path = parsed.path.strip("/")
            if path:
                segments = path.split("/")
                for i, segment in enumerate(segments):
                    level = f"level_{i}"
                    if level not in patterns["route_segments"]:
                        patterns["route_segments"][level] = set()
                    patterns["route_segments"][level].add(segment)

                # Check for dynamic/parameter routes
                if any(
                    seg.startswith(":") or seg.startswith("{") or seg.startswith("[")
                    for seg in segments
                ):
                    patterns["dynamic_routes"].append(route)
                    patterns["parameter_routes"].append(route)

                # Check for nested routes (3+ segments)
                if len(segments) >= 3:
                    patterns["nested_routes"].append(route)

        # Convert sets to lists for JSON serialization
        for level, segments in patterns["route_segments"].items():
            patterns["route_segments"][level] = list(segments)

        return patterns

    def _extract_spa_specific_features(self, html_content: str, framework: str) -> Dict:
        """
        Extract SPA-specific features and indicators.

        Args:
            html_content: HTML content to analyze
            framework: Detected framework

        Returns:
            Dictionary with SPA features
        """
        features = {
            "has_router_outlet": False,
            "has_dynamic_imports": False,
            "has_state_management": False,
            "has_history_api": False,
            "has_single_page_container": False,
            "framework_specific_features": {},
        }

        # Check for router outlets/containers
        router_patterns = [
            r"<router-outlet",
            r"<router-view",
            r'<div[^>]+id=["\']app["\']',
            r'<div[^>]+id=["\']root["\']',
            r'<main[^>]+id=["\']app',
        ]

        for pattern in router_patterns:
            if re.search(pattern, html_content, re.IGNORECASE):
                features["has_router_outlet"] = True
                break

        # Check for dynamic imports
        dynamic_import_patterns = [
            r"import\s*\(",
            r"require\.ensure\s*\(",
            r"System\.import\s*\(",
            r"lazy\s*\(\s*\(\s*\)\s*=>\s*import",
        ]

        for pattern in dynamic_import_patterns:
            if re.search(pattern, html_content, re.IGNORECASE):
                features["has_dynamic_imports"] = True
                break

        # Check for state management
        state_patterns = [
            r"redux",
            r"vuex",
            r"mobx",
            r"zustand",
            r"recoil",
            r"ngrx",
            r"akita",
            r"ngxs",
        ]

        for pattern in state_patterns:
            if re.search(pattern, html_content, re.IGNORECASE):
                features["has_state_management"] = True
                break

        # Check for History API usage
        history_patterns = [
            r"history\.pushState",
            r"history\.replaceState",
            r"window\.history",
            r"History\.push",
            r"History\.replace",
        ]

        for pattern in history_patterns:
            if re.search(pattern, html_content, re.IGNORECASE):
                features["has_history_api"] = True
                break

        # Check for single page container
        if len(re.findall(r"<body[^>]*>", html_content, re.IGNORECASE)) == 1:
            body_content = re.search(
                r"<body[^>]*>(.*?)</body>", html_content, re.DOTALL | re.IGNORECASE
            )
            if body_content:
                # Count major content containers
                containers = len(
                    re.findall(
                        r"<(div|main|section|article)[^>]*>",
                        body_content.group(1),
                        re.IGNORECASE,
                    )
                )
                if containers <= 3:  # Likely SPA with minimal container structure
                    features["has_single_page_container"] = True

        # Framework-specific features
        if framework == "React":
            features["framework_specific_features"] = {
                "has_jsx": bool(
                    re.search(r"React\.createElement|jsx", html_content, re.IGNORECASE)
                ),
                "has_hooks": bool(
                    re.search(
                        r"useState|useEffect|useContext", html_content, re.IGNORECASE
                    )
                ),
            }
        elif framework == "Vue":
            features["framework_specific_features"] = {
                "has_directives": bool(
                    re.search(r"v-if|v-for|v-model|v-show", html_content, re.IGNORECASE)
                ),
                "has_composition": bool(
                    re.search(
                        r"setup\s*\(|ref\s*\(|reactive\s*\(",
                        html_content,
                        re.IGNORECASE,
                    )
                ),
            }
        elif framework == "Angular":
            features["framework_specific_features"] = {
                "has_directives": bool(
                    re.search(
                        r"\*ngIf|\*ngFor|\[ngClass\]|\(click\)",
                        html_content,
                        re.IGNORECASE,
                    )
                ),
                "has_services": bool(
                    re.search(r"@Injectable|@Service", html_content, re.IGNORECASE)
                ),
            }

        return features
