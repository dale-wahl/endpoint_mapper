"""
Test suite for SPA (Single Page Application) route detection capabilities.
"""

import pytest
from unittest.mock import Mock, patch
from src.crawler import WebCrawler


class TestSPAFrameworkDetection:
    """Test SPA framework detection capabilities."""

    def test_detect_react_framework(self):
        """Test detection of React framework."""
        crawler = WebCrawler(enable_spa=True)

        react_content = """
        <script>
        import React from 'react';
        import { BrowserRouter as Router, Route, Switch } from 'react-router-dom';
        
        function App() {
            return (
                <Router>
                    <Switch>
                        <Route exact path="/" component={Home} />
                        <Route path="/about" component={About} />
                    </Switch>
                </Router>
            );
        }
        </script>
        """

        framework = crawler._detect_spa_framework(react_content)
        assert framework == "react"

    def test_detect_vue_framework(self):
        """Test detection of Vue.js framework."""
        crawler = WebCrawler(enable_spa=True)

        vue_content = """
        <script>
        import Vue from 'vue';
        import VueRouter from 'vue-router';
        
        const router = new VueRouter({
            routes: [
                { path: '/', component: Home },
                { path: '/about', component: About }
            ]
        });
        </script>
        """

        framework = crawler._detect_spa_framework(vue_content)
        assert framework == "vue"

    def test_detect_angular_framework(self):
        """Test detection of Angular framework."""
        crawler = WebCrawler(enable_spa=True)

        angular_content = """
        <script>
        import { NgModule } from '@angular/core';
        import { RouterModule, Routes } from '@angular/router';
        
        const routes: Routes = [
            { path: '', component: HomeComponent },
            { path: 'about', component: AboutComponent }
        ];
        </script>
        """

        framework = crawler._detect_spa_framework(angular_content)
        assert framework == "angular"

    def test_detect_nextjs_framework(self):
        """Test detection of Next.js framework."""
        crawler = WebCrawler(enable_spa=True)

        nextjs_content = """
        <script>
        import Link from 'next/link';
        import { useRouter } from 'next/router';
        
        export default function Navigation() {
            return (
                <nav>
                    <Link href="/about">About</Link>
                    <Link href="/contact">Contact</Link>
                </nav>
            );
        }
        </script>
        """

        framework = crawler._detect_spa_framework(nextjs_content)
        assert framework == "nextjs"

    def test_detect_no_framework(self):
        """Test when no SPA framework is detected."""
        crawler = WebCrawler(enable_spa=True)

        regular_content = """
        <html>
        <body>
            <h1>Regular HTML page</h1>
            <a href="/about">About</a>
        </body>
        </html>
        """

        framework = crawler._detect_spa_framework(regular_content)
        assert framework is None


class TestSPARouteExtraction:
    """Test SPA route extraction from different patterns."""

    def test_extract_react_routes(self):
        """Test extraction of React Router routes."""
        crawler = WebCrawler(enable_spa=True)

        js_content = """
        <Route exact path="/" component={Home} />
        <Route path="/about" component={About} />
        <Route path="/products/:id" component={Product} />
        <Route path="/users/{userId}/profile" component={Profile} />
        """

        routes = crawler._extract_react_routes(
            js_content, "https://example.com", "example.com"
        )
        expected_routes = {
            "https://example.com/about",
            "https://example.com/products/1",
            "https://example.com/users/1/profile",
        }

        assert routes == expected_routes

    def test_extract_vue_routes(self):
        """Test extraction of Vue Router routes."""
        crawler = WebCrawler(enable_spa=True)

        js_content = """
        const routes = [
            { path: '/', component: Home },
            { path: '/about', component: About },
            { path: '/products/:id', component: Product },
            { path: '/users/{userId}', component: User }
        ];
        """

        routes = crawler._extract_vue_routes(
            js_content, "https://example.com", "example.com"
        )
        expected_routes = {
            "https://example.com/",
            "https://example.com/about",
            "https://example.com/products/1",
            "https://example.com/users/1",
        }

        assert routes == expected_routes

    def test_extract_angular_routes(self):
        """Test extraction of Angular routes."""
        crawler = WebCrawler(enable_spa=True)

        js_content = """
        const routes: Routes = [
            { path: '', component: HomeComponent },
            { path: 'about', component: AboutComponent },
            { path: 'products/:id', component: ProductComponent },
            { path: 'users/{userId}', component: UserComponent }
        ];
        """

        routes = crawler._extract_angular_routes(
            js_content, "https://example.com", "example.com"
        )
        expected_routes = {
            "https://example.com/about",
            "https://example.com/products/1",
            "https://example.com/users/1",
        }

        assert routes == expected_routes

    def test_extract_generic_spa_routes(self):
        """Test extraction of generic SPA routing patterns."""
        crawler = WebCrawler(enable_spa=True)

        js_content = """
        navigate('/dashboard');
        router.push('/settings');
        pushState(null, null, '/profile');
        window.location.pathname = '/help';
        """

        routes = crawler._extract_generic_spa_routes(
            js_content, "https://example.com", "example.com"
        )
        expected_routes = {"https://example.com/dashboard", "https://example.com/help"}

        assert routes == expected_routes

    def test_extract_hash_routes(self):
        """Test extraction of hash-based routes."""
        crawler = WebCrawler(enable_spa=True)

        js_content = """
        window.location.hash = '#/home';
        location.hash = '#/about';
        href = '#/contact';
        """

        routes = crawler._extract_hash_routes(
            js_content, "https://example.com", "example.com"
        )
        expected_routes = {
            "https://example.com/home",
            "https://example.com/about",
            "https://example.com/contact",
        }

        assert routes == expected_routes

    def test_extract_history_api_routes(self):
        """Test extraction of History API routes."""
        crawler = WebCrawler(enable_spa=True)

        js_content = """
        history.pushState({}, '', '/new-page');
        history.replaceState({}, '', '/updated-page');
        pushState(null, null, '/another-page');
        """

        routes = crawler._extract_history_api_routes(
            js_content, "https://example.com", "example.com"
        )
        expected_routes = {
            "https://example.com/new-page",
            "https://example.com/updated-page",
            "https://example.com/another-page",
        }

        assert routes == expected_routes


class TestSPARouteValidation:
    """Test SPA route validation logic."""

    def test_valid_spa_routes(self):
        """Test validation of valid SPA routes."""
        crawler = WebCrawler(enable_spa=True)

        valid_routes = [
            "/home",
            "/about",
            "/products",
            "/users/profile",
            "/dashboard/settings",
            "/api-docs",
        ]

        for route in valid_routes:
            assert crawler._is_valid_spa_route(route) is True

    def test_invalid_spa_routes(self):
        """Test validation of invalid SPA routes."""
        crawler = WebCrawler(enable_spa=True)

        invalid_routes = [
            "",  # Empty string
            "relative-path",  # No leading slash
            "/images/logo.png",  # Image file
            "/styles.css",  # CSS file
            "/script.js",  # JavaScript file
            "/file.pdf",  # PDF file
            "/special@chars!",  # Special characters
            "//double-slash",  # Invalid format
        ]

        for route in invalid_routes:
            assert crawler._is_valid_spa_route(route) is False


class TestSPAParameterResolution:
    """Test parameter resolution in SPA routes."""

    def test_resolve_colon_parameters(self):
        """Test resolution of colon-style parameters (:id)."""
        crawler = WebCrawler(enable_spa=True)

        test_cases = [
            ("/users/:id", "https://example.com/users/1"),
            (
                "/products/:productId/reviews/:reviewId",
                "https://example.com/products/1/reviews/1",
            ),
            ("/category/:slug", "https://example.com/category/example"),
        ]

        for input_route, expected_output in test_cases:
            result = crawler._resolve_spa_route(input_route, "https://example.com")
            assert result == expected_output

    def test_resolve_brace_parameters(self):
        """Test resolution of brace-style parameters ({id})."""
        crawler = WebCrawler(enable_spa=True)

        test_cases = [
            ("/users/{userId}", "https://example.com/users/1"),
            (
                "/products/{productId}/reviews/{reviewId}",
                "https://example.com/products/1/reviews/1",
            ),
            ("/api/{version}/data", "https://example.com/api/example/data"),
        ]

        for input_route, expected_output in test_cases:
            result = crawler._resolve_spa_route(input_route, "https://example.com")
            assert result == expected_output

    def test_resolve_mixed_parameters(self):
        """Test resolution of mixed parameter styles."""
        crawler = WebCrawler(enable_spa=True)

        test_cases = [
            ("/users/:id/posts/{postId}", "https://example.com/users/1/posts/1"),
            ("/api/{version}/users/:userId", "https://example.com/api/example/users/1"),
        ]

        for input_route, expected_output in test_cases:
            result = crawler._resolve_spa_route(input_route, "https://example.com")
            assert result == expected_output

    def test_resolve_no_parameters(self):
        """Test routes without parameters remain unchanged."""
        crawler = WebCrawler(enable_spa=True)

        test_routes = ["/home", "/about", "/contact", "/dashboard/settings"]

        for route in test_routes:
            result = crawler._resolve_spa_route(route, "https://example.com")
            expected = f"https://example.com{route}"
            assert result == expected


class TestSPAIntegration:
    """Test full SPA detection integration."""

    @patch("requests.Session.get")
    def test_spa_routes_in_crawl_results(self, mock_get):
        """Test that SPA routes are included in crawl results."""
        # Mock response with SPA content
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "text/html"}
        mock_response.text = """
        <html>
        <head><title>SPA App</title></head>
        <body>
            <div id="app"></div>
            <script>
                import React from 'react';
                import { BrowserRouter, Route } from 'react-router-dom';
                
                <Route path="/dashboard" component={Dashboard} />
                <Route path="/profile" component={Profile} />
                <Route path="/settings" component={Settings} />
            </script>
        </body>
        </html>
        """
        mock_get.return_value = mock_response

        crawler = WebCrawler(enable_spa=True, verbose=True)

        # Should find SPA routes when crawling
        pages = crawler.crawl_site("https://example.com", max_pages=1)

        # Extract all discovered URLs
        all_urls = set()
        for page_data in pages:
            links_found = page_data.get("all_links_found", {})
            all_urls.update(links_found.get("internal_links", []))

        # Should include SPA routes
        expected_spa_routes = {
            "https://example.com/dashboard",
            "https://example.com/profile",
            "https://example.com/settings",
        }

        # At least some SPA routes should be discovered
        found_spa_routes = all_urls.intersection(expected_spa_routes)
        assert len(found_spa_routes) > 0

    def test_spa_disabled_by_default(self):
        """Test that SPA detection is disabled by default."""
        crawler = WebCrawler()
        assert crawler.enable_spa is False

    def test_spa_enabled_when_requested(self):
        """Test that SPA detection can be enabled."""
        crawler = WebCrawler(enable_spa=True)
        assert crawler.enable_spa is True


if __name__ == "__main__":
    pytest.main([__file__])
