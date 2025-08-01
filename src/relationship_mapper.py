"""
Relationship Mapper Module

Maps relationships between web pages and the API endpoints they use.
Generates summaries and statistics about page-API connections.
"""

from typing import List, Dict
from collections import defaultdict, Counter


class RelationshipMapper:
    """Maps relationships between pages and API endpoints."""

    def __init__(self):
        """Initialize the relationship mapper."""
        pass

    def _normalize_endpoint(self, endpoint: str) -> str:
        """
        Normalize endpoint URL for consistent grouping while preserving meaningful differences.

        Args:
            endpoint: Raw endpoint URL

        Returns:
            Normalized endpoint URL
        """
        # Remove query parameters and fragments for grouping
        normalized = endpoint.split("?")[0].split("#")[0]

        # DO NOT remove trailing slashes - they can represent different endpoints!
        # Examples:
        # - /api/users/  (collection endpoint)
        # - /api/users   (might be different or redirect)
        # - /api/user/123/ (resource with trailing slash convention)
        # - /api/user/123  (resource without trailing slash)

        # Only normalize protocol and case for the domain part if it's a full URL
        if normalized.lower().startswith(("http://", "https://")):
            from urllib.parse import urlparse, urlunparse

            parsed = urlparse(normalized)
            # Normalize domain to lowercase, keep path as-is (including trailing slash)
            normalized = urlunparse(
                (
                    parsed.scheme.lower(),
                    parsed.netloc.lower(),
                    parsed.path,  # Keep original path including trailing slash
                    parsed.params,
                    "",  # Remove query (already handled above)
                    "",  # Remove fragment (already handled above)
                )
            )

        return normalized

    def _extract_endpoint_info(self, endpoints: List[Dict]) -> Dict:
        """
        Extract and summarize endpoint information.

        Args:
            endpoints: List of endpoint dictionaries

        Returns:
            Summarized endpoint information
        """
        if not endpoints:
            return {}

        # Group by normalized endpoint
        endpoint_groups = defaultdict(list)
        for ep in endpoints:
            normalized = self._normalize_endpoint(ep["endpoint"])
            endpoint_groups[normalized].append(ep)

        # Create summary for each endpoint
        endpoint_summary = {}
        for endpoint, ep_list in endpoint_groups.items():
            methods = list(set(ep["method"] for ep in ep_list))
            detected_in = list(set(ep["detected_in"] for ep in ep_list))
            usage_count = len(ep_list)

            endpoint_summary[endpoint] = {
                "methods": sorted(methods),
                "detected_in": sorted(detected_in),
                "usage_count": usage_count,
            }

        return endpoint_summary

    def _calculate_page_relationships(self, pages_data: List[Dict]) -> Dict:
        """
        Calculate page-to-page relationships including all discovered links.

        Args:
            pages_data: List of page data with discovered links

        Returns:
            Dictionary with comprehensive page relationship mappings
        """
        # Initialize data structures
        crawled_pages = {}
        all_internal_links = set()
        all_external_links = set()
        page_to_internal_links = {}
        page_to_external_links = {}

        # Process crawled pages
        for page_data in pages_data:
            page_url = page_data["url"]
            crawled_pages[page_url] = {
                "title": page_data.get("title", ""),
                "discovered_from": page_data.get("discovered_from"),
                "status_code": page_data.get("status_code"),
                "internal_outbound_links": [],
                "external_outbound_links": [],
                "internal_inbound_links": [],
            }

            # Get all links found on this page
            all_links = page_data.get("all_links_found", {})
            internal_links = all_links.get("internal_links", [])
            external_links = all_links.get("external_links", [])

            page_to_internal_links[page_url] = internal_links
            page_to_external_links[page_url] = external_links

            all_internal_links.update(internal_links)
            all_external_links.update(external_links)

        # Build internal link relationships
        for source_page, target_links in page_to_internal_links.items():
            if source_page in crawled_pages:
                crawled_pages[source_page]["internal_outbound_links"] = target_links

                # Build inbound links for internal pages
                for target_link in target_links:
                    if target_link in crawled_pages:
                        crawled_pages[target_link]["internal_inbound_links"].append(
                            source_page
                        )

        # Add external links to pages
        for source_page, external_links in page_to_external_links.items():
            if source_page in crawled_pages:
                crawled_pages[source_page]["external_outbound_links"] = external_links

        # Create discovered but not crawled internal pages
        discovered_internal_pages = {}
        for internal_link in all_internal_links:
            if internal_link not in crawled_pages:
                # Find which pages discovered this link
                discovered_from = []
                for source_page, target_links in page_to_internal_links.items():
                    if internal_link in target_links:
                        discovered_from.append(source_page)

                discovered_internal_pages[internal_link] = {
                    "title": "Not crawled",
                    "discovered_from": discovered_from,
                    "status_code": None,
                    "internal_outbound_links": [],
                    "external_outbound_links": [],
                    "internal_inbound_links": discovered_from,
                }

        # Create external pages summary
        external_pages_summary = {}
        for external_link in all_external_links:
            # Find which pages link to this external page
            linking_pages = []
            for source_page, target_links in page_to_external_links.items():
                if external_link in target_links:
                    linking_pages.append(source_page)

            external_pages_summary[external_link] = {
                "linked_from": linking_pages,
                "link_count": len(linking_pages),
            }

        # Calculate summary statistics
        relationship_summary = {
            "crawled_pages": len(crawled_pages),
            "discovered_but_not_crawled": len(discovered_internal_pages),
            "total_internal_links_found": len(all_internal_links),
            "total_external_links_found": len(all_external_links),
            "total_internal_link_connections": sum(
                len(page["internal_outbound_links"]) for page in crawled_pages.values()
            ),
            "total_external_link_connections": sum(
                len(page["external_outbound_links"]) for page in crawled_pages.values()
            ),
            "most_linked_internal_pages": sorted(
                [
                    (url, len(page["internal_inbound_links"]))
                    for url, page in {
                        **crawled_pages,
                        **discovered_internal_pages,
                    }.items()
                ],
                key=lambda x: x[1],
                reverse=True,
            )[:10],
            "most_linking_pages": sorted(
                [
                    (url, len(page["internal_outbound_links"]))
                    for url, page in crawled_pages.items()
                ],
                key=lambda x: x[1],
                reverse=True,
            )[:10],
            "most_linked_external_pages": sorted(
                [
                    (url, data["link_count"])
                    for url, data in external_pages_summary.items()
                ],
                key=lambda x: x[1],
                reverse=True,
            )[:10],
        }

        return {
            "crawled_pages": crawled_pages,
            "discovered_internal_pages": discovered_internal_pages,
            "external_pages": external_pages_summary,
            "summary": relationship_summary,
        }

    def _calculate_endpoint_stats(self, pages_data: List[Dict]) -> Dict:
        """
        Calculate statistics about API endpoint usage across all pages.

        Args:
            pages_data: List of page data with detected endpoints

        Returns:
            Dictionary with endpoint usage statistics
        """
        # Collect all endpoints across pages
        all_endpoints = []
        endpoint_to_pages = defaultdict(set)
        page_to_endpoints = defaultdict(set)

        for page_data in pages_data:
            page_url = page_data["url"]
            endpoints = page_data.get("api_endpoints", [])

            for ep in endpoints:
                normalized_endpoint = self._normalize_endpoint(ep["endpoint"])
                all_endpoints.append(normalized_endpoint)
                endpoint_to_pages[normalized_endpoint].add(page_url)
                page_to_endpoints[page_url].add(normalized_endpoint)

        # Count endpoint usage
        endpoint_usage = Counter(all_endpoints)

        # Create summary
        api_summary = {}
        for endpoint, count in endpoint_usage.items():
            pages_using = list(endpoint_to_pages[endpoint])

            # Get methods and detection sources for this endpoint
            methods = set()
            detected_in = set()

            for page_data in pages_data:
                for ep in page_data.get("api_endpoints", []):
                    if self._normalize_endpoint(ep["endpoint"]) == endpoint:
                        methods.add(ep["method"])
                        detected_in.add(ep["detected_in"])

            api_summary[endpoint] = {
                "used_by_pages": sorted(pages_using),
                "methods": sorted(list(methods)),
                "detected_in": sorted(list(detected_in)),
                "total_usage": count,
            }

        return api_summary

    def _calculate_page_stats(self, pages_data: List[Dict]) -> Dict:
        """
        Calculate statistics about pages and their API usage.

        Args:
            pages_data: List of page data with detected endpoints

        Returns:
            Dictionary with page statistics
        """
        stats = {
            "total_pages": len(pages_data),
            "pages_with_apis": 0,
            "pages_without_apis": 0,
            "total_api_calls": 0,
            "unique_endpoints": set(),
            "avg_apis_per_page": 0.0,
        }

        for page_data in pages_data:
            endpoints = page_data.get("api_endpoints", [])

            if endpoints:
                stats["pages_with_apis"] += 1
                stats["total_api_calls"] += len(endpoints)

                for ep in endpoints:
                    normalized = self._normalize_endpoint(ep["endpoint"])
                    stats["unique_endpoints"].add(normalized)
            else:
                stats["pages_without_apis"] += 1

        # Convert set to count
        stats["unique_endpoints"] = len(stats["unique_endpoints"])

        # Calculate average
        if stats["total_pages"] > 0:
            stats["avg_apis_per_page"] = stats["total_api_calls"] / stats["total_pages"]

        return stats

    def map_relationships(self, pages_data: List[Dict]) -> Dict:
        """
        Map relationships between pages and API endpoints.

        Args:
            pages_data: List of page data with detected endpoints

        Returns:
            Dictionary containing relationship mappings and statistics
        """
        # Process each page's endpoints
        for page_data in pages_data:
            endpoints = page_data.get("api_endpoints", [])
            page_data["endpoint_summary"] = self._extract_endpoint_info(endpoints)

        # Calculate overall statistics
        api_summary = self._calculate_endpoint_stats(pages_data)
        page_stats = self._calculate_page_stats(pages_data)
        page_relationships = self._calculate_page_relationships(pages_data)

        # Create relationship mapping
        relationship_data = {
            "api_summary": api_summary,
            "page_statistics": page_stats,
            "page_relationships": page_relationships,
            "endpoint_categories": self._categorize_endpoints(api_summary.keys()),
            "site_structure": {
                "total_pages": len(pages_data),
                "pages_by_domain": self._group_pages_by_domain(pages_data),
                "crawl_depth_analysis": self._analyze_crawl_depth(pages_data),
            },
        }

        return relationship_data

    def _categorize_endpoints(self, endpoints: List[str]) -> Dict:
        """
        Categorize endpoints by their apparent purpose.

        Args:
            endpoints: List of endpoint URLs

        Returns:
            Dictionary with categorized endpoints
        """
        categories = {
            "authentication": [],
            "user_management": [],
            "data_retrieval": [],
            "crud_operations": [],
            "graphql": [],
            "other": [],
        }

        for endpoint in endpoints:
            endpoint_lower = endpoint.lower()

            # Authentication endpoints
            if any(
                auth_term in endpoint_lower
                for auth_term in [
                    "auth",
                    "login",
                    "logout",
                    "token",
                    "session",
                    "signin",
                    "signup",
                ]
            ):
                categories["authentication"].append(endpoint)

            # User management
            elif any(
                user_term in endpoint_lower
                for user_term in ["user", "profile", "account", "member"]
            ):
                categories["user_management"].append(endpoint)

            # GraphQL
            elif "graphql" in endpoint_lower:
                categories["graphql"].append(endpoint)

            # CRUD operations (based on path structure)
            elif any(
                crud_term in endpoint_lower
                for crud_term in ["create", "update", "delete", "edit", "add", "remove"]
            ):
                categories["crud_operations"].append(endpoint)

            # Data retrieval (common patterns)
            elif any(
                data_term in endpoint_lower
                for data_term in ["get", "list", "search", "find", "fetch", "data"]
            ):
                categories["data_retrieval"].append(endpoint)

            else:
                categories["other"].append(endpoint)

        # Remove empty categories
        return {cat: endpoints for cat, endpoints in categories.items() if endpoints}

    def _group_pages_by_domain(self, pages_data: List[Dict]) -> Dict:
        """
        Group pages by their domain/subdomain.

        Args:
            pages_data: List of page data

        Returns:
            Dictionary grouping pages by domain
        """
        from urllib.parse import urlparse

        domain_groups = defaultdict(list)

        for page_data in pages_data:
            parsed = urlparse(page_data["url"])
            domain = parsed.netloc
            domain_groups[domain].append(
                {
                    "url": page_data["url"],
                    "title": page_data.get("title", ""),
                    "path": parsed.path,
                }
            )

        return dict(domain_groups)

    def _analyze_crawl_depth(self, pages_data: List[Dict]) -> Dict:
        """
        Analyze the depth of crawled pages from the root.

        Args:
            pages_data: List of page data

        Returns:
            Dictionary with crawl depth analysis
        """
        from urllib.parse import urlparse

        if not pages_data:
            return {}

        # Assume first page is root
        root_url = pages_data[0]["url"]
        root_parsed = urlparse(root_url)
        root_path_depth = len([p for p in root_parsed.path.split("/") if p])

        depth_analysis = {
            "root_url": root_url,
            "depth_distribution": defaultdict(int),
            "deepest_pages": [],
            "max_depth": 0,
        }

        for page_data in pages_data:
            parsed = urlparse(page_data["url"])
            path_depth = len([p for p in parsed.path.split("/") if p])
            relative_depth = max(0, path_depth - root_path_depth)

            depth_analysis["depth_distribution"][relative_depth] += 1

            if relative_depth > depth_analysis["max_depth"]:
                depth_analysis["max_depth"] = relative_depth
                depth_analysis["deepest_pages"] = [page_data["url"]]
            elif relative_depth == depth_analysis["max_depth"]:
                depth_analysis["deepest_pages"].append(page_data["url"])

        # Convert defaultdict to regular dict
        depth_analysis["depth_distribution"] = dict(
            depth_analysis["depth_distribution"]
        )

        return depth_analysis
