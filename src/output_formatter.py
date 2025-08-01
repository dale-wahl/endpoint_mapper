"""
Output Formatter Module

Formats the crawling and analysis results into structured output formats.
Currently supports JSON output with comprehensive site analysis data.
"""

from typing import List, Dict
from datetime import datetime, timezone


class OutputFormatter:
    """Formats analysis results into structured output."""

    def __init__(self):
        """Initialize the output formatter."""
        pass

    def _format_page_data(self, page_data: Dict) -> Dict:
        """
        Format individual page data for output.

        Args:
            page_data: Raw page data dictionary

        Returns:
            Formatted page data
        """
        formatted_endpoints = []

        for endpoint in page_data.get("api_endpoints", []):
            formatted_endpoints.append(
                {
                    "endpoint": endpoint["endpoint"],
                    "method": endpoint["method"],
                    "detected_in": endpoint["detected_in"],
                    "full_url": endpoint.get("full_url", endpoint["endpoint"]),
                }
            )

        # Include link information
        all_links = page_data.get("all_links_found", {})

        # Format SPA analysis if available
        spa_analysis = page_data.get("spa_analysis")
        formatted_spa = None
        if spa_analysis:
            formatted_spa = {
                "framework": spa_analysis.get("framework", "Unknown"),
                "route_count": spa_analysis.get("route_count", 0),
                "spa_routes": spa_analysis.get("spa_routes", []),
                "route_patterns": spa_analysis.get("route_patterns", {}),
                "features": spa_analysis.get("features", {}),
                "has_spa_indicators": spa_analysis.get("has_spa_indicators", False),
            }

        formatted_page = {
            "url": page_data["url"],
            "title": page_data.get("title", ""),
            "status_code": page_data.get("status_code"),
            "content_type": page_data.get("content_type"),
            "discovered_from": page_data.get("discovered_from"),
            "api_endpoints": formatted_endpoints,
            "endpoint_count": len(formatted_endpoints),
            "scripts_analysis": {
                "scripts_found": page_data.get("scripts_found", []),
                "total_scripts_found": page_data.get("total_scripts_found", 0),
                "scripts_analyzed_count": page_data.get("scripts_analyzed_count", 0),
                "external_scripts_found": len(
                    [
                        s
                        for s in page_data.get("scripts_found", [])
                        if s.get("type") == "external"
                    ]
                ),
                "inline_scripts_found": len(
                    [
                        s
                        for s in page_data.get("scripts_found", [])
                        if s.get("type") == "inline"
                    ]
                ),
            },
            "links_found": {
                "internal_count": len(all_links.get("internal_links", [])),
                "external_count": len(all_links.get("external_links", [])),
                "internal_links": all_links.get("internal_links", []),
                "external_links": all_links.get("external_links", []),
            },
        }

        # Add SPA analysis if available
        if formatted_spa:
            formatted_page["spa_analysis"] = formatted_spa

        return formatted_page

    def _generate_crawl_summary(
        self,
        base_url: str,
        pages_data: List[Dict],
        relationship_data: Dict,
        crawl_time: float,
    ) -> Dict:
        """
        Generate summary information about the crawl.

        Args:
            base_url: Base URL that was crawled
            pages_data: List of page data
            relationship_data: Relationship mapping data
            crawl_time: Time taken for crawl in seconds

        Returns:
            Summary dictionary
        """
        total_endpoints = sum(len(page.get("api_endpoints", [])) for page in pages_data)
        unique_endpoints = len(relationship_data.get("api_summary", {}))

        return {
            "base_url": base_url,
            "crawl_timestamp": datetime.now(timezone.utc).isoformat(),
            "crawl_duration_seconds": round(crawl_time, 2),
            "pages_discovered": len(pages_data),
            "total_api_calls_found": total_endpoints,
            "unique_api_endpoints": unique_endpoints,
            "pages_with_apis": relationship_data.get("page_statistics", {}).get(
                "pages_with_apis", 0
            ),
            "pages_without_apis": relationship_data.get("page_statistics", {}).get(
                "pages_without_apis", 0
            ),
            "avg_apis_per_page": round(
                relationship_data.get("page_statistics", {}).get(
                    "avg_apis_per_page", 0
                ),
                2,
            ),
        }

    def _format_api_summary(self, api_summary: Dict) -> Dict:
        """
        Format API summary for better readability.

        Args:
            api_summary: Raw API summary data

        Returns:
            Formatted API summary
        """
        formatted_summary = {}

        for endpoint, data in api_summary.items():
            formatted_summary[endpoint] = {
                "used_by_pages": data["used_by_pages"],
                "http_methods": data["methods"],
                "detection_sources": data["detected_in"],
                "usage_frequency": data["total_usage"],
                "page_count": len(data["used_by_pages"]),
            }

        return formatted_summary

    def _generate_insights(
        self, pages_data: List[Dict], relationship_data: Dict
    ) -> Dict:
        """
        Generate insights and analysis from the crawled data.

        Args:
            pages_data: List of page data
            relationship_data: Relationship mapping data

        Returns:
            Dictionary with insights
        """
        insights = {
            "most_used_endpoints": [],
            "endpoint_methods_distribution": {},
            "detection_source_distribution": {},
            "page_complexity_analysis": {},
            "potential_issues": [],
        }

        api_summary = relationship_data.get("api_summary", {})

        # Most used endpoints
        if api_summary:
            sorted_endpoints = sorted(
                api_summary.items(), key=lambda x: x[1]["total_usage"], reverse=True
            )
            insights["most_used_endpoints"] = [
                {
                    "endpoint": endpoint,
                    "usage_count": data["total_usage"],
                    "page_count": len(data["used_by_pages"]),
                }
                for endpoint, data in sorted_endpoints[:10]
            ]

        # Method distribution
        method_counts = {}
        source_counts = {}

        for page_data in pages_data:
            for endpoint in page_data.get("api_endpoints", []):
                method = endpoint["method"]
                source = endpoint["detected_in"]

                method_counts[method] = method_counts.get(method, 0) + 1
                source_counts[source] = source_counts.get(source, 0) + 1

        insights["endpoint_methods_distribution"] = method_counts
        insights["detection_source_distribution"] = source_counts

        # Page complexity analysis
        page_complexities = []
        for page_data in pages_data:
            endpoint_count = len(page_data.get("api_endpoints", []))
            page_complexities.append(endpoint_count)

        if page_complexities and len(page_complexities) > 0:
            insights["page_complexity_analysis"] = {
                "min_endpoints_per_page": min(page_complexities),
                "max_endpoints_per_page": max(page_complexities),
                "avg_endpoints_per_page": round(
                    sum(page_complexities) / len(page_complexities), 2
                ),
                "pages_with_no_apis": page_complexities.count(0),
            }

        # Potential issues
        if not api_summary:
            insights["potential_issues"].append(
                "No API endpoints detected - site may be purely static"
            )

        # Check for JavaScript-based detection (more accurate check)
        javascript_sources = [
            source
            for source in source_counts.keys()
            if any(
                js_indicator in source.lower()
                for js_indicator in [
                    "script",
                    "fetch",
                    "ajax",
                    "jquery",
                    "template_literal",
                    "method_pattern",
                ]
            )
        ]

        if not javascript_sources:
            insights["potential_issues"].append(
                "No JavaScript-based API calls detected - may need dynamic analysis"
            )

        return insights

    def format_output(
        self,
        base_url: str,
        pages_data: List[Dict],
        relationship_data: Dict,
        crawl_time: float,
        **kwargs,
    ) -> Dict:
        """
        Format all analysis results into final output structure.

        Args:
            base_url: Base URL that was crawled
            pages_data: List of page data with detected endpoints
            relationship_data: Relationship mapping data
            crawl_time: Time taken for crawl in seconds
            **kwargs: Additional parameters (enable_spa, max_pages, etc.)

        Returns:
            Complete formatted output dictionary
        """
        # Format page data
        formatted_pages = [self._format_page_data(page) for page in pages_data]

        # Generate summary
        crawl_summary = self._generate_crawl_summary(
            base_url, pages_data, relationship_data, crawl_time
        )

        # Format API summary
        api_summary = self._format_api_summary(relationship_data.get("api_summary", {}))

        # Generate insights
        insights = self._generate_insights(pages_data, relationship_data)

        # Generate script analysis summary (optimized to avoid duplication)
        script_summary = self._generate_optimized_script_summary(pages_data)

        # Generate SPA analysis summary if applicable
        spa_summary = self._generate_spa_summary(
            pages_data, kwargs.get("enable_spa", False)
        )

        # Create enhanced metadata
        metadata = self._generate_enhanced_metadata(kwargs)

        # Create final output structure
        output = {
            "crawl_summary": crawl_summary,
            "pages": formatted_pages,
            "api_summary": api_summary,
            "script_analysis_summary": script_summary,
            "page_relationships": relationship_data.get("page_relationships", {}),
            "site_structure": relationship_data.get("site_structure", {}),
            "endpoint_categories": relationship_data.get("endpoint_categories", {}),
            "page_statistics": relationship_data.get("page_statistics", {}),
            "insights": insights,
            "metadata": metadata,
        }

        # Add SPA summary if SPA analysis was enabled
        if spa_summary:
            output["spa_analysis_summary"] = spa_summary

        return output

    def _generate_script_summary(self, pages_data: List[Dict]) -> Dict:
        """
        Generate a summary of all scripts found across the site.

        Args:
            pages_data: List of page data with script information

        Returns:
            Script analysis summary
        """
        all_external_scripts = {}  # URL -> script info
        total_inline_scripts = 0
        total_external_scripts = 0
        scripts_analyzed = 0
        scripts_with_endpoints = 0
        total_endpoints_from_scripts = 0

        for page_data in pages_data:
            scripts_found = page_data.get("scripts_found", [])

            for script in scripts_found:
                if script.get("type") == "inline":
                    total_inline_scripts += 1
                    if script.get("analyzed", False):
                        scripts_analyzed += 1
                    if script.get("endpoints_found", 0) > 0:
                        scripts_with_endpoints += 1
                        total_endpoints_from_scripts += script.get("endpoints_found", 0)

                elif script.get("type") == "external":
                    total_external_scripts += 1
                    script_url = script.get("full_url", script.get("src", ""))

                    if script_url not in all_external_scripts:
                        all_external_scripts[script_url] = {
                            "src": script.get("src", ""),
                            "full_url": script_url,
                            "found_on_pages": [],
                            "analyzed": script.get("analyzed", False),
                            "fetch_attempted": script.get("fetch_attempted", False),
                            "fetch_successful": script.get("fetch_successful", False),
                            "endpoints_found": script.get("endpoints_found", 0),
                            "error": script.get("error"),
                            "content_length": script.get("content_length"),
                        }

                    all_external_scripts[script_url]["found_on_pages"].append(
                        page_data["url"]
                    )

                    if script.get("analyzed", False):
                        scripts_analyzed += 1
                    if script.get("endpoints_found", 0) > 0:
                        scripts_with_endpoints += 1
                        total_endpoints_from_scripts += script.get("endpoints_found", 0)

        return {
            "total_inline_scripts": total_inline_scripts,
            "total_external_scripts": total_external_scripts,
            "unique_external_scripts": len(all_external_scripts),
            "scripts_analyzed": scripts_analyzed,
            "scripts_with_endpoints": scripts_with_endpoints,
            "total_endpoints_from_scripts": total_endpoints_from_scripts,
            "external_scripts_details": list(all_external_scripts.values()),
            "analysis_summary": {
                "external_scripts_fetched": len(
                    [s for s in all_external_scripts.values() if s["fetch_successful"]]
                ),
                "external_scripts_failed": len(
                    [
                        s
                        for s in all_external_scripts.values()
                        if s["fetch_attempted"] and not s["fetch_successful"]
                    ]
                ),
                "external_scripts_skipped": len(
                    [
                        s
                        for s in all_external_scripts.values()
                        if not s["fetch_attempted"]
                    ]
                ),
            },
        }

    def _generate_optimized_script_summary(self, pages_data: List[Dict]) -> Dict:
        """
        Generate an optimized script summary that avoids duplication by analyzing unique scripts.

        Args:
            pages_data: List of page data with script information

        Returns:
            Optimized script analysis summary with unique script analysis
        """
        unique_external_scripts = {}  # URL -> comprehensive script info
        unique_inline_scripts = {}  # content_hash -> script info
        total_inline_scripts = 0
        total_script_references = 0
        scripts_analyzed = 0
        scripts_with_endpoints = 0
        total_endpoints_from_scripts = 0

        for page_data in pages_data:
            scripts_found = page_data.get("scripts_found", [])
            total_script_references += len(scripts_found)

            for script in scripts_found:
                if script.get("type") == "inline":
                    total_inline_scripts += 1
                    # Create a simple hash for inline scripts to identify duplicates
                    content = script.get("content", "")[
                        :100
                    ]  # First 100 chars as identifier
                    content_hash = hash(content) if content else hash(str(script))

                    if content_hash not in unique_inline_scripts:
                        unique_inline_scripts[content_hash] = {
                            "type": "inline",
                            "content_preview": content[:100] + "..."
                            if len(content) > 100
                            else content,
                            "found_on_pages": [],
                            "analyzed": script.get("analyzed", False),
                            "endpoints_found": script.get("endpoints_found", 0),
                        }

                    unique_inline_scripts[content_hash]["found_on_pages"].append(
                        page_data["url"]
                    )

                    if script.get("analyzed", False):
                        scripts_analyzed += 1
                    if script.get("endpoints_found", 0) > 0:
                        scripts_with_endpoints += 1
                        total_endpoints_from_scripts += script.get("endpoints_found", 0)

                elif script.get("type") == "external":
                    script_url = script.get("full_url", script.get("src", ""))

                    if script_url not in unique_external_scripts:
                        unique_external_scripts[script_url] = {
                            "src": script.get("src", ""),
                            "full_url": script_url,
                            "found_on_pages": [],
                            "analyzed": script.get("analyzed", False),
                            "fetch_attempted": script.get("fetch_attempted", False),
                            "fetch_successful": script.get("fetch_successful", False),
                            "endpoints_found": script.get("endpoints_found", 0),
                            "error": script.get("error"),
                            "content_length": script.get("content_length"),
                            "reference_count": 0,  # Track how many times this script is referenced
                        }

                    unique_external_scripts[script_url]["found_on_pages"].append(
                        page_data["url"]
                    )
                    unique_external_scripts[script_url]["reference_count"] += 1

                    # Only count analysis once per unique script
                    if (
                        script.get("analyzed", False)
                        and unique_external_scripts[script_url]["reference_count"] == 1
                    ):
                        scripts_analyzed += 1
                    if (
                        script.get("endpoints_found", 0) > 0
                        and unique_external_scripts[script_url]["reference_count"] == 1
                    ):
                        scripts_with_endpoints += 1
                        total_endpoints_from_scripts += script.get("endpoints_found", 0)

        return {
            "total_script_references": total_script_references,
            "unique_inline_scripts": len(unique_inline_scripts),
            "unique_external_scripts": len(unique_external_scripts),
            "total_inline_script_instances": total_inline_scripts,
            "scripts_analyzed": scripts_analyzed,
            "scripts_with_endpoints": scripts_with_endpoints,
            "total_endpoints_from_scripts": total_endpoints_from_scripts,
            "unique_external_scripts_details": list(unique_external_scripts.values()),
            "unique_inline_scripts_details": list(unique_inline_scripts.values()),
            "analysis_efficiency": {
                "external_scripts_fetched": len(
                    [
                        s
                        for s in unique_external_scripts.values()
                        if s["fetch_successful"]
                    ]
                ),
                "external_scripts_failed": len(
                    [
                        s
                        for s in unique_external_scripts.values()
                        if s["fetch_attempted"] and not s["fetch_successful"]
                    ]
                ),
                "external_scripts_skipped": len(
                    [
                        s
                        for s in unique_external_scripts.values()
                        if not s["fetch_attempted"]
                    ]
                ),
                "most_referenced_scripts": sorted(
                    [
                        (url, data["reference_count"])
                        for url, data in unique_external_scripts.items()
                    ],
                    key=lambda x: x[1],
                    reverse=True,
                )[:5],
            },
        }

    def _generate_spa_summary(self, pages_data: List[Dict], spa_enabled: bool) -> Dict:
        """
        Generate comprehensive SPA analysis summary.

        Args:
            pages_data: List of page data with potential SPA analysis
            spa_enabled: Whether SPA analysis was enabled

        Returns:
            SPA analysis summary or None if not enabled
        """
        if not spa_enabled:
            return None

        pages_with_spa = []
        frameworks_detected = {}
        total_spa_routes = 0
        unique_spa_routes = set()
        spa_features_summary = {
            "has_router_outlet": 0,
            "has_dynamic_imports": 0,
            "has_state_management": 0,
            "has_history_api": 0,
            "has_single_page_container": 0,
        }
        route_patterns_summary = {
            "dynamic_routes": 0,
            "nested_routes": 0,
            "hash_routes": 0,
            "parameter_routes": 0,
        }

        for page_data in pages_data:
            spa_analysis = page_data.get("spa_analysis")
            if spa_analysis and spa_analysis.get("has_spa_indicators"):
                pages_with_spa.append(
                    {
                        "url": page_data["url"],
                        "framework": spa_analysis.get("framework", "Unknown"),
                        "route_count": spa_analysis.get("route_count", 0),
                        "has_spa_indicators": spa_analysis.get(
                            "has_spa_indicators", False
                        ),
                    }
                )

                # Framework tracking
                framework = spa_analysis.get("framework", "Unknown")
                frameworks_detected[framework] = (
                    frameworks_detected.get(framework, 0) + 1
                )

                # Route tracking
                spa_routes = spa_analysis.get("spa_routes", [])
                total_spa_routes += len(spa_routes)
                unique_spa_routes.update(spa_routes)

                # Features tracking
                features = spa_analysis.get("features", {})
                for feature, has_feature in features.items():
                    if feature in spa_features_summary and has_feature:
                        spa_features_summary[feature] += 1

                # Route patterns tracking
                patterns = spa_analysis.get("route_patterns", {})
                for pattern_type, routes in patterns.items():
                    if pattern_type in route_patterns_summary and isinstance(
                        routes, list
                    ):
                        route_patterns_summary[pattern_type] += len(routes)

        if not pages_with_spa:
            return {
                "spa_analysis_enabled": True,
                "pages_with_spa_indicators": 0,
                "frameworks_detected": {},
                "total_spa_routes_found": 0,
                "unique_spa_routes_found": 0,
                "summary": "No SPA indicators detected across crawled pages",
            }

        return {
            "spa_analysis_enabled": True,
            "pages_with_spa_indicators": len(pages_with_spa),
            "pages_analyzed": len(
                [p for p in pages_data if p.get("spa_analysis") is not None]
            ),
            "frameworks_detected": frameworks_detected,
            "total_spa_routes_found": total_spa_routes,
            "unique_spa_routes_found": len(unique_spa_routes),
            "spa_features_summary": spa_features_summary,
            "route_patterns_summary": route_patterns_summary,
            "pages_with_spa_details": pages_with_spa,
            "all_unique_spa_routes": list(unique_spa_routes),
            "insights": {
                "most_common_framework": max(
                    frameworks_detected.items(), key=lambda x: x[1]
                )[0]
                if frameworks_detected
                else None,
                "avg_routes_per_spa_page": round(
                    total_spa_routes / len(pages_with_spa), 2
                )
                if pages_with_spa
                else 0,
                "spa_adoption_rate": f"{len(pages_with_spa)}/{len(pages_data)} pages ({round(len(pages_with_spa) / len(pages_data) * 100, 1)}%)",
            },
        }

    def _generate_enhanced_metadata(self, kwargs: Dict) -> Dict:
        """
        Generate enhanced metadata including run parameters.

        Args:
            kwargs: Additional parameters passed to format_output

        Returns:
            Enhanced metadata dictionary
        """
        metadata = {
            "format_version": "1.1",
            "tool_name": "Intelligent Endpoint Mapper",
            "tool_version": "1.0.0",
            "generation_timestamp": datetime.now(timezone.utc).isoformat(),
            "run_parameters": {
                "spa_analysis_enabled": kwargs.get("enable_spa", False),
                "max_pages": kwargs.get("max_pages"),
                "fetch_external_scripts": kwargs.get("fetch_external_scripts", False),
                "include_external_apis": kwargs.get("include_external_apis", True),
                "request_delay": kwargs.get("delay"),
                "timeout": kwargs.get("timeout"),
            },
            "analysis_capabilities": {
                "api_endpoint_detection": True,
                "script_analysis": True,
                "relationship_mapping": True,
                "spa_route_discovery": kwargs.get("enable_spa", False),
                "external_script_fetching": kwargs.get("fetch_external_scripts", False),
            },
        }

        # Remove None values from run_parameters
        metadata["run_parameters"] = {
            k: v for k, v in metadata["run_parameters"].items() if v is not None
        }

        return metadata
