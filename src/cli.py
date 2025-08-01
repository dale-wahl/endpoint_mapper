"""
CLI Module - Command Line Interface for Intelligent Endpoint Mapper

Handles command-line argument parsing and orchestrates the crawling,
endpoint detection, and output generation process.
"""

import argparse
import json
import sys
import time

from .crawler import WebCrawler
from .endpoint_detector import EndpointDetector
from .relationship_mapper import RelationshipMapper
from .output_formatter import OutputFormatter


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Analyze websites to discover pages and API endpoints",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py https://qa-practice.netlify.app
  python main.py https://example.com --output results.json --max-pages 50
  python main.py https://site.com --delay 1 --verbose
  python main.py https://localhost:3000 --api-key your_api_key_here
  python main.py https://api.example.com --api-key token123 --auth-header X-API-Key
        """,
    )

    parser.add_argument("url", help="Base URL to start crawling from")

    parser.add_argument(
        "--output",
        "-o",
        help="Output file path (default: data/endpoint_analysis.json)",
        default="data/endpoint_analysis.json",
    )

    parser.add_argument(
        "--max-pages",
        type=int,
        default=50,
        help="Maximum number of pages to crawl (default: 50)",
    )

    parser.add_argument(
        "--delay",
        type=float,
        default=0.5,
        help="Delay between requests in seconds (default: 0.5)",
    )

    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose logging"
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)",
    )

    parser.add_argument(
        "--api-key",
        help="API key for authentication (added as Authorization: Bearer <key> header)",
    )

    parser.add_argument(
        "--auth-header",
        help="Custom authorization header name (default: Authorization)",
    )

    parser.add_argument(
        "--fetch-external-scripts",
        action="store_true",
        help="Fetch and analyze external JavaScript files for API endpoints (same-domain only)",
    )

    parser.add_argument(
        "--include-external-apis",
        action="store_true",
        default=True,
        help="Include external API endpoints in results (e.g., jsonplaceholder.typicode.com) (default: True)",
    )

    parser.add_argument(
        "--exclude-external-apis",
        action="store_true",
        help="Exclude external API endpoints from results (overrides --include-external-apis)",
    )

    parser.add_argument(
        "--enable-spa",
        action="store_true",
        help="Enable enhanced SPA (Single Page Application) route discovery",
    )

    return parser.parse_args()


def main() -> None:
    """Main entry point for the CLI application."""
    args = parse_arguments()

    # Ensure output directory exists
    from pathlib import Path

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if args.verbose:
        print(f"🚀 Starting analysis of: {args.url}")
        print(f"📊 Max pages: {args.max_pages}")
        print(f"⏱️  Request delay: {args.delay}s")
        print(f"💾 Output file: {args.output}")
        print("-" * 50)

    start_time = time.time()

    try:
        # Initialize components
        crawler = WebCrawler(
            delay=args.delay,
            timeout=args.timeout,
            verbose=args.verbose,
            api_key=args.api_key,
            auth_header=args.auth_header,
            enable_spa=args.enable_spa,
        )

        # Determine external API inclusion setting
        include_external_apis = (
            args.include_external_apis and not args.exclude_external_apis
        )

        endpoint_detector = EndpointDetector(
            verbose=args.verbose,
            session=crawler.session,
            timeout=args.timeout,
            fetch_external_scripts=args.fetch_external_scripts,
            include_external_apis=include_external_apis,
        )
        relationship_mapper = RelationshipMapper()
        output_formatter = OutputFormatter()

        # Crawl the website
        if args.verbose:
            print("🕷️  Starting website crawl...")

        pages_data = crawler.crawl_site(args.url, max_pages=args.max_pages)

        if args.verbose:
            print(f"📄 Discovered {len(pages_data)} pages")
            print("🔍 Detecting API endpoints...")

        # Detect endpoints for each successfully crawled page
        for page_data in pages_data:
            if page_data.get("crawl_successful", False) and page_data.get("content"):
                endpoint_analysis = endpoint_detector.detect_endpoints(
                    page_data["content"], page_data["url"]
                )
                page_data["api_endpoints"] = endpoint_analysis["endpoints"]
                page_data["scripts_found"] = endpoint_analysis["scripts_found"]
                page_data["scripts_analyzed_count"] = endpoint_analysis[
                    "scripts_analyzed_count"
                ]
                page_data["total_scripts_found"] = endpoint_analysis[
                    "total_scripts_found"
                ]
            else:
                # For failed pages, set empty endpoint and script data
                page_data["api_endpoints"] = []
                page_data["scripts_found"] = []
                page_data["scripts_analyzed_count"] = 0
                page_data["total_scripts_found"] = 0

        # Map relationships
        if args.verbose:
            print("🔗 Mapping page-API relationships...")

        relationship_data = relationship_mapper.map_relationships(pages_data)

        # Generate output
        crawl_time = time.time() - start_time
        output_data = output_formatter.format_output(
            base_url=args.url,
            pages_data=pages_data,
            relationship_data=relationship_data,
            crawl_time=crawl_time,
            enable_spa=args.enable_spa,
            max_pages=args.max_pages,
            fetch_external_scripts=args.fetch_external_scripts,
            include_external_apis=include_external_apis,
            delay=args.delay,
            timeout=args.timeout,
        )

        # Output results
        json_output = json.dumps(output_data, indent=2, ensure_ascii=False)

        # Always save to file now
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(json_output)

        if args.verbose:
            print(f"✅ Results saved to: {args.output}")
            print(f"\n🎉 Analysis completed in {crawl_time:.2f} seconds")
            print(
                f"📊 Found {len(pages_data)} pages and {len(relationship_data.get('api_summary', {}))} unique API endpoints"
            )

            # Print a summary to console
            print(f"\n{'=' * 60}")
            print("📋 ENDPOINT MAPPING SUMMARY")
            print("=" * 60)

            for page_data in pages_data[:5]:  # Show first 5 pages
                endpoints = page_data.get("api_endpoints", [])
                all_links = page_data.get("all_links_found", {})
                internal_count = len(all_links.get("internal_links", []))
                external_count = len(all_links.get("external_links", []))

                print(f"\n🌐 {page_data['url']}")
                print(
                    f"   📊 Links: {internal_count} internal, {external_count} external"
                )

                if endpoints:
                    for ep in endpoints:
                        print(
                            f"   🔗 {ep['method']} {ep['endpoint']} ({ep['detected_in']})"
                        )
                else:
                    print("   🔗 No API endpoints detected")

            if len(pages_data) > 5:
                print(
                    f"\n... and {len(pages_data) - 5} more pages (see {args.output} for full results)"
                )

            # Show relationship summary
            relationships = relationship_data.get("page_relationships", {})
            summary = relationships.get("summary", {})
            if summary:
                print("\n📈 RELATIONSHIP SUMMARY:")
                print(f"   • {summary.get('crawled_pages', 0)} pages crawled")
                print(
                    f"   • {summary.get('discovered_but_not_crawled', 0)} internal pages discovered but not crawled"
                )
                print(
                    f"   • {summary.get('total_external_links_found', 0)} unique external links found"
                )
                print(
                    f"   • {summary.get('total_internal_link_connections', 0)} internal link connections"
                )
        else:
            print(f"Analysis complete. Results saved to: {args.output}")

    except KeyboardInterrupt:
        print("\n❌ Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error during analysis: {str(e)}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
