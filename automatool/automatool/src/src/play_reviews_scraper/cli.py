import argparse
import asyncio
import logging
import sys

from .scraper import PlayStoreReviewScraper


def main():
    """Parses arguments, runs the scraper, and handles output."""
    parser = argparse.ArgumentParser(
        description='Scrape reviews from Google Play Store across different countries'
    )
    parser.add_argument(
        'package_name',
        help='Google Play Store package name (e.g., com.example.app)'
    )
    parser.add_argument(
        '-t', '--threads',
        type=int,
        default=50, # Reduced default threads slightly for stability
        help='Maximum number of concurrent threads for scraping (default: 50)'
    )
    parser.add_argument(
        '-r', '--reviews',
        type=int,
        default=5,
        help='Number of reviews to fetch per language (default: 5)'
    )
    parser.add_argument(
        '-d', '--delay',
        type=float,
        default=0.5,
        help='Delay between requests in seconds (default: 0.5)'
    )
    parser.add_argument(
        '-f', '--format',
        choices=['rich', 'rich-table', 'json'],
        default='rich-table', # Changed default to rich-table
        help='Output format (default: rich-table)'
    )
    parser.add_argument(
        '-o', '--output',
        help='Output file path (only valid with --format=json)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    args = parser.parse_args()

    if args.output and args.format != 'json':
        parser.error("The --output option can only be used with --format=json.")

    # --- Workaround for Windows Event Loop Closed Error ---
    if sys.platform == "win32":
        try:
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        except Exception as e:
             logging.warning(f"Could not set WindowsSelectorEventLoopPolicy: {e}")
    # --- End Workaround ---

    scraper = PlayStoreReviewScraper(
        package_name=args.package_name,
        max_threads=args.threads,
        max_reviews_per_language=args.reviews,
        rate_limit_delay=args.delay,
        output_format=args.format,
        output_file=args.output,
        verbose=args.verbose
    )

    try:
        # Scrape countries (synchronous part using threads)
        results = scraper.scrape_all_countries()

        # Process translations (asynchronous part)
        asyncio.run(scraper.process_translation_queue())

        # Output results (synchronous)
        scraper.output_results(results)

    except Exception as e:
        logging.exception(f"An unexpected error occurred during scraping or processing: {e}")
        sys.exit(1) 

    sys.exit(0) 