import asyncio
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from queue import Queue
from typing import Dict, List, Union, Optional

import httpx
import pycountry
from google_play_scraper import Sort, reviews
from googletrans import Translator
from rich import box
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from .constants import NA_STRING, BAD_WORD_PATTERNS, INTERESTING_COUNTRIES_SET
from .models import ReviewData
from .utils import (
    DateTimeEncoder, get_primary_language_code, get_countries_for_language,
    highlight_bad_words, truncate_text, get_country_name
)


class PlayStoreReviewScraper:
    """Scrapes and processes Google Play Store reviews for a given package.

    Handles fetching reviews from multiple countries in English and local languages,
    translating local language reviews, and outputting results.
    """

    def __init__(
        self,
        package_name: str,
        max_threads: int = 100,
        max_reviews_per_language: int = 5,
        rate_limit_delay: float = 0.5,
        output_format: str = 'rich',
        output_file: str = None,
        verbose: bool = False
    ):
        """
        Initialize the Play Store Review Scraper.

        Args:
            package_name: The Google Play Store package name (e.g., com.example.app).
            max_threads: Maximum number of concurrent threads for scraping.
            max_reviews_per_language: Number of reviews to fetch per language per country.
            rate_limit_delay: Delay in seconds between requests to avoid API limits.
            output_format: The format for the output ('rich', 'rich-table', 'json').
            output_file: File path to save results (only for 'json' format).
            verbose: Enable verbose logging output.
        """
        self.package_name = package_name
        self.max_threads = max_threads
        self.max_reviews_per_language = max_reviews_per_language
        self.rate_limit_delay = rate_limit_delay
        self.output_format = output_format
        self.output_file = output_file

        # Build a list of available country codes.
        try:
            self.country_codes = [country.alpha_2 for country in pycountry.countries]
        except Exception as e:
            logging.error(f"Could not load country codes from pycountry: {e}")
            self.country_codes = ['US'] # Fallback to US
            logging.warning("Falling back to scraping only the US country code.")

        self.console = Console()

        # Configure logging.
        log_level = logging.DEBUG if verbose else logging.INFO
        # Use basicConfig only if no handlers are configured yet
        if not logging.getLogger().handlers:
             logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
        else:
             logging.getLogger().setLevel(log_level)

        self.logger = logging.getLogger(__name__)

        # Suppress INFO logs from httpx used by googletrans
        logging.getLogger("httpx").setLevel(logging.WARNING)

        self.translator = Translator()
        # Queue to hold ReviewData objects that require translation.
        self.translation_queue: Queue[ReviewData] = Queue()

    def fetch_reviews_for_language(self, country_code: str, lang: str) -> List[ReviewData]:
        """
        Fetch reviews for a specified country code and language.
        Returns a list of ReviewData objects.
        Rate-limits the requests to avoid overloading the API.
        """
        try:
            raw_reviews, _ = reviews(
                self.package_name,
                lang=lang,
                country=country_code,
                count=self.max_reviews_per_language,
                sort=Sort.NEWEST
            )
            time.sleep(self.rate_limit_delay)
            # Map raw dicts to ReviewData objects
            processed_reviews = [
                ReviewData(
                    review_id=r.get('reviewId'),
                    user_name=r.get('userName'),
                    content=r.get('content'),
                    score=r.get('score'),
                    thumbs_up_count=r.get('thumbsUpCount'),
                    review_created_version=r.get('reviewCreatedVersion'),
                    at=r.get('at'),
                    reply_content=r.get('replyContent'),
                    replied_at=r.get('repliedAt'),
                    country_code=country_code, 
                    fetched_lang=lang 
                )
                for r in raw_reviews if r.get('reviewId') 
            ]
            return processed_reviews
        except Exception as e:
            self.logger.error(f"Error fetching reviews for {country_code}/{lang}: {e}")
            return []

    def fetch_reviews_for_country(self, country_code: str) -> Dict[str, Union[Dict[str, Union[List[ReviewData], Dict]], str]]:
        """
        Fetch local language reviews for a country (English fetching currently skipped).
        Non-English ReviewData objects are added to the translation queue.
        Returns a dict containing lists of ReviewData objects or an error string.
        """
        country_name = get_country_name(country_code)
        try:
            english_reviews: List[ReviewData] = []

            # Determine and fetch local language reviews
            local_lang_code = get_primary_language_code(country_code)
            local_reviews: List[ReviewData] = []
            reviews_added_to_queue = 0
            if local_lang_code.lower() != 'en':
                local_reviews = self.fetch_reviews_for_language(country_code, local_lang_code)
                for review in local_reviews:
                    if review.content:
                        self.translation_queue.put(review)
                        reviews_added_to_queue += 1

            # Prepare result structure
            return {
                country_name: {
                    'english': english_reviews,
                    'local': local_reviews,
                    'metadata': {
                        'language_code': local_lang_code,
                        'timestamp': datetime.now().isoformat()
                    }
                }
            }
        except Exception as e:
            self.logger.error(f"Error processing {country_name} ({country_code}): {e}")
            return {country_name: f"Error: {e}"}

    def scrape_all_countries(self) -> List[Dict]:
        """
        Scrape reviews for all available countries concurrently.

        Uses a ThreadPoolExecutor to manage concurrent requests and displays
        progress using the Rich library.

        Returns:
            A list of dictionaries, where each dictionary represents the scraped
            data for one country (or an error message if scraping failed).
        """
        results = []
        if not self.country_codes:
            self.logger.error("No country codes available to scrape.")
            return []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            task_desc = f"[cyan]Scraping {len(self.country_codes)} countries..."
            task = progress.add_task(task_desc, total=len(self.country_codes))

            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                future_to_country = {
                    executor.submit(self.fetch_reviews_for_country, code): code
                    for code in self.country_codes
                }
                for future in as_completed(future_to_country):
                    country_code = future_to_country[future]
                    country_name = get_country_name(country_code)
                    try:
                        country_result = future.result()
                        if country_result and country_name in country_result:
                            details = country_result.get(country_name, {})
                            if isinstance(details, dict) and (details.get('english') or details.get('local')):
                                results.append(country_result)
                        else:
                             self.logger.warning(f"Received invalid result structure for {country_name} ({country_code})")
                    except Exception as e:
                        self.logger.error(f"Error processing result future for {country_name} ({country_code}): {e}")
                    finally:
                        progress.advance(task)
        return results

    async def process_translation_queue(self):
        """
        Process and translate ReviewData objects in the translation queue asynchronously.
        """
        queue_size = self.translation_queue.qsize()
        if queue_size == 0:
            self.logger.info("No reviews in the translation queue.")
            return

        self.logger.info(f"Translating {queue_size} reviews in the queue...")

        tasks = []
        processed_reviews: List[ReviewData] = []

        # Drain the queue and create translation tasks
        while not self.translation_queue.empty():
            review: ReviewData = self.translation_queue.get()
            tasks.append(self.translate_single_review(review))
            self.translation_queue.task_done()

        # Run translation tasks concurrently
        if tasks:
            translation_results = await asyncio.gather(*tasks)
            processed_reviews = [res for res in translation_results if res is not None]

        self.logger.info(f"Translation processing finished. Successfully processed {len(processed_reviews)} reviews.")

    async def translate_single_review(self, review: ReviewData) -> Optional[ReviewData]:
        """Translates a single ReviewData object. Returns modified object or None on error."""
        try:
            original_text = review.content
            review.detected_source_lang = NA_STRING # Default if no content or translation happens
            if original_text:
                translated = await self.translator.translate(original_text, src='auto', dest='en')
                review.translated_content = translated.text
                review.detected_source_lang = translated.src # STORE DETECTED LANGUAGE
            else:
                review.translated_content = NA_STRING
            return review
        except (httpx.HTTPStatusError, httpx.RequestError) as net_err:
            self.logger.warning(f"Network error translating review ID {review.review_id}: {net_err}")
            review.translated_content = NA_STRING
            review.detected_source_lang = "Error"
        except TypeError as type_err:
            review_id_log = review.review_id if hasattr(review, 'review_id') else 'N/A'
            self.logger.warning(f"Type error translating review ID {review_id_log}: {type_err} - Text: '{review.content if hasattr(review, 'content') else 'N/A'}'")
            if hasattr(review, 'translated_content'):
                review.translated_content = NA_STRING
            if hasattr(review, 'detected_source_lang'):
                review.detected_source_lang = "Error"
        except Exception as e:
            review_id_log = review.review_id if hasattr(review, 'review_id') else 'N/A'
            self.logger.warning(f"Failed to translate review ID {review_id_log}: {e}")
            if hasattr(review, 'translated_content'):
                review.translated_content = NA_STRING
            if hasattr(review, 'detected_source_lang'):
                 review.detected_source_lang = "Error"
        return None

    def output_results(self, results: List[Dict]):
        """
        Output the scraped and processed review results in the selected format.
        Flattens, de-duplicates, enriches, and formats the review data.
        """
        # 1. Flatten results
        all_reviews: List[ReviewData] = []
        for country_data in results:
            for country_name, details in country_data.items():
                if isinstance(details, dict):
                    all_reviews.extend(details.get('english', []))
                    all_reviews.extend(details.get('local', []))

        if not all_reviews:
            self.logger.warning("No valid review data found after flattening results.")
            return

        # 2. De-duplicate based on content
        seen_content = set()
        deduplicated_reviews: List[ReviewData] = []
        reviews_discarded = 0
        for review in all_reviews:
            if review.content is None or review.content not in seen_content:
                deduplicated_reviews.append(review)
                if review.content is not None:
                    seen_content.add(review.content)
            else:
                reviews_discarded += 1
        if reviews_discarded > 0:
            self.logger.info(f"Discarded {reviews_discarded} duplicate reviews based on original content.")

        if not deduplicated_reviews:
            self.logger.warning("No reviews remaining after de-duplication.")
            return

        # 3. Enrich with Possible Countries and Format for Output
        lang_country_cache: Dict[str, List[str]] = {}
        output_rows = []

        for review in deduplicated_reviews:
            possible_countries_str = NA_STRING
            detected_lang = review.detected_source_lang
            if detected_lang and detected_lang not in [NA_STRING, "Error", "en"]:
                all_countries = get_countries_for_language(detected_lang, lang_country_cache)
                filtered_countries = [
                    country for country in all_countries
                    if country.lower() in INTERESTING_COUNTRIES_SET
                ]
                if filtered_countries:
                    possible_countries_str = ", ".join(filtered_countries)
            elif detected_lang == "en":
                possible_countries_str = "all"

            review.possible_countries_str = possible_countries_str

            original_content = truncate_text(review.content)
            translated_content = NA_STRING
            if review.translated_content and review.translated_content != NA_STRING:
                highlighted = highlight_bad_words(review.translated_content, BAD_WORD_PATTERNS)
                translated_content = truncate_text(highlighted)

            row = {
                'Score': str(review.score),
                'Date': str(review.at.date()) if review.at else NA_STRING,
                'Original Content': original_content,
                'Translated Content': translated_content,
                'Detected Lang': detected_lang or NA_STRING,
                'Possible Countries': review.possible_countries_str or NA_STRING
            }
            output_rows.append(row)

        if self.output_format == 'json':
            output_list = [review.__dict__ for review in deduplicated_reviews]
            output_data = json.dumps(output_list, indent=2, cls=DateTimeEncoder)
            if self.output_file:
                try:
                    with open(self.output_file, 'w', encoding='utf-8') as f:
                        f.write(output_data)
                    self.logger.info(f"Results written to {self.output_file}")
                except IOError as e:
                     self.logger.error(f"Error writing results to file {self.output_file}: {e}")
            else:
                print(output_data)

        elif self.output_format == 'rich-table':
            if not output_rows:
                self.logger.info("No valid reviews found to display in table format.")
                return

            table = Table(
                show_header=True,
                header_style="bold cyan",
                box=box.ROUNDED,
                show_lines=True,
                title=f"[bold]Reviews for {self.package_name}[/bold]",
                padding=(0, 1)
            )

            table.add_column("Score", style="dim", width=7, justify="center")
            table.add_column("Date", style="dim", width=12, justify="right")
            table.add_column("Original", style="dim", ratio=1)
            table.add_column("Translated", style="dim", ratio=2)
            table.add_column("Lang", style="dim", width=8, justify="center")
            table.add_column("Possible Countries", style="dim", ratio=1)

            def style_na(value: str) -> str:
                return f"[dim]{NA_STRING}[/dim]" if value == NA_STRING else value

            for row_data in output_rows:
                score_str = row_data.get('Score', NA_STRING)
                score_display = NA_STRING 
                if score_str != NA_STRING:
                    try:
                        score_val = int(score_str)
                        score_val = max(1, min(5, score_val))

                        stars = "★" * score_val + "☆" * (5 - score_val)
                        score_display = f"[gold1]{stars}[/gold1]"
                    except (ValueError, TypeError):
                        score_display = style_na(str(score_str))
                else:
                    score_display = style_na(score_str)

                styled_row = [
                    score_display, 
                    style_na(row_data.get('Date', NA_STRING)),
                    style_na(row_data.get('Original Content', NA_STRING)),
                    style_na(row_data.get('Translated Content', NA_STRING)),
                    style_na(row_data.get('Detected Lang', NA_STRING)),
                    style_na(row_data.get('Possible Countries', NA_STRING))
                ]
                table.add_row(*styled_row)

            self.console.print(table)

        else: 
            self.console.print(deduplicated_reviews) 