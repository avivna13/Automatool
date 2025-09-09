from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

@dataclass
class ReviewData:
    """Represents structured data for a single review scraped from the Google Play Store,
    including metadata added during processing.

    Attributes:
        review_id: The unique identifier assigned to the review by Google Play.
        user_name: The display name of the user who submitted the review.
        content: The original text content of the review as submitted by the user.
        score: The star rating given by the user (typically 1 to 5).
        thumbs_up_count: The number of users who found the review helpful.
        review_created_version: The version name of the app when the review was submitted (e.g., '1.2.3'). May be None.
        at: The timestamp indicating when the review was submitted.
        reply_content: The developer's reply text to the review, if any.
        replied_at: The timestamp indicating when the developer replied, if applicable.
        country_code: The ISO 3166-1 alpha-2 country code for which this review was fetched (e.g., 'US', 'DE').
        fetched_lang: The ISO 639-1 language code that was requested from the API when fetching this review (e.g., 'en', 'de').
        translated_content: The English translation of the original review content, if translation was performed.
        detected_source_lang: The source language code automatically detected by the translation service (e.g., 'hi', 'es'), if applicable.
        possible_countries_str: A comma-separated string of possible countries where the detected language is spoken (cached from Wikidata).
    """
    review_id: str
    user_name: str
    content: Optional[str]
    score: int
    thumbs_up_count: int
    review_created_version: Optional[str]
    at: datetime
    reply_content: Optional[str]
    replied_at: Optional[datetime]

    country_code: str = field(default="XX")
    fetched_lang: str = field(default="en")
    translated_content: Optional[str] = field(default=None)
    detected_source_lang: Optional[str] = field(default=None)
    possible_countries_str: Optional[str] = field(default=None)

    def __post_init__(self):
        """Post-initialization processing to ensure datetime fields are correctly typed."""
        if isinstance(self.at, str):
            try:
                self.at = datetime.fromisoformat(self.at)
            except ValueError:
                pass
        if self.replied_at and isinstance(self.replied_at, str):
             try:
                 self.replied_at = datetime.fromisoformat(self.replied_at)
             except ValueError:
                 self.replied_at = None