import logging
import re
from datetime import datetime
from json import JSONEncoder
from typing import Dict, List

import pycountry
from SPARQLWrapper import SPARQLWrapper, JSON

from .constants import HIGHLIGHT_STYLE, NA_STRING


class DateTimeEncoder(JSONEncoder):
    """JSON encoder subclass that knows how to encode datetime objects."""
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

def highlight_bad_words(text: str, patterns: List[re.Pattern]) -> str:
    """
    Highlight bad words in a given text using the precompiled regex patterns.
    Returns the modified text with highlighted words.
    """
    if not text:
        return text
    for pattern in patterns:
        text = pattern.sub(HIGHLIGHT_STYLE, text)
    return text

def get_country_name(country_code: str) -> str:
    """Return the country name for a given country code."""
    try:
        country = pycountry.countries.get(alpha_2=country_code)
        return country.name if country else country_code
    except Exception:
        # Use the module-level logger
        logging.warning(f"Could not find country name for code: {country_code}")
        return country_code # Return code if lookup fails

def get_primary_language_code(country_code: str) -> str:
    """
    Get the primary language code (ISO 639-1 alpha-2) for a given country code.
    Falls back to English ('en') if no language information is available
    or if the country code itself is used as the lookup key (incorrect usage
    seen in some pycountry versions or specific country lookups).
    """
    try:
        country = pycountry.countries.get(alpha_2=country_code)
        if country and hasattr(country, 'official_name'):
            language = pycountry.languages.get(alpha_2=country_code.lower())
            if language and hasattr(language, 'alpha_2'):
                 return language.alpha_2
    except Exception as e:
        logging.warning(f"Could not determine language for {country_code}, falling back to 'en'. Error: {e}")
    return 'en'

def truncate_text(text: str, max_length: int = 200) -> str:
    """
    Truncate the text to a specified maximum length.
    If the text is longer than max_length, add an ellipsis.
    """
    if not text:
        return NA_STRING
    return text if len(text) <= max_length else text[:max_length] + '...'

def get_countries_for_language(lang_code: str, cache: Dict[str, List[str]]) -> List[str]:
    """
    Query Wikidata to find country names where a given language is spoken.
    Uses a cache to avoid repeated queries for the same language code.

    Args:
        lang_code: ISO 639-1 language code (e.g., 'en', 'hi').
        cache: A dictionary used for caching results within a single run.

    Returns:
        A list of country names, or an empty list if none found or on error.
    """
    if not lang_code or len(lang_code) != 2:
        return [] # Invalid language code

    if lang_code in cache:
        return cache[lang_code]

    endpoint = "https://query.wikidata.org/sparql"
    sparql_query = f"""
    SELECT DISTINCT ?countryLabel WHERE {{
      ?language wdt:P218 "{lang_code}".
      ?country wdt:P37 ?language. # Use ONLY P37 (official language)
      ?country wdt:P31/wdt:P279* wd:Q6256 .
      SERVICE wikibase:label {{ bd:serviceParam wikibase:language "en". }}
    }}
    """
    sparql = SPARQLWrapper(endpoint)
    sparql.setQuery(sparql_query)
    sparql.setReturnFormat(JSON)
    sparql.setTimeout(10) 

    try:
        results = sparql.query().convert()
        countries = sorted(list(set(
            result["countryLabel"]["value"] for result in results["results"]["bindings"]
            if "countryLabel" in result and result["countryLabel"]["type"] == "literal"
        )))
        cache[lang_code] = countries
        logging.debug(f"Wikidata query for {lang_code} found: {countries}")
        return countries
    except Exception as e:
        logging.error(f"Wikidata query failed for language {lang_code}: {e}")
        cache[lang_code] = []
        return [] 