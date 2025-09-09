#!/usr/bin/env python
import sys
import os

src_path = os.path.join(os.path.dirname(__file__), 'src')
sys.path.insert(0, src_path)

from play_reviews_scraper.cli import main

if __name__ == "__main__":
    main()