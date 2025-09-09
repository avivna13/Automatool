import os
import json
from collections import Counter


def parse_reviews_to_summary(output_directory, verbose=False):
    """
    Parse reviews.json and create a simplified summary with only essential fields.
    Includes analysis of most frequent country.
    
    Args:
        output_directory (str): Directory containing reviews.json and where summary will be saved
        verbose (bool): Enable verbose output
        
    Returns:
        str: Formatted summary string of parsed reviews with country analysis
    """
    input_file = os.path.join(output_directory, "reviews.json")
    output_file = os.path.join(output_directory, "reviews_summary.txt")
    
    if verbose:
        print(f"[DEBUG] Parsing reviews from: {input_file}")
        print(f"[DEBUG] Output summary to: {output_file}")
    
    # Check if input file exists
    if not os.path.exists(input_file):
        error_msg = f"❌ ERROR: reviews.json not found in {output_directory}"
        print(error_msg)
        return error_msg
    
    try:
        # Load and parse JSON data
        with open(input_file, 'r', encoding='utf-8') as f:
            reviews_data = json.load(f)
        
        if verbose:
            print(f"[DEBUG] Loaded {len(reviews_data)} reviews from JSON")
        
        # Process reviews and extract required fields
        processed_reviews = []
        country_codes = []
        
        for review in reviews_data:
            # Skip reviews missing required fields
            if not all(key in review for key in ['user_name', 'translated_content', 'country_code']):
                if verbose:
                    print(f"[DEBUG] Skipping review with missing required fields: {review.get('review_id', 'unknown')}")
                continue
            
            # Extract only the required fields
            processed_review = {
                'user_name': review['user_name'],
                'translated_content': review['translated_content'],
                'country_code': review['country_code']
            }
            processed_reviews.append(processed_review)
            country_codes.append(review['country_code'])
        
        if verbose:
            print(f"[DEBUG] Successfully processed {len(processed_reviews)} reviews")
        
        if not processed_reviews:
            warning_msg = "⚠️  WARNING: No valid reviews found to process"
            print(warning_msg)
            return warning_msg
        
        # Analyze country distribution
        country_counter = Counter(country_codes)
        most_common_country, most_common_count = country_counter.most_common(1)[0]
        
        if verbose:
            print(f"[DEBUG] Most common country: {most_common_country} ({most_common_count} reviews)")
            print(f"[DEBUG] Total countries: {len(country_counter)}")
        
        # Build summary text
        summary_lines = ["=== REVIEWS SUMMARY ==="]
        summary_lines.append(f"Most Reviews From: {most_common_country} ({most_common_count} reviews)")
        
        # Add verbose country distribution if requested
        if verbose:
            total_reviews = len(processed_reviews)
            percentage = (most_common_count / total_reviews) * 100
            summary_lines[1] = f"Most Reviews From: {most_common_country} ({most_common_count} reviews - {percentage:.1f}% of total)"
            summary_lines.append("")
            summary_lines.append("Country Distribution:")
            
            for country, count in country_counter.most_common():
                percentage = (count / total_reviews) * 100
                summary_lines.append(f"- {country}: {count} reviews ({percentage:.1f}%)")
        
        summary_lines.append("")
        
        # Add individual reviews
        for i, review in enumerate(processed_reviews, 1):
            summary_lines.append(f"{i}. User: {review['user_name']} | Country: {review['country_code']}")
            summary_lines.append(f"   Review: {review['translated_content']}")
            summary_lines.append("")
        
        summary_text = "\n".join(summary_lines)
        
        # Write summary to file
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(summary_text)
            
            if verbose:
                print(f"[DEBUG] ✅ Summary written to {output_file}")
            print(f"✅ Reviews summary created: {output_file}")
            
        except IOError as e:
            error_msg = f"❌ ERROR: Failed to write summary file: {e}"
            print(error_msg)
            return error_msg
            
        return summary_text
        
    except json.JSONDecodeError as e:
        error_msg = f"❌ ERROR: Invalid JSON in reviews file: {e}"
        print(error_msg)
        return error_msg
        
    except Exception as e:
        error_msg = f"❌ ERROR: Failed to parse reviews: {e}"
        print(error_msg)
        if verbose:
            print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
        return error_msg
