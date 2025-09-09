import re

# Value to represent missing data
NA_STRING = "N/A"

# Rich markup style for highlighting
HIGHLIGHT_STYLE = r"[bold black on bright_red]\1[/bold black on bright_red]"

# List of words to highlight in translations
BAD_WORDS = [
    'scam', 'free', 'abuse', 'abusive', 'antivirus',
    'attack', 'attacked', 'beware', 'breach', 'compromise',
    'credential', 'credentials', 'exploit', 'fraudulent',
    'hack', 'hacked', 'harm', 'harmful', 'insecure', 'leak',
    'leaking', 'ad', 'ads', 'fraud', 'fake', 'gamble', 'gambling'
]

# Precompiled regex patterns for bad words (case-insensitive)
BAD_WORD_PATTERNS = [re.compile(rf"(?i)\b({re.escape(word)})\b") for word in BAD_WORDS]

# List of specific countries to filter results against
INTERESTING_COUNTRIES_RAW = [
    "Albania", "Algeria", "Andorra", "Angola", "Argentina",
    "Armenia", "Australia", "Austria", "Azerbaijan", "Bahamas",
    "Bahrain", "Bangladesh", "Belgium", "Belize", "Bermuda",
    "Bhutan", "Bolivia", "Bosnia And Herzegovina", "Brazil",
    "Bulgaria", "Cambodia", "Canada", "Cayman Islands", "Chile",
    "Colombia", "Costa Rica", "Croatia", "Cyprus", "Czech Republic",
    "Denmark", "Dominican Republic", "Ecuador", "Egypt", "El Salvador",
    "Estonia", "Finland", "France", "Georgia", "Germany",
    "Ghana", "Greece", "Greenland", "Guam", "Guatemala",
    "Honduras", "Hong Kong", "Hungary", "Iceland", "India",
    "Indonesia", "Ireland", "Isle Of Man", "Israel", "Italy",
    "Jamaica", "Japan", "Jersey", "Jordan", "Kazakhstan",
    "Kenya", "Kuwait", "Lao Peoples Democratic Republic", "Latvia", "Lebanon",
    "Liechtenstein", "Lithuania", "Luxembourg", "Malaysia", "Malta",
    "Mexico", "Moldova", "Monaco", "Mongolia", "Montenegro",
    "Morocco", "Mozambique", "Myanmar", "Nepal", "Netherlands",
    "New Zealand", "Nigeria", "North Macedonia", "Norway", "Pakistan",
    "Panama", "Papua New Guinea", "Paraguay", "Peru", "Philippines",
    "Poland", "Portugal", "Puerto Rico", "Romania", "Senegal",
    "Serbia", "Singapore", "Slovakia", "Slovenia", "South Africa",
    "South Korea", "Spain", "Sri Lanka", "Sweden", "Switzerland",
    "Taiwan", "Thailand", "Trinidad And Tobago", "Tunisia", "Turkey",
    "Ukraine", "United Arab Emirates", "United Kingdom", "United States", "Uruguay",
    "Uzbekistan", "Venezuela", "Vietnam"
]

# Create a set of lowercase country names for efficient, case-insensitive lookup
INTERESTING_COUNTRIES_SET = {name.lower() for name in INTERESTING_COUNTRIES_RAW} 