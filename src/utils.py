# File: src/utils.py
# (Final version with weighted random choice and helper functions)

import random
import base64

# [FINAL] لیست نهایی و گسترش‌یافته User-Agent ها
AGENTS_POPULATION = [
    # --- Windows Browsers ---
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 OPR/111.0.0.0",

    # --- macOS Browsers ---
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:127.0) Gecko/20100101 Firefox/127.0",
    
    # --- Mobile (Android) ---
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",

    # --- Mobile (iOS) ---
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/126.0.6478.54 Mobile/15E148 Safari/604.1",

    # --- Linux ---
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
]

# [FINAL] لیست وزن‌های نهایی که سهم بازار سیستم‌عامل‌ها و مرورگرها را منعکس می‌کند
AGENTS_WEIGHTS = [
    # Weights for Windows (High OS Share)
    12, # Chrome (Very High)
    9,  # Firefox (Medium)
    8,  # Edge (Medium)
    3,  # Opera (Low)

    # Weights for macOS (Medium OS Share)
    7,  # Chrome (High)
    8,  # Safari (Very High, Native)
    4,  # Firefox (Low)

    # Weights for Android (Very High OS Share)
    12, # Chrome on Pixel (Very High)
    11, # Chrome on Samsung (Very High)

    # Weights for iOS (High OS Share)
    10, # Safari (Very High, Native)
    6,  # Chrome (Medium)

    # Weight for Linux (Low OS Share)
    3,  # Firefox (Medium for this OS)
]


def get_random_user_agent() -> str:
    """یک User-Agent تصادفی بر اساس وزن‌ها برمی‌گرداند."""
    return random.choices(AGENTS_POPULATION, weights=AGENTS_WEIGHTS, k=1)[0]

def generate_unique_name(existing_names: dict, name: str) -> str:
    """یک نام منحصربه‌فرد برای کانفیگ تولید می‌کند تا از تکرار جلوگیری شود."""
    count = existing_names.get(name, 0)
    existing_names[name] = count + 1
    
    if count > 0:
        return f"{name}-{count+1}"
    return name

def clean_proxy_name(name: str) -> str:
    """کاراکترهای مشکل‌ساز را از نام پراکسی حذف می‌کند."""
    return name.replace('=', '-').replace(';', ',').replace('"', '')