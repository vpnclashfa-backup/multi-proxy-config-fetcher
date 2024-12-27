import os

# لیست کانال‌های تلگرام (به عنوان مثال)
TELEGRAM_CHANNELS = [
    "https://t.me/s/v2rayngvpn",
    "https://t.me/s/V2ray_Alpha",
    "https://t.me/s/SvnV2ray",
    "https://t.me/s/RadixVPN"
    # ... اضافه کردن کانال‌های بیشتر
]

# پروتکل‌های پشتیبانی شده
SUPPORTED_PROTOCOLS = [
    "wireguard://",
    "hysteria2://",
    "vless://",
    "vmess://",
    "ss://",
    "trojan://"
]

# تنظیمات عمومی
MIN_CONFIGS_PER_CHANNEL = 20
MAX_CONFIG_AGE_DAYS = 90
OUTPUT_FILE = 'configs/proxy_configs.txt'

# تنظیمات هدر برای درخواست‌های HTTP
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
}