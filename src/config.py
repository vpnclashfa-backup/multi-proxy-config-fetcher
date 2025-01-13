from typing import Dict, List

class ChannelConfig:
    def __init__(self, url: str, enabled: bool = True):
        self.url = url
        self.enabled = enabled

class ProxyConfig:
    def __init__(self):
        # لیست کانال‌ها و URL‌های منابع
        self.SOURCE_URLS = [
            ChannelConfig("https://raw.githubusercontent.com/4n0nymou3/wg-config-fetcher/refs/heads/main/configs/wireguard_configs.txt"),
            ChannelConfig("https://raw.githubusercontent.com/4n0nymou3/ss-config-updater/refs/heads/main/configs.txt"),
            ChannelConfig("https://raw.githubusercontent.com/Kwinshadow/TelegramV2rayCollector/main/sublinks/mix.txt"),
            ChannelConfig("https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector_Py/refs/heads/main/sub/Mix/mix.txt"),
            ChannelConfig("https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt"),
            ChannelConfig("https://t.me/s/v2ray_free_conf"),
            ChannelConfig("https://t.me/s/PrivateVPNs"),
            ChannelConfig("https://t.me/s/v2Source"),
            ChannelConfig("https://t.me/s/IP_CF_Config"),
            ChannelConfig("https://t.me/s/oneclickvpnkeys"),
            ChannelConfig("https://t.me/s/ShadowProxy66"),
            ChannelConfig("https://t.me/s/OutlineReleasedKey"),
            ChannelConfig("https://t.me/s/GetConfigIR"),
            ChannelConfig("https://t.me/s/prrofile_purple"),
            ChannelConfig("https://t.me/s/proxy_shadosocks"),
            ChannelConfig("https://t.me/s/meli_proxyy"),
            ChannelConfig("https://t.me/s/DirectVPN"),
            ChannelConfig("https://t.me/s/Parsashonam"),
            ChannelConfig("https://t.me/s/ArV2ray"),
            ChannelConfig("https://t.me/s/VmessProtocol"),
            ChannelConfig("https://t.me/s/V2ray_Alpha"),
        ]

        # تنظیم حداقل و حداکثر تعداد کانفیگ‌ها برای هر پروتکل
        self.PROTOCOL_CONFIG_LIMITS = {
            "min": 5,
            "max": 30
        }

        # تعریف پروتکل‌های پشتیبانی‌شده
        self.SUPPORTED_PROTOCOLS: Dict[str, Dict] = {
            "wireguard://": {"min_configs": 5, "max_configs": 30},
            "hysteria2://": {"min_configs": 5, "max_configs": 30},
            "vless://": {"min_configs": 5, "max_configs": 30},
            "vmess://": {"min_configs": 5, "max_configs": 30},
            "ss://": {"min_configs": 5, "max_configs": 30},
            "trojan://": {"min_configs": 5, "max_configs": 30},
            "tuic://": {"min_configs": 5, "max_configs": 30}
        }

        # سایر تنظیمات
        self.MIN_CONFIGS_PER_CHANNEL = 5
        self.MAX_CONFIGS_PER_CHANNEL = 50
        self.MAX_CONFIG_AGE_DAYS = 30
        self.CHANNEL_RETRY_LIMIT = 5
        self.CHANNEL_ERROR_THRESHOLD = 0.7
        self.MIN_PROTOCOL_RATIO = 0.1
        self.OUTPUT_FILE = 'configs/proxy_configs.txt'
        self.STATS_FILE = 'configs/channel_stats.json'
        self.MAX_RETRIES = 5
        self.RETRY_DELAY = 5
        self.REQUEST_TIMEOUT = 60

        # تنظیمات هدر HTTP
        self.HEADERS = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }