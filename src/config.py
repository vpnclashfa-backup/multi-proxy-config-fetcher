from typing import Dict, List

class ChannelConfig:
    def __init__(self, url: str, enabled: bool = True, retry_count: int = 0):
        self.url = url
        self.enabled = enabled
        self.retry_count = retry_count
        self.success_rate = 100.0

class ProxyConfig:
    def __init__(self):
        self.TELEGRAM_CHANNELS = [
            ChannelConfig("https://t.me/s/v2ray_free_conf"),
            ChannelConfig("https://t.me/s/v2rayngvpn"),
            ChannelConfig("https://t.me/s/V2ray_Alpha"),
            ChannelConfig("https://t.me/s/SvnV2ray"),
            ChannelConfig("https://t.me/s/RadixVPN")
        ]

        self.SUPPORTED_PROTOCOLS: Dict[str, Dict] = {
            "wireguard://": {"min_configs": 2, "max_configs": 10},
            "hysteria2://": {"min_configs": 2, "max_configs": 10},
            "vless://": {"min_configs": 2, "max_configs": 10},
            "vmess://": {"min_configs": 2, "max_configs": 10},
            "ss://": {"min_configs": 2, "max_configs": 10},
            "trojan://": {"min_configs": 2, "max_configs": 10}
        }

        # Channel configuration
        self.MIN_CONFIGS_PER_CHANNEL = 2
        self.MAX_CONFIGS_PER_CHANNEL = 20
        self.MAX_CONFIG_AGE_DAYS = 2
        self.CHANNEL_RETRY_LIMIT = 3
        self.CHANNEL_ERROR_THRESHOLD = 0.7  # 70% success rate threshold

        # Protocol balance settings
        self.MIN_PROTOCOL_RATIO = 0.1  # Minimum 10% of total configs per protocol

        # Output settings
        self.OUTPUT_FILE = 'configs/proxy_configs.txt'
        self.STATS_FILE = 'configs/channel_stats.json'

        # Request settings
        self.MAX_RETRIES = 3
        self.RETRY_DELAY = 5
        self.REQUEST_TIMEOUT = 30

        self.HEADERS = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }

    def is_protocol_enabled(self, protocol: str) -> bool:
        return protocol in self.SUPPORTED_PROTOCOLS

    def get_enabled_channels(self) -> List[ChannelConfig]:
        return [channel for channel in self.TELEGRAM_CHANNELS if channel.enabled]

    def update_channel_stats(self, channel: ChannelConfig, success: bool):
        channel.retry_count = 0 if success else channel.retry_count + 1
        
        # Update success rate
        weight = 0.7  # Weight for new result vs historical data
        new_rate = 100.0 if success else 0.0
        channel.success_rate = (weight * new_rate) + ((1 - weight) * channel.success_rate)
        
        # Disable channel if it's performing poorly
        if channel.success_rate < self.CHANNEL_ERROR_THRESHOLD * 100:
            channel.enabled = False