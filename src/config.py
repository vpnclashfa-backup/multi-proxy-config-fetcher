from typing import Dict, List

class ChannelConfig:
    def __init__(self, url: str, enabled: bool = True, retry_count: int = 0):
        self.url = url
        self.enabled = enabled
        self.retry_count = retry_count
        self.success_rate = 100.0

class ProxyConfig:
    def __init__(self):
        # Telegram channels for fetching configs
        # These are example channels and can be modified
        self.TELEGRAM_CHANNELS = [
            ChannelConfig("https://t.me/s/v2ray_free_conf"),
            ChannelConfig("https://t.me/s/v2rayngvpn"),
            ChannelConfig("https://t.me/s/V2ray_Alpha"),
            ChannelConfig("https://t.me/s/SvnV2ray"),
            ChannelConfig("https://t.me/s/RadixVPN"),
            ChannelConfig("https://t.me/s/PrivateVPNs"),
            ChannelConfig("https://t.me/s/VlessConfig"),
            ChannelConfig("https://t.me/s/freewireguard")
        ]

        # Protocol-specific configuration
        # min_configs: Minimum configs to collect per protocol
        # max_configs: Maximum configs to keep per protocol
        self.SUPPORTED_PROTOCOLS: Dict[str, Dict] = {
            "wireguard://": {"min_configs": 2, "max_configs": 5},
            "hysteria2://": {"min_configs": 2, "max_configs": 5},
            "vless://": {"min_configs": 2, "max_configs": 5},
            "vmess://": {"min_configs": 2, "max_configs": 5},
            "ss://": {"min_configs": 2, "max_configs": 5},
            "trojan://": {"min_configs": 2, "max_configs": 5}
        }

        # Channel configuration
        # Minimum configs to consider a channel fetch successful
        self.MIN_CONFIGS_PER_CHANNEL = 2
        # Maximum configs to fetch from each channel
        # Should be greater than or equal to sum of min_configs of all protocols
        self.MAX_CONFIGS_PER_CHANNEL = 15
        # Maximum age of configs in days
        self.MAX_CONFIG_AGE_DAYS = 60
        # Maximum number of retries for each channel
        self.CHANNEL_RETRY_LIMIT = 3
        # Success rate threshold (70%) below which channel is disabled
        self.CHANNEL_ERROR_THRESHOLD = 0.7

        # Protocol balance configuration
        # Minimum ratio of configs for each protocol (10%)
        # Ensures reasonable distribution across protocols
        self.MIN_PROTOCOL_RATIO = 0.1

        # File paths
        self.OUTPUT_FILE = 'configs/proxy_configs.txt'
        self.STATS_FILE = 'configs/channel_stats.json'

        # Request configuration
        # Maximum number of retry attempts for failed requests
        self.MAX_RETRIES = 3
        # Delay between retries in seconds
        self.RETRY_DELAY = 5
        # Request timeout in seconds
        self.REQUEST_TIMEOUT = 30

        # HTTP Headers for requests
        self.HEADERS = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }

    def is_protocol_enabled(self, protocol: str) -> bool:
        """Check if a protocol is enabled in configuration."""
        return protocol in self.SUPPORTED_PROTOCOLS

    def get_enabled_channels(self) -> List[ChannelConfig]:
        """Get list of currently enabled channels."""
        return [channel for channel in self.TELEGRAM_CHANNELS if channel.enabled]

    def update_channel_stats(self, channel: ChannelConfig, success: bool):
        """Update channel statistics based on fetch success/failure.
        
        Args:
            channel: The channel to update
            success: Whether the fetch was successful
        """
        # Reset retry count on success, increment on failure
        channel.retry_count = 0 if success else channel.retry_count + 1
        
        # Update success rate with weighted average (70% new result, 30% history)
        weight = 0.7
        new_rate = 100.0 if success else 0.0
        channel.success_rate = (weight * new_rate) + ((1 - weight) * channel.success_rate)
        
        # Disable channel if success rate drops below threshold
        if channel.success_rate < self.CHANNEL_ERROR_THRESHOLD * 100:
            channel.enabled = False