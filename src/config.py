from typing import Dict, List
from datetime import datetime

class ChannelMetrics:
    def __init__(self):
        self.total_configs = 0
        self.valid_configs = 0
        self.unique_configs = 0
        self.avg_response_time = 0
        self.last_success_time = None
        self.fail_count = 0
        self.success_count = 0
        self.overall_score = 100.0

class ChannelConfig:
    def __init__(self, url: str, enabled: bool = True):
        self.url = url
        self.enabled = enabled
        self.metrics = ChannelMetrics()
        
    def calculate_overall_score(self):
        reliability_score = (self.metrics.success_count / max(1, self.metrics.success_count + self.metrics.fail_count)) * 40
        quality_score = (self.metrics.valid_configs / max(1, self.metrics.total_configs)) * 30
        uniqueness_score = (self.metrics.unique_configs / max(1, self.metrics.valid_configs)) * 20
        response_score = max(0, (1 - (self.metrics.avg_response_time / 10))) * 10
        
        self.metrics.overall_score = reliability_score + quality_score + uniqueness_score + response_score

class ProxyConfig:
    def __init__(self):
        self.TELEGRAM_CHANNELS = [
            ChannelConfig("https://t.me/s/v2ray_free_conf"),
            ChannelConfig("https://t.me/s/v2rayvpno"),
            ChannelConfig("https://t.me/s/ZibaNabz"),
            ChannelConfig("https://t.me/s/configV2rayForFree"),
            ChannelConfig("https://t.me/s/v2rayngvpn"),
            ChannelConfig("https://t.me/s/SvnV2ray"), 
            ChannelConfig("https://t.me/s/RadixVPN"),
            ChannelConfig("https://t.me/s/PrivateVPNs"),
            ChannelConfig("https://t.me/s/VlessConfig"),
            ChannelConfig("https://t.me/s/freewireguard")
        ]

        self.PROTOCOL_CONFIG_LIMITS = {
            "min": 5,
            "max": 15
        }

        self.SUPPORTED_PROTOCOLS: Dict[str, Dict] = {
            "wireguard://": {"min_configs": self.PROTOCOL_CONFIG_LIMITS["min"], "max_configs": self.PROTOCOL_CONFIG_LIMITS["max"]},
            "hysteria2://": {"min_configs": self.PROTOCOL_CONFIG_LIMITS["min"], "max_configs": self.PROTOCOL_CONFIG_LIMITS["max"]},
            "vless://": {"min_configs": self.PROTOCOL_CONFIG_LIMITS["min"], "max_configs": self.PROTOCOL_CONFIG_LIMITS["max"]},
            "vmess://": {"min_configs": self.PROTOCOL_CONFIG_LIMITS["min"], "max_configs": self.PROTOCOL_CONFIG_LIMITS["max"]},
            "ss://": {"min_configs": self.PROTOCOL_CONFIG_LIMITS["min"], "max_configs": self.PROTOCOL_CONFIG_LIMITS["max"]},
            "trojan://": {"min_configs": self.PROTOCOL_CONFIG_LIMITS["min"], "max_configs": self.PROTOCOL_CONFIG_LIMITS["max"]}
        }

        self.MIN_CONFIGS_PER_CHANNEL = 5
        self.MAX_CONFIGS_PER_CHANNEL = 30
        self.MAX_CONFIG_AGE_DAYS = 7
        self.CHANNEL_RETRY_LIMIT = 3
        self.CHANNEL_ERROR_THRESHOLD = 0.5

        self.MIN_PROTOCOL_RATIO = 0.15

        self.OUTPUT_FILE = 'configs/proxy_configs.txt'
        self.STATS_FILE = 'configs/channel_stats.json'

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

    def update_channel_stats(self, channel: ChannelConfig, success: bool, response_time: float = 0):
        if success:
            channel.metrics.success_count += 1
            channel.metrics.last_success_time = datetime.now()
        else:
            channel.metrics.fail_count += 1
        
        if response_time > 0:
            if channel.metrics.avg_response_time == 0:
                channel.metrics.avg_response_time = response_time
            else:
                channel.metrics.avg_response_time = (channel.metrics.avg_response_time * 0.7) + (response_time * 0.3)
        
        channel.calculate_overall_score()
        
        if channel.metrics.overall_score < 30:
            channel.enabled = False