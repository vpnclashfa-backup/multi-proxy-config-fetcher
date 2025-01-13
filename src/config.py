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
        self.overall_score = 0.0
        self.protocol_counts = {}

class ChannelConfig:
    def __init__(self, url: str, enabled: bool = True):
        self.url = url
        self.enabled = enabled
        self.metrics = ChannelMetrics()
        self.is_telegram = bool(re.match(r'^https://t\.me/s/', url))
        
    def calculate_overall_score(self):
        if self.metrics.success_count + self.metrics.fail_count == 0:
            reliability_score = 0
        else:
            reliability_score = (self.metrics.success_count / (self.metrics.success_count + self.metrics.fail_count)) * 35
        
        if self.metrics.total_configs == 0:
            quality_score = 0
        else:
            quality_score = (self.metrics.valid_configs / self.metrics.total_configs) * 25
        
        if self.metrics.valid_configs == 0:
            uniqueness_score = 0
        else:
            uniqueness_score = (self.metrics.unique_configs / self.metrics.valid_configs) * 25
        
        if self.metrics.avg_response_time == 0:
            response_score = 15
        else:
            response_score = max(0, min(15, 15 * (1 - (self.metrics.avg_response_time / 10))))
        
        self.metrics.overall_score = reliability_score + quality_score + uniqueness_score + response_score

class ProxyConfig:
    def __init__(self):
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
            ChannelConfig("https://t.me/s/V2ray_Alpha")
        ]

        self.PROTOCOL_CONFIG_LIMITS = {
            "min": 5,
            "max": 30
        }

        self.SUPPORTED_PROTOCOLS: Dict[str, Dict] = {
            "wireguard://": {"min_configs": 5, "max_configs": 30, "priority": 1},
            "hysteria2://": {"min_configs": 5, "max_configs": 30, "priority": 1},
            "vless://": {"min_configs": 5, "max_configs": 30, "priority": 1},
            "vmess://": {"min_configs": 5, "max_configs": 30, "priority": 1},
            "ss://": {"min_configs": 5, "max_configs": 30, "priority": 1},
            "trojan://": {"min_configs": 5, "max_configs": 30, "priority": 1},
            "tuic://": {"min_configs": 5, "max_configs": 30, "priority": 1}
        }

        self.MIN_CONFIGS_PER_CHANNEL = 5
        self.MAX_CONFIGS_PER_CHANNEL = 50
        self.MAX_CONFIG_AGE_DAYS = 30
        self.CHANNEL_RETRY_LIMIT = 5
        self.CHANNEL_ERROR_THRESHOLD = 0.3
        self.MIN_PROTOCOL_RATIO = 0.10
        self.OUTPUT_FILE = 'configs/proxy_configs.txt'
        self.STATS_FILE = 'configs/channel_stats.json'
        self.MAX_RETRIES = 5
        self.RETRY_DELAY = 3
        self.REQUEST_TIMEOUT = 60

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
        return [channel for channel in self.SOURCE_URLS if channel.enabled]

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
        
        if channel.metrics.overall_score < 20:
            channel.enabled = False