# Refactored config.py with English comments replacing Persian ones.

from typing import Dict, List
from datetime import datetime
import re

class ChannelMetrics:
    """
    Holds statistics and metrics for each channel's configuration.
    """
    def __init__(self):
        self.total_configs = 0
        self.valid_configs = 0
        self.unique_configs = 0
        self.avg_response_time = 0  # Average response time in seconds.
        self.last_success_time = None  # Timestamp of the last successful operation.
        self.fail_count = 0
        self.success_count = 0
        self.overall_score = 0.0  # Overall score for ranking.
        self.protocol_counts = {}  # Protocol distribution for the channel.

class ChannelConfig:
    """
    Represents a configuration source channel with its metrics.
    """
    def __init__(self, url: str, enabled: bool = True):
        self.url = url
        self.enabled = enabled
        self.metrics = ChannelMetrics()
        self.is_telegram = bool(re.match(r'^https://t\.me/s/', url))  # Determines if the source is a Telegram channel.
        
    def calculate_overall_score(self):
        """
        Calculates an overall score based on reliability, quality, uniqueness, and response time.
        """
        reliability_score = (self.metrics.success_count / (self.metrics.success_count + self.metrics.fail_count)) * 35 if (self.metrics.success_count + self.metrics.fail_count) > 0 else 0
        quality_score = (self.metrics.valid_configs / self.metrics.total_configs) * 25 if self.metrics.total_configs > 0 else 0
        uniqueness_score = (self.metrics.unique_configs / self.metrics.valid_configs) * 25 if self.metrics.valid_configs > 0 else 0
        response_score = max(0, min(15, 15 * (1 - (self.metrics.avg_response_time / 10)))) if self.metrics.avg_response_time > 0 else 15
        
        self.metrics.overall_score = reliability_score + quality_score + uniqueness_score + response_score

class ProxyConfig:
    """
    Defines configuration settings for fetching and managing proxy configurations.
    """
    def __init__(self):
        # List of source URLs to fetch proxy configurations.
        self.SOURCE_URLS = [
            ChannelConfig("https://raw.githubusercontent.com/4n0nymou3/wg-config-fetcher/refs/heads/main/configs/wireguard_configs.txt"),
            ChannelConfig("https://raw.githubusercontent.com/Kwinshadow/TelegramV2rayCollector/main/sublinks/mix.txt"),
            ChannelConfig("https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector_Py/refs/heads/main/sub/Mix/mix.txt"),
            ChannelConfig("https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt"),
            ChannelConfig("https://raw.githubusercontent.com/valid7996/Gozargah/refs/heads/main/Gozargah_Sub"),
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

        # Protocol configuration limits to control minimum and maximum fetch limits.
        self.PROTOCOL_CONFIG_LIMITS = {
            "min": 3,  # Minimum number of configurations required per protocol.
            "max": 25  # Maximum number of configurations allowed per protocol.
        }

        # Supported protocols with their respective properties.
        self.SUPPORTED_PROTOCOLS: Dict[str, Dict] = {
            "wireguard://": {
                "min_configs": self.PROTOCOL_CONFIG_LIMITS["min"],
                "max_configs": self.PROTOCOL_CONFIG_LIMITS["max"],
                "priority": 2,  # Priority level for protocol selection.
                "flexible_max": True  # Allows dynamic adjustment of maximum limits.
            },
            "hysteria2://": {
                "min_configs": self.PROTOCOL_CONFIG_LIMITS["min"],
                "max_configs": self.PROTOCOL_CONFIG_LIMITS["max"],
                "priority": 2,
                "flexible_max": True
            },
            "vless://": {
                "min_configs": self.PROTOCOL_CONFIG_LIMITS["min"],
                "max_configs": self.PROTOCOL_CONFIG_LIMITS["max"],
                "priority": 1,
                "flexible_max": True
            },
            "vmess://": {
                "min_configs": self.PROTOCOL_CONFIG_LIMITS["min"],
                "max_configs": self.PROTOCOL_CONFIG_LIMITS["max"],
                "priority": 1,
                "flexible_max": True
            },
            "ss://": {
                "min_configs": self.PROTOCOL_CONFIG_LIMITS["min"],
                "max_configs": self.PROTOCOL_CONFIG_LIMITS["max"],
                "priority": 1,
                "flexible_max": True
            },
            "trojan://": {
                "min_configs": self.PROTOCOL_CONFIG_LIMITS["min"],
                "max_configs": self.PROTOCOL_CONFIG_LIMITS["max"],
                "priority": 1,
                "flexible_max": True
            },
            "tuic://": {
                "min_configs": self.PROTOCOL_CONFIG_LIMITS["min"],
                "max_configs": self.PROTOCOL_CONFIG_LIMITS["max"],
                "priority": 2,
                "flexible_max": True
            }
        }

        # Global limits for channels and protocols.
        self.MIN_CONFIGS_PER_CHANNEL = 3  # Minimum number of configurations required for a channel to be valid.
        self.MAX_CONFIGS_PER_CHANNEL = 50  # Maximum number of configurations fetched per channel.
        self.MAX_CONFIG_AGE_DAYS = 90  # Maximum age (in days) for a configuration to be considered valid.
        self.CHANNEL_RETRY_LIMIT = 5  # Maximum retries for fetching from a channel before marking it as failed.
        self.CHANNEL_ERROR_THRESHOLD = 0.7  # Error threshold beyond which the channel is disabled.
        self.MIN_PROTOCOL_RATIO = 0.1  # Minimum protocol ratio for consideration in final configurations.
        
        # Dynamic protocol adjustments based on fetch results.
        self.DYNAMIC_PROTOCOL_ADJUSTMENT = True
        self.PROTOCOL_BALANCE_FACTOR = 1.5  # Multiplier for adjusting the maximum number of configurations for a protocol.
        
        # File paths for output and statistics.
        self.OUTPUT_FILE = 'configs/proxy_configs.txt'
        self.STATS_FILE = 'configs/channel_stats.json'
        self.MAX_RETRIES = 5  # Maximum retry attempts for fetching configurations.
        self.RETRY_DELAY = 3  # Delay (in seconds) between retries.
        self.REQUEST_TIMEOUT = 45  # Timeout (in seconds) for HTTP requests.
        
        # HTTP headers for requests.
        self.HEADERS = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }

    def is_protocol_enabled(self, protocol: str) -> bool:
        """
        Checks if a protocol is enabled in the supported protocols list.
        """
        return protocol in self.SUPPORTED_PROTOCOLS

    def get_enabled_channels(self) -> List[ChannelConfig]:
        """
        Returns a list of currently enabled channels for configuration fetching.
        """
        return [channel for channel in self.SOURCE_URLS if channel.enabled]

    def update_channel_stats(self, channel: ChannelConfig, success: bool, response_time: float = 0):
        """
        Updates the statistics and score for a given channel based on the success or failure of operations.
        """
        if success:
            channel.metrics.success_count += 1
            channel.metrics.last_success_time = datetime.now()
        else:
            channel.metrics.fail_count += 1
        
        if response_time > 0:
            # Calculate moving average for response time.
            if channel.metrics.avg_response_time == 0:
                channel.metrics.avg_response_time = response_time
            else:
                channel.metrics.avg_response_time = (channel.metrics.avg_response_time * 0.7) + (response_time * 0.3)
        
        channel.calculate_overall_score()
        
        if channel.metrics.overall_score < 25:  # Disable the channel if the score is too low.
            channel.enabled = False
            
    def adjust_protocol_limits(self, channel: ChannelConfig):
        """
        Dynamically adjusts protocol limits based on channel statistics.
        """
        if not self.DYNAMIC_PROTOCOL_ADJUSTMENT:
            return
            
        for protocol in self.SUPPORTED_PROTOCOLS:
            if protocol in channel.metrics.protocol_counts:
                count = channel.metrics.protocol_counts[protocol]
                if count >= self.SUPPORTED_PROTOCOLS[protocol]["min_configs"]:
                    new_max = min(
                        int(count * self.PROTOCOL_BALANCE_FACTOR),
                        self.MAX_CONFIGS_PER_CHANNEL
                    )
                    if self.SUPPORTED_PROTOCOLS[protocol]["flexible_max"]:
                        self.SUPPORTED_PROTOCOLS[protocol]["max_configs"] = new_max