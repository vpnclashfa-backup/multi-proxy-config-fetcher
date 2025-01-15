from typing import Dict, List
from datetime import datetime
import re

class ChannelMetrics:
    """
    A class to track and store metrics for each proxy config channel.
    Handles statistics like success rates, response times, and scoring.
    """
    def __init__(self):
        self.total_configs = 0  # Total number of configs found in channel
        self.valid_configs = 0  # Number of configs that passed validation
        self.unique_configs = 0  # Number of configs not seen in other channels
        self.avg_response_time = 0  # Average time to fetch configs from channel
        self.last_success_time = None  # Last time configs were successfully fetched
        self.fail_count = 0  # Number of failed fetch attempts
        self.success_count = 0  # Number of successful fetch attempts
        self.overall_score = 0.0  # Channel performance score (0-100)
        self.protocol_counts = {}  # Count of configs per protocol type

class ChannelConfig:
    """
    Represents a source channel for proxy configurations.
    Handles channel-specific settings and metrics tracking.
    """
    def __init__(self, url: str, enabled: bool = True):
        self.url = url
        self.enabled = enabled
        self.metrics = ChannelMetrics()
        # Check if channel is a Telegram channel by URL pattern
        self.is_telegram = bool(re.match(r'^https://t\.me/s/', url))
        
    def calculate_overall_score(self):
        """
        Calculates channel performance score based on multiple factors:
        - Reliability (35%): Success rate of fetch attempts
        - Quality (25%): Ratio of valid configs to total configs
        - Uniqueness (25%): Ratio of unique configs to valid configs
        - Response Time (15%): Speed of config fetching
        """
        reliability_score = (self.metrics.success_count / (self.metrics.success_count + self.metrics.fail_count)) * 35 if (self.metrics.success_count + self.metrics.fail_count) > 0 else 0
        quality_score = (self.metrics.valid_configs / self.metrics.total_configs) * 25 if self.metrics.total_configs > 0 else 0
        uniqueness_score = (self.metrics.unique_configs / self.metrics.valid_configs) * 25 if self.metrics.valid_configs > 0 else 0
        response_score = max(0, min(15, 15 * (1 - (self.metrics.avg_response_time / 10)))) if self.metrics.avg_response_time > 0 else 15
        
        self.metrics.overall_score = reliability_score + quality_score + uniqueness_score + response_score

class ProxyConfig:
    """
    Main configuration class for the proxy config fetcher.
    Contains all settings, limits, and source management.
    """
    def __init__(self):
        # Complete list of all source URLs and Telegram channels to fetch proxy configs from
        self.SOURCE_URLS = [
            ChannelConfig("https://raw.githubusercontent.com/4n0nymou3/wg-config-fetcher/refs/heads/main/configs/wireguard_configs.txt"),
            ChannelConfig("https://raw.githubusercontent.com/4n0nymou3/ss-config-updater/refs/heads/main/configs.txt"),
            ChannelConfig("https://raw.githubusercontent.com/valid7996/Gozargah/refs/heads/main/Gozargah_Sub"),
            # ChannelConfig("https://raw.githubusercontent.com/Kwinshadow/TelegramV2rayCollector/main/sublinks/mix.txt"),
            # ChannelConfig("https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector_Py/refs/heads/main/sub/Mix/mix.txt"),
            # ChannelConfig("https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt"),
            ChannelConfig("https://t.me/s/v2ray_free_conf"),
            ChannelConfig("https://t.me/s/PrivateVPNs"),
            ChannelConfig("https://t.me/s/IP_CF_Config"),
            ChannelConfig("https://t.me/s/ShadowProxy66"),
            ChannelConfig("https://t.me/s/OutlineReleasedKey"),
            ChannelConfig("https://t.me/s/prrofile_purple"),
            ChannelConfig("https://t.me/s/proxy_shadosocks"),
            ChannelConfig("https://t.me/s/meli_proxyy"),
            ChannelConfig("https://t.me/s/DirectVPN"),
            ChannelConfig("https://t.me/s/VmessProtocol"),
            ChannelConfig("https://t.me/s/V2ray_Alpha")
        ]

        # Global limits for all protocols
        self.PROTOCOL_CONFIG_LIMITS = {
            "min": 3,  # Minimum configs required per protocol
            "max": 25  # Maximum configs allowed per protocol
        }

        # Detailed configuration for each supported protocol
        # Defines limits, priorities, and flexibility settings
        self.SUPPORTED_PROTOCOLS: Dict[str, Dict] = {
            "wireguard://": {
                "min_configs": self.PROTOCOL_CONFIG_LIMITS["min"],
                "max_configs": self.PROTOCOL_CONFIG_LIMITS["max"],
                "priority": 2,  # Higher priority protocols are preferred
                "flexible_max": True  # Allow exceeding max limit if needed
            },
            "hysteria2://": {
                "min_configs": self.PROTOCOL_CONFIG_LIMITS["min"],
                "max_configs": self.PROTOCOL_CONFIG_LIMITS["max"],
                "priority": 1,
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
                "priority": 2,
                "flexible_max": True
            },
            "tuic://": {
                "min_configs": self.PROTOCOL_CONFIG_LIMITS["min"],
                "max_configs": self.PROTOCOL_CONFIG_LIMITS["max"],
                "priority": 1,
                "flexible_max": True
            }
        }

        # Channel configuration limits
        self.MIN_CONFIGS_PER_CHANNEL = 3  # Minimum configs needed from each channel
        self.MAX_CONFIGS_PER_CHANNEL = 50  # Maximum configs to take from each channel
        self.MAX_CONFIG_AGE_DAYS = 90  # Maximum age of configs in days
        self.CHANNEL_RETRY_LIMIT = 10  # Maximum retry attempts per channel
        self.CHANNEL_ERROR_THRESHOLD = 0.7  # Error rate threshold for disabling channels
        self.MIN_PROTOCOL_RATIO = 0.1  # Minimum ratio of configs per protocol

        # Dynamic protocol adjustment settings
        self.DYNAMIC_PROTOCOL_ADJUSTMENT = True  # Enable automatic limit adjustments
        self.PROTOCOL_BALANCE_FACTOR = 1.5  # Factor for increasing protocol limits
        
        # File paths for outputs
        self.OUTPUT_FILE = 'configs/proxy_configs.txt'  # Final proxy config file
        self.STATS_FILE = 'configs/channel_stats.json'  # Channel statistics file
        
        # HTTP request settings
        self.MAX_RETRIES = 10  # Maximum retry attempts for HTTP requests
        self.RETRY_DELAY = 15  # Delay between retries in seconds
        self.REQUEST_TIMEOUT = 60  # Request timeout in seconds
        
        # HTTP request headers to mimic browser behavior
        self.HEADERS = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }

    def is_protocol_enabled(self, protocol: str) -> bool:
        """Check if a protocol is supported and enabled"""
        return protocol in self.SUPPORTED_PROTOCOLS

    def get_enabled_channels(self) -> List[ChannelConfig]:
        """Return list of currently enabled channel sources"""
        return [channel for channel in self.SOURCE_URLS if channel.enabled]

    def update_channel_stats(self, channel: ChannelConfig, success: bool, response_time: float = 0):
        """
        Update channel statistics and metrics after fetch attempt.
        Handles success/failure counting and score calculation.
        Disables channels that perform poorly.
        """
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
        
        # Disable channels with consistently poor performance
        if channel.metrics.overall_score < 25:
            channel.enabled = False
            
    def adjust_protocol_limits(self, channel: ChannelConfig):
        """
        Dynamically adjust protocol limits based on channel performance.
        Increases max limits for protocols that consistently provide good configs.
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