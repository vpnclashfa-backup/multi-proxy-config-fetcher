from typing import Dict, List
from datetime import datetime
import re
from urllib.parse import urlparse

class ChannelMetrics:
    """
    Class to store and track metrics for each proxy config channel.
    All metrics start with default values of 0 or None.
    """
    def __init__(self):
        self.total_configs = 0          # Total number of configs found in channel
        self.valid_configs = 0          # Number of valid configs after validation
        self.unique_configs = 0         # Number of unique configs (not duplicates)
        self.avg_response_time = 0      # Average response time in seconds
        self.last_success_time = None   # Timestamp of last successful fetch
        self.fail_count = 0             # Number of failed fetch attempts
        self.success_count = 0          # Number of successful fetch attempts
        self.overall_score = 0.0        # Overall channel performance score 0-100
        self.protocol_counts = {}       # Count of configs per protocol

class ChannelConfig:
    """
    Class to store channel configuration and associated metrics.
    Default state for each channel is enabled (True).
    """
    def __init__(self, url: str, enabled: bool = True):
        self.url = url
        self.enabled = enabled
        self.metrics = ChannelMetrics()
        self.is_telegram = bool(re.match(r'^https://t\.me/s/', url))
        
    def calculate_overall_score(self):
        """
        Calculate overall channel score based on multiple factors:
        - Reliability (35%): Success rate of fetch attempts
        - Quality (25%): Ratio of valid configs to total configs
        - Uniqueness (25%): Ratio of unique configs to valid configs
        - Response Time (15%): Score based on average response time
        """
        reliability_score = (self.metrics.success_count / (self.metrics.success_count + self.metrics.fail_count)) * 35 if (self.metrics.success_count + self.metrics.fail_count) > 0 else 0
        quality_score = (self.metrics.valid_configs / self.metrics.total_configs) * 25 if self.metrics.total_configs > 0 else 0
        uniqueness_score = (self.metrics.unique_configs / self.metrics.valid_configs) * 25 if self.metrics.valid_configs > 0 else 0
        response_score = max(0, min(15, 15 * (1 - (self.metrics.avg_response_time / 10)))) if self.metrics.avg_response_time > 0 else 15
        
        self.metrics.overall_score = reliability_score + quality_score + uniqueness_score + response_score

class ProxyConfig:
    def __init__(self):
        # Collection Mode Configuration
        # This is the main setting that users should modify
        # Values:
        # - "minimal": Collects minimum viable number of configs (around 10-20 total)
        # - "balanced": Collects a moderate number of configs (around 50-100 total)
        # - "maximum": Collects maximum possible configs (200+ depending on sources)
        self.COLLECTION_MODE = "balanced"  # Default: balanced mode
        
        # Custom total config count (optional)
        # Set this to override the collection mode and get specific number of configs
        # Set to None to use collection mode instead
        # Example: 50 will try to collect exactly 50 configs across all protocols
        self.DESIRED_TOTAL_CONFIGS = None  # Default: None (use collection mode)
        
        # Automatically calculated limits based on collection mode
        self._calculate_limits()
        
        # List of source URLs to fetch proxy configs from
        initial_urls = [
            ChannelConfig("https://raw.githubusercontent.com/4n0nymou3/wg-config-fetcher/refs/heads/main/configs/wireguard_configs.txt"),
            ChannelConfig("https://raw.githubusercontent.com/4n0nymou3/ss-config-updater/refs/heads/main/configs.txt"),
            ChannelConfig("https://raw.githubusercontent.com/valid7996/Gozargah/refs/heads/main/Gozargah_Sub"),
            ChannelConfig("https://t.me/s/FreeV2rays"),
            ChannelConfig("https://t.me/s/v2ray_free_conf"),
            ChannelConfig("https://t.me/s/PrivateVPNs"),
            ChannelConfig("https://t.me/s/IP_CF_Config"),
            ChannelConfig("https://t.me/s/shadowproxy66"),
            ChannelConfig("https://t.me/s/OutlineReleasedKey"),
            ChannelConfig("https://t.me/s/prrofile_purple"),
            ChannelConfig("https://t.me/s/proxy_shadosocks"),
            ChannelConfig("https://t.me/s/meli_proxyy"),
            ChannelConfig("https://t.me/s/DirectVPN"),
            ChannelConfig("https://t.me/s/VmessProtocol"),
            ChannelConfig("https://t.me/s/ViProxys"),
            ChannelConfig("https://t.me/s/heyatserver"),
            ChannelConfig("https://t.me/s/vpnfail_vless"),
            ChannelConfig("https://t.me/s/DailyV2RY"),
            ChannelConfig("https://t.me/s/ShadowsocksM")
        ]

        self.SOURCE_URLS = self._remove_duplicate_urls(initial_urls)

        # Supported proxy protocols configuration
        self.SUPPORTED_PROTOCOLS: Dict[str, Dict] = {
            "wireguard://": {
                "min_configs": self.PROTOCOL_CONFIG_LIMITS["min"],
                "max_configs": self.PROTOCOL_CONFIG_LIMITS["max"],
                "priority": 2,
                "flexible_max": True
            },
            "hysteria2://": {
                "min_configs": self.PROTOCOL_CONFIG_LIMITS["min"],
                "max_configs": self.PROTOCOL_CONFIG_LIMITS["max"],
                "priority": 2,
                "flexible_max": True,
                "aliases": ["hy2://"]
            },
            "vless://": {
                "min_configs": self.PROTOCOL_CONFIG_LIMITS["min"],
                "max_configs": self.PROTOCOL_CONFIG_LIMITS["max"],
                "priority": 2,
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
                "priority": 2,
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

        # Output file paths
        self.OUTPUT_FILE = 'configs/proxy_configs.txt'    # Path to save final configs
        self.STATS_FILE = 'configs/channel_stats.json'    # Path to save channel stats
        
        # HTTP request settings
        self.MAX_RETRIES = 5             # Maximum number of retry attempts
        self.RETRY_DELAY = 15            # Delay between retries in seconds
        self.REQUEST_TIMEOUT = 60        # Request timeout in seconds
        
        # HTTP request headers
        self.HEADERS = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }

    def _calculate_limits(self):
        """
        Calculate all limits based on collection mode or desired total configs.
        This method automatically adjusts all related settings to maintain consistency.
        """
        if self.DESIRED_TOTAL_CONFIGS is not None:
            # If user specified exact number of configs
            total = max(10, min(1000, self.DESIRED_TOTAL_CONFIGS))  # Ensure between 10 and 1000
            per_protocol = max(1, total // len(self.SUPPORTED_PROTOCOLS))
            
            self.PROTOCOL_CONFIG_LIMITS = {
                "min": max(1, per_protocol // 2),
                "max": per_protocol * 2
            }
            
            self.MIN_CONFIGS_PER_CHANNEL = 1
            self.MAX_CONFIGS_PER_CHANNEL = max(10, total // 2)
            
        else:
            # Based on collection mode
            mode_settings = {
                "minimal": {
                    "protocol_min": 1,
                    "protocol_max": 5,
                    "channel_min": 1,
                    "channel_max": 10
                },
                "balanced": {
                    "protocol_min": 3,
                    "protocol_max": 15,
                    "channel_min": 2,
                    "channel_max": 30
                },
                "maximum": {
                    "protocol_min": 5,
                    "protocol_max": 50,
                    "channel_min": 3,
                    "channel_max": 100
                }
            }
            
            settings = mode_settings.get(self.COLLECTION_MODE, mode_settings["balanced"])
            
            self.PROTOCOL_CONFIG_LIMITS = {
                "min": settings["protocol_min"],
                "max": settings["protocol_max"]
            }
            
            self.MIN_CONFIGS_PER_CHANNEL = settings["channel_min"]
            self.MAX_CONFIGS_PER_CHANNEL = settings["channel_max"]

        # Other settings that adapt to the mode
        self.MAX_CONFIG_AGE_DAYS = 90        # Keep this fixed as it affects reliability
        self.CHANNEL_RETRY_LIMIT = 3         # Keep retries minimal
        self.CHANNEL_ERROR_THRESHOLD = 0.7    # Standard error threshold
        self.MIN_PROTOCOL_RATIO = 0.1        # Minimum ratio of configs per protocol
        
        # Dynamic adjustment settings
        self.DYNAMIC_PROTOCOL_ADJUSTMENT = True
        self.PROTOCOL_BALANCE_FACTOR = 1.2

    def _normalize_url(self, url: str) -> str:
        """Normalize URLs to ensure consistent comparison."""
        if url.startswith('ssconf://'):
            url = url.replace('ssconf://', 'https://', 1)
            
        parsed = urlparse(url)
        path = parsed.path.rstrip('/')
        
        if parsed.netloc.startswith('t.me/s/'):
            channel_name = parsed.path.strip('/').lower()
            return f"telegram:{channel_name}"
            
        return f"{parsed.scheme}://{parsed.netloc}{path}"

    def _remove_duplicate_urls(self, channel_configs: List[ChannelConfig]) -> List[ChannelConfig]:
        """Remove duplicate URLs from the channel config list."""
        seen_urls = {}
        unique_configs = []
        
        for config in channel_configs:
            normalized_url = self._normalize_url(config.url)
            if normalized_url not in seen_urls:
                seen_urls[normalized_url] = True
                unique_configs.append(config)
                
        return unique_configs

    def is_protocol_enabled(self, protocol: str) -> bool:
        """Check if a protocol is enabled in SUPPORTED_PROTOCOLS."""
        if protocol in self.SUPPORTED_PROTOCOLS:
            return True
        for main_protocol, info in self.SUPPORTED_PROTOCOLS.items():
            if 'aliases' in info and protocol in info['aliases']:
                return True
        return False

    def get_enabled_channels(self) -> List[ChannelConfig]:
        """Return list of enabled channels only."""
        return [channel for channel in self.SOURCE_URLS if channel.enabled]

    def update_channel_stats(self, channel: ChannelConfig, success: bool, response_time: float = 0):
        """Update channel statistics after fetch attempt."""
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
        
        if channel.metrics.overall_score < 25:
            channel.enabled = False
            
    def adjust_protocol_limits(self, channel: ChannelConfig):
        """Dynamically adjust protocol limits based on channel performance."""
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