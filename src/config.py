from typing import Dict, List
from datetime import datetime
import re
from urllib.parse import urlparse

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
        reliability_score = (self.metrics.success_count / (self.metrics.success_count + self.metrics.fail_count)) * 35 if (self.metrics.success_count + self.metrics.fail_count) > 0 else 0
        quality_score = (self.metrics.valid_configs / self.metrics.total_configs) * 25 if self.metrics.total_configs > 0 else 0
        uniqueness_score = (self.metrics.unique_configs / self.metrics.valid_configs) * 25 if self.metrics.valid_configs > 0 else 0
        response_score = max(0, min(15, 15 * (1 - (self.metrics.avg_response_time / 10)))) if self.metrics.avg_response_time > 0 else 15
        
        self.metrics.overall_score = reliability_score + quality_score + uniqueness_score + response_score

class ProxyConfig:
    def __init__(self):
        # User Configuration Mode
        # Option 1: Set use_maximum_power = True for maximum possible configs (Highest Priority)
        # Option 2: Set specific_config_count > 0 for desired number of configs (Default: 50)
        # Note: If use_maximum_power is True, specific_config_count will be ignored
        self.use_maximum_power = False
        self.specific_config_count = 50

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
        self.SUPPORTED_PROTOCOLS = self._initialize_protocols()
        self._initialize_settings()
        self._set_smart_limits()

    def _initialize_protocols(self) -> Dict:
        return {
            "wireguard://": {"priority": 2, "aliases": []},
            "hysteria2://": {"priority": 2, "aliases": ["hy2://"]},
            "vless://": {"priority": 2, "aliases": []},
            "vmess://": {"priority": 1, "aliases": []},
            "ss://": {"priority": 2, "aliases": []},
            "trojan://": {"priority": 2, "aliases": []},
            "tuic://": {"priority": 1, "aliases": []}
        }

    def _initialize_settings(self):
        self.MAX_CONFIG_AGE_DAYS = 90
        self.CHANNEL_RETRY_LIMIT = 5
        self.CHANNEL_ERROR_THRESHOLD = 0.7
        self.OUTPUT_FILE = 'configs/proxy_configs.txt'
        self.STATS_FILE = 'configs/channel_stats.json'
        self.MAX_RETRIES = 5
        self.RETRY_DELAY = 15
        self.REQUEST_TIMEOUT = 60
        
        self.HEADERS = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }

    def _set_smart_limits(self):
        if self.use_maximum_power:
            self._set_maximum_power_mode()
        else:
            self._set_specific_count_mode()

    def _set_maximum_power_mode(self):
        protocols_count = len(self.SUPPORTED_PROTOCOLS)
        
        for protocol in self.SUPPORTED_PROTOCOLS:
            self.SUPPORTED_PROTOCOLS[protocol].update({
                "min_configs": 1,
                "max_configs": float('inf'),
                "flexible_max": True
            })
        
        self.MIN_CONFIGS_PER_CHANNEL = 1
        self.MAX_CONFIGS_PER_CHANNEL = float('inf')
        self.MAX_RETRIES = 10
        self.CHANNEL_RETRY_LIMIT = 10
        self.REQUEST_TIMEOUT = 90

    def _set_specific_count_mode(self):
        if self.specific_config_count <= 0:
            self.specific_config_count = 50
        
        protocols_count = len(self.SUPPORTED_PROTOCOLS)
        base_per_protocol = max(1, self.specific_config_count // protocols_count)
        
        for protocol in self.SUPPORTED_PROTOCOLS:
            self.SUPPORTED_PROTOCOLS[protocol].update({
                "min_configs": 1,
                "max_configs": base_per_protocol * 2,
                "flexible_max": True
            })
        
        self.MIN_CONFIGS_PER_CHANNEL = 1
        self.MAX_CONFIGS_PER_CHANNEL = max(5, self.specific_config_count // 2)

    def _normalize_url(self, url: str) -> str:
        if url.startswith('ssconf://'):
            url = url.replace('ssconf://', 'https://', 1)
            
        parsed = urlparse(url)
        path = parsed.path.rstrip('/')
        
        if parsed.netloc.startswith('t.me/s/'):
            channel_name = parsed.path.strip('/').lower()
            return f"telegram:{channel_name}"
            
        return f"{parsed.scheme}://{parsed.netloc}{path}"

    def _remove_duplicate_urls(self, channel_configs: List[ChannelConfig]) -> List[ChannelConfig]:
        seen_urls = {}
        unique_configs = []
        
        for config in channel_configs:
            normalized_url = self._normalize_url(config.url)
            if normalized_url not in seen_urls:
                seen_urls[normalized_url] = True
                unique_configs.append(config)
                
        return unique_configs

    def is_protocol_enabled(self, protocol: str) -> bool:
        if protocol in self.SUPPORTED_PROTOCOLS:
            return True
        for main_protocol, info in self.SUPPORTED_PROTOCOLS.items():
            if 'aliases' in info and protocol in info['aliases']:
                return True
        return False

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
        
        if channel.metrics.overall_score < 25:
            channel.enabled = False

    def adjust_protocol_limits(self, channel: ChannelConfig):
        if self.use_maximum_power:
            return
            
        for protocol in channel.metrics.protocol_counts:
            if protocol in self.SUPPORTED_PROTOCOLS:
                current_count = channel.metrics.protocol_counts[protocol]
                if current_count > 0:
                    self.SUPPORTED_PROTOCOLS[protocol]["min_configs"] = min(
                        self.SUPPORTED_PROTOCOLS[protocol]["min_configs"],
                        current_count
                    )

    def save_empty_config_file(self):
        try:
            with open(self.OUTPUT_FILE, 'w', encoding='utf-8') as f:
                f.write("")
            return True
        except Exception:
            return False