import re
import os
import time
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional, Set
import requests
from bs4 import BeautifulSoup
from config import ProxyConfig, ChannelConfig
from config_validator import ConfigValidator

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('proxy_fetcher.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ConfigFetcher:
    def __init__(self, config: ProxyConfig):
        self.config = config
        self.validator = ConfigValidator()
        self.protocol_counts: Dict[str, int] = {p: 0 for p in config.SUPPORTED_PROTOCOLS}
        self.seen_configs: Set[str] = set()
        self.channel_protocol_counts: Dict[str, Dict[str, int]] = {}
        self.session = requests.Session()
        self.session.headers.update(config.HEADERS)

    def fetch_with_retry(self, url: str) -> Optional[requests.Response]:
        backoff = 1
        for attempt in range(self.config.MAX_RETRIES):
            try:
                response = self.session.get(url, timeout=self.config.REQUEST_TIMEOUT)
                response.raise_for_status()
                return response
            except requests.RequestException as e:
                if attempt == self.config.MAX_RETRIES - 1:
                    logger.error(f"Failed to fetch {url} after {self.config.MAX_RETRIES} attempts: {str(e)}")
                    return None
                wait_time = min(self.config.RETRY_DELAY * backoff, 60)
                time.sleep(wait_time)
                backoff *= 2
        return None

    def fetch_configs_from_source(self, channel: ChannelConfig) -> List[str]:
        configs: List[str] = []
        channel.metrics.total_configs = 0
        channel.metrics.valid_configs = 0
        channel.metrics.unique_configs = 0
        channel.metrics.protocol_counts = {p: 0 for p in self.config.SUPPORTED_PROTOCOLS}
        start_time = time.time()
        response = self.fetch_with_retry(channel.url)
        if not response:
            self.config.update_channel_stats(channel, False)
            return configs
        response_time = time.time() - start_time
        text = response.text
        text_parts = text.split()
        for part in text_parts:
            part = part.strip()
            if not part:
                continue
            decoded_part = self.validator.decode_base64_text(part) if self.validator.is_base64(part) else part
            found_configs = self.validator.split_configs(decoded_part)
            channel.metrics.total_configs += len(found_configs)
            configs.extend(found_configs)
        configs = list(set(configs))
        for config in configs[:]:
            for protocol in self.config.SUPPORTED_PROTOCOLS:
                if config.startswith(protocol):
                    processed_configs = self.process_config(config, channel)
                    if not processed_configs:
                        configs.remove(config)
                    break
        if len(configs) >= self.config.MIN_CONFIGS_PER_CHANNEL:
            self.config.update_channel_stats(channel, True, response_time)
            self.config.adjust_protocol_limits(channel)
        else:
            self.config.update_channel_stats(channel, False)
        return configs

    def process_config(self, config: str, channel: ChannelConfig) -> List[str]:
        processed_configs = []
        if config.startswith('hy2://'):
            config = self.validator.normalize_hysteria2_protocol(config)
        for protocol, info in self.config.SUPPORTED_PROTOCOLS.items():
            aliases = info.get("aliases", [])
            if config.startswith(protocol):
                if not info.get("enabled", True):
                    return []
                clean_config = self.validator.clean_config(config)
                if self.validator.validate_protocol_config(clean_config, protocol):
                    channel.metrics.valid_configs += 1
                    channel.metrics.protocol_counts[protocol] += 1
                    if clean_config not in self.seen_configs:
                        channel.metrics.unique_configs += 1
                        self.seen_configs.add(clean_config)
                        processed_configs.append(clean_config)
                        self.protocol_counts[protocol] += 1
                break
            for alias in aliases:
                if config.startswith(alias):
                    if not info.get("enabled", True):
                        return []
                    config = config.replace(alias, protocol, 1)
                    clean_config = self.validator.clean_config(config)
                    if self.validator.validate_protocol_config(clean_config, protocol):
                        channel.metrics.valid_configs += 1
                        channel.metrics.protocol_counts[protocol] += 1
                        if clean_config not in self.seen_configs:
                            channel.metrics.unique_configs += 1
                            self.seen_configs.add(clean_config)
                            processed_configs.append(clean_config)
                            self.protocol_counts[protocol] += 1
                    break
            if processed_configs:
                break
        return processed_configs

    def fetch_all_configs(self) -> List[str]:
        all_configs: List[str] = []
        enabled_channels = self.config.get_enabled_channels()
        for channel in enabled_channels:
            channel_configs = self.fetch_configs_from_source(channel)
            all_configs.extend(channel_configs)
            time.sleep(2)
        return sorted(set(all_configs))

def save_configs(configs: List[str], config: ProxyConfig):
    try:
        os.makedirs(os.path.dirname(config.OUTPUT_FILE), exist_ok=True)
        with open(config.OUTPUT_FILE, 'w', encoding='utf-8') as f:
            for config in configs:
                f.write(config + '\n\n')
    except Exception:
        pass

def main():
    try:
        config = ProxyConfig()
        fetcher = ConfigFetcher(config)
        configs = fetcher.fetch_all_configs()
        if configs:
            save_configs(configs, config)
    except Exception:
        pass

if __name__ == '__main__':
    main()