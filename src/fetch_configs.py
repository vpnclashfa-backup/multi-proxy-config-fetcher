import re
import os
import time
import json
import logging
from datetime import datetime, timedelta
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

    def fetch_ssconf_config(self, ssconf_url: str) -> Optional[str]:
        try:
            https_url = self.validator.convert_ssconf_to_https(ssconf_url)
            if not https_url:
                return None

            response = requests.get(https_url, timeout=10)
            response.raise_for_status()
            content = response.text.strip()
            if content.startswith("ss://"):
                return content
            else:
                logger.error(f"Invalid SS config format at {https_url}")
                return None
        except requests.RequestException as e:
            logger.error(f"Error fetching SS config from {ssconf_url}: {str(e)}")
            return None

    def fetch_configs_from_source(self, channel: ChannelConfig) -> List[str]:
        configs: List[str] = []
        channel.metrics.total_configs = 0
        channel.metrics.valid_configs = 0
        channel.metrics.unique_configs = 0

        start_time = time.time()

        for attempt in range(self.config.MAX_RETRIES):
            try:
                response = requests.get(
                    channel.url,
                    headers=self.config.HEADERS,
                    timeout=self.config.REQUEST_TIMEOUT
                )
                response.raise_for_status()

                response_time = time.time() - start_time

                if channel.is_telegram:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    messages = soup.find_all('div', class_='tgme_widget_message_text')

                    for message in messages:
                        if not message or not message.text:
                            continue

                        message_date = self.extract_date_from_message(message)
                        if not self.is_config_valid(message.text, message_date):
                            continue

                        text = message.text
                        found_configs = self.validator.split_configs(text)
                        channel.metrics.total_configs += len(found_configs)

                        for config in found_configs:
                            if config.startswith("ssconf://"):
                                fetched_config = self.fetch_ssconf_config(config)
                                if fetched_config:
                                    configs.append(fetched_config)
                            else:
                                configs.extend(self.process_config(config, channel))
                else:
                    text = response.text
                    found_configs = self.validator.split_configs(text)
                    channel.metrics.total_configs += len(found_configs)

                    for config in found_configs:
                        if config.startswith("ssconf://"):
                            fetched_config = self.fetch_ssconf_config(config)
                            if fetched_config:
                                configs.append(fetched_config)
                        else:
                            configs.extend(self.process_config(config, channel))

                if len(configs) >= self.config.MIN_CONFIGS_PER_CHANNEL:
                    self.config.update_channel_stats(channel, True, response_time)
                    break
                elif attempt < self.config.MAX_RETRIES - 1:
                    logger.warning(f"Not enough configs found in {channel.url}, retrying...")
                    time.sleep(self.config.RETRY_DELAY)

            except Exception as e:
                logger.error(f"Attempt {attempt + 1}/{self.config.MAX_RETRIES} failed for {channel.url}: {str(e)}")
                if attempt < self.config.MAX_RETRIES - 1:
                    time.sleep(self.config.RETRY_DELAY)
                continue

        if not configs:
            self.config.update_channel_stats(channel, False)

        return configs

    def process_config(self, config: str, channel: ChannelConfig) -> List[str]:
        processed_configs = []
        for protocol in self.config.SUPPORTED_PROTOCOLS:
            if config.startswith(protocol):
                if protocol == "vmess://":
                    config = self.validator.clean_vmess_config(config)
                if self.protocol_counts[protocol] >= self.config.SUPPORTED_PROTOCOLS[protocol]["max_configs"]:
                    continue

                clean_config = self.validator.clean_config(config)
                if self.validator.validate_protocol_config(clean_config, protocol):
                    channel.metrics.valid_configs += 1
                    if clean_config not in self.seen_configs:
                        channel.metrics.unique_configs += 1
                        self.seen_configs.add(clean_config)
                        processed_configs.append(clean_config)
                        self.protocol_counts[protocol] += 1
                break
        return processed_configs

    def extract_date_from_message(self, message) -> Optional[datetime]:
        try:
            time_element = message.find_parent('div', class_='tgme_widget_message').find('time')
            if time_element and 'datetime' in time_element.attrs:
                return datetime.fromisoformat(time_element['datetime'].replace('Z', '+00:00'))
        except Exception:
            pass
        return None

    def is_config_valid(self, config_text: str, date: Optional[datetime]) -> bool:
        if not date:
            return True
        cutoff_date = datetime.now(date.tzinfo) - timedelta(days=self.config.MAX_CONFIG_AGE_DAYS)
        return date >= cutoff_date

    def balance_protocols(self, configs: List[str]) -> List[str]:
        protocol_configs: Dict[str, List[str]] = {p: [] for p in self.config.SUPPORTED_PROTOCOLS}
        for config in configs:
            for protocol in self.config.SUPPORTED_PROTOCOLS:
                if config.startswith(protocol):
                    protocol_configs[protocol].append(config)
                    break

        balanced_configs: List[str] = []
        for protocol, protocol_config_list in sorted(protocol_configs.items()):
            balanced_configs.extend(protocol_config_list[:self.config.SUPPORTED_PROTOCOLS[protocol]["max_configs"]])

        return balanced_configs

    def fetch_all_configs(self) -> List[str]:
        all_configs: List[str] = []
        enabled_channels = self.config.get_enabled_channels()

        for channel in enabled_channels:
            logger.info(f"Fetching configs from {channel.url}")
            channel_configs = self.fetch_configs_from_source(channel)
            all_configs.extend(channel_configs)

        if all_configs:
            all_configs = self.balance_protocols(sorted(set(all_configs)))
            return all_configs
        return []

def save_configs(configs: List[str], config: ProxyConfig):
    try:
        os.makedirs(os.path.dirname(config.OUTPUT_FILE), exist_ok=True)
        with open(config.OUTPUT_FILE, 'w', encoding='utf-8') as f:
            for config in configs:
                f.write(config + '\n\n')
        logger.info(f"Successfully saved {len(configs)} configs to {config.OUTPUT_FILE}")
    except Exception as e:
        logger.error(f"Error saving configs: {str(e)}")

def save_channel_stats(config: ProxyConfig):
    try:
        stats = {
            'timestamp': datetime.now().isoformat(),
            'channels': []
        }

        for channel in config.SOURCE_URLS:
            channel_stats = {
                'url': channel.url,
                'enabled': channel.enabled,
                'metrics': {
                    'total_configs': channel.metrics.total_configs,
                    'valid_configs': channel.metrics.valid_configs,
                    'unique_configs': channel.metrics.unique_configs,
                    'avg_response_time': round(channel.metrics.avg_response_time, 2),
                    'success_count': channel.metrics.success_count,
                    'fail_count': channel.metrics.fail_count,
                    'overall_score': round(channel.metrics.overall_score, 2),
                    'last_success': channel.metrics.last_success_time.isoformat() if channel.metrics.last_success_time else None
                }
            }
            stats['channels'].append(channel_stats)

        os.makedirs(os.path.dirname(config.STATS_FILE), exist_ok=True)
        with open(config.STATS_FILE, 'w', encoding='utf-8') as f:
            json.dump(stats, f, indent=2)

        logger.info(f"Channel statistics saved to {config.STATS_FILE}")
    except Exception as e:
        logger.error(f"Error saving channel statistics: {str(e)}")

def main():
    try:
        config = ProxyConfig()
        fetcher = ConfigFetcher(config)
        configs = fetcher.fetch_all_configs()

        if configs:
            save_configs(configs, config)
            logger.info(f"Successfully processed {len(configs)} configs at {datetime.now()}")

            for protocol, count in fetcher.protocol_counts.items():
                logger.info(f"{protocol}: {count} configs")
        else:
            logger.error("No valid configs found!")

        save_channel_stats(config)

    except Exception as e:
        logger.error(f"Error in main execution: {str(e)}")

if __name__ == '__main__':
    main()