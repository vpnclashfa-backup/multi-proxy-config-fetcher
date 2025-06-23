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

    # ... (All methods from extract_config down to is_config_valid remain unchanged) ...
    def extract_config(self, text: str, start_index: int, protocol: str) -> Optional[str]:
        try:
            remaining_text = text[start_index:]
            configs = self.validator.split_configs(remaining_text)

            for config in configs:
                if config.startswith(protocol):
                    clean_config = self.validator.clean_config(config)
                    if self.validator.validate_protocol_config(clean_config, protocol):
                        return clean_config
            return None
        except Exception as e:
            logger.error(f"Error in extract_config: {str(e)}")
            return None

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
                logger.warning(f"Attempt {attempt + 1} failed, retrying in {wait_time}s: {str(e)}")
                time.sleep(wait_time)
                backoff *= 2
        return None

    def fetch_ssconf_configs(self, url: str) -> List[str]:
        https_url = self.validator.convert_ssconf_to_https(url)
        configs = []

        response = self.fetch_with_retry(https_url)
        if response and response.text.strip():
            text = response.text.strip()
            if self.validator.is_base64(text):
                decoded = self.validator.decode_base64_text(text)
                if decoded:
                    text = decoded

            if text.startswith('ss://'):
                configs.append(text)
            else:
                configs.extend(self.validator.split_configs(text))

        return configs

    def check_and_decode_base64(self, text: str) -> str:
        if self.validator.is_base64(text):
            decoded = self.validator.decode_base64_text(text)
            if decoded:
                return decoded
        return text

    def fetch_configs_from_source(self, channel: ChannelConfig) -> List[str]:
        configs: List[str] = []
        channel.metrics.total_configs = 0
        channel.metrics.valid_configs = 0
        channel.metrics.unique_configs = 0
        channel.metrics.protocol_counts = {p: 0 for p in self.config.SUPPORTED_PROTOCOLS}

        start_time = time.time()

        if channel.url.startswith('ssconf://'):
            configs.extend(self.fetch_ssconf_configs(channel.url))
            if configs:
                response_time = time.time() - start_time
                self.config.update_channel_stats(channel, True, response_time)
            return configs

        response = self.fetch_with_retry(channel.url)
        if not response:
            self.config.update_channel_stats(channel, False)
            return configs

        response_time = time.time() - start_time

        if channel.is_telegram:
            soup = BeautifulSoup(response.text, 'html.parser')
            messages = soup.find_all('div', class_='tgme_widget_message_text')

            sorted_messages = sorted(
                messages,
                key=lambda message: self.extract_date_from_message(message) or datetime.min.replace(tzinfo=timezone.utc),
                reverse=True
            )

            for message in sorted_messages:
                if not message or not message.text:
                    continue

                message_date = self.extract_date_from_message(message)
                if not self.is_config_valid(message.text, message_date):
                    continue

                text = message.text
                text_parts = text.split()

                for part in text_parts:
                    part = part.strip()
                    if not part:
                        continue

                    if part.startswith('ssconf://'):
                        ssconf_configs = self.fetch_ssconf_configs(part)
                        configs.extend(ssconf_configs)
                        channel.metrics.total_configs += len(ssconf_configs)
                    else:
                        decoded_part = self.check_and_decode_base64(part)
                        if decoded_part != part:
                            found_configs = self.validator.split_configs(decoded_part)
                            channel.metrics.total_configs += len(found_configs)
                            configs.extend(found_configs)

                found_configs = self.validator.split_configs(text)
                channel.metrics.total_configs += len(found_configs)
                configs.extend(found_configs)
        else:
            text = response.text
            text_parts = text.split()

            for part in text_parts:
                part = part.strip()
                if not part:
                    continue

                decoded_part = self.check_and_decode_base64(part)
                if decoded_part != part:
                    found_configs = self.validator.split_configs(decoded_part)
                    channel.metrics.total_configs += len(found_configs)
                    configs.extend(found_configs)

            found_configs = self.validator.split_configs(text)
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
            logger.warning(f"Not enough configs found in {channel.url}: {len(configs)} configs")

        return configs

    def process_config(self, config: str, channel: ChannelConfig) -> List[str]:
        processed_configs = []

        if config.startswith('hy2://'):
            config = self.validator.normalize_hysteria2_protocol(config)

        for protocol in self.config.SUPPORTED_PROTOCOLS:
            aliases = self.config.SUPPORTED_PROTOCOLS[protocol].get('aliases', [])
            protocol_match = False

            if config.startswith(protocol):
                protocol_match = True
            else:
                for alias in aliases:
                    if config.startswith(alias):
                        protocol_match = True
                        config = config.replace(alias, protocol, 1)
                        break

            if protocol_match:
                if not self.config.is_protocol_enabled(protocol):
                    break
                if protocol == "vmess://":
                    config = self.validator.clean_vmess_config(config)

                clean_config = self.validator.clean_config(config)
                if self.validator.validate_protocol_config(clean_config, protocol):
                    channel.metrics.valid_configs += 1
                    channel.metrics.protocol_counts[protocol] = channel.metrics.protocol_counts.get(protocol, 0) + 1

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
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=self.config.MAX_CONFIG_AGE_DAYS)
        return date >= cutoff_date
    
    def balance_protocols(self, configs: List[str]) -> Dict[str, List[str]]:
        """
        MODIFIED: This function now returns a dictionary of configs categorized by protocol
        instead of a flat list.
        """
        protocol_configs: Dict[str, List[str]] = {p: [] for p in self.config.SUPPORTED_PROTOCOLS}
        for config in configs:
            # Normalize hy2 alias for correct categorization
            normalized_config = self.validator.normalize_hysteria2_protocol(config)
            
            for protocol in self.config.SUPPORTED_PROTOCOLS:
                if normalized_config.startswith(protocol):
                    protocol_configs[protocol].append(config) # Append original config
                    break

        # The balancing logic can be enhanced, but for now, we'll just categorize
        # and return all valid unique configs found, separated by protocol.
        # You could add logic here to limit the number of configs per protocol if needed.
        
        return protocol_configs

    def fetch_all_configs(self) -> Dict[str, List[str]]:
        """
        MODIFIED: This function now returns a dictionary of configs categorized by protocol.
        """
        all_configs: List[str] = []
        enabled_channels = self.config.get_enabled_channels()
        total_channels = len(enabled_channels)

        for idx, channel in enumerate(enabled_channels, 1):
            logger.info(f"Fetching configs from {channel.url} ({idx}/{total_channels})")
            try:
                channel_configs = self.fetch_configs_from_source(channel)
                all_configs.extend(channel_configs)
            except Exception as e:
                logger.error(f"Failed to fetch from {channel.url}: {e}")

            if idx < total_channels:
                time.sleep(2)
        
        unique_configs = sorted(list(set(all_configs)))
        categorized_configs = self.balance_protocols(unique_configs)
        
        return categorized_configs

def save_configs(categorized_configs: Dict[str, List[str]], config: ProxyConfig):
    """
    MODIFIED: Saves a main subscription file with all configs, and also saves
    separate subscription files for each protocol.
    """
    try:
        output_dir = os.path.dirname(config.OUTPUT_FILE)
        os.makedirs(output_dir, exist_ok=True)
        
        all_configs_list = []
        
        # --- Save per-protocol files ---
        for protocol_scheme, configs_list in categorized_configs.items():
            if not configs_list:
                continue
            
            all_configs_list.extend(configs_list)
            protocol_name = protocol_scheme.replace("://", "")
            protocol_filename = os.path.join(output_dir, f"{protocol_name}_configs.txt")
            
            try:
                with open(protocol_filename, 'w', encoding='utf-8') as f:
                    f.write('\n\n'.join(configs_list))
                logger.info(f"Successfully saved {len(configs_list)} configs to {protocol_filename}")
            except Exception as e:
                logger.error(f"Error saving protocol file {protocol_filename}: {e}")

        # --- Save main combined file ---
        header = """//profile-title: base64:8J+RvUFub255bW91cy3wnZWP
//profile-update-interval: 1
//subscription-userinfo: upload=0; download=0; total=10737418240000000; expire=2546249531
//support-url: https://t.me/BXAMbot
//profile-web-page-url: https://github.com/4n0nymou3

"""
        with open(config.OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write(header)
            f.write('\n\n'.join(all_configs_list))
        logger.info(f"Successfully saved {len(all_configs_list)} total configs to {config.OUTPUT_FILE}")

    except Exception as e:
        logger.error(f"Error saving config files: {str(e)}")


def save_channel_stats(config: ProxyConfig):
    # ... (This function remains unchanged) ...
    try:
        stats = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
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
                    'last_success': channel.metrics.last_success_time.replace(tzinfo=timezone.utc).isoformat() if channel.metrics.last_success_time else None,
                    'protocol_counts': channel.metrics.protocol_counts
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
    """
    MODIFIED: The main function is updated to handle the new categorized output.
    """
    try:
        config = ProxyConfig()
        fetcher = ConfigFetcher(config)
        
        logger.info("Starting config fetching process...")
        categorized_configs = fetcher.fetch_all_configs()

        total_config_count = sum(len(v) for v in categorized_configs.values())

        if total_config_count > 0:
            save_configs(categorized_configs, config)
            logger.info(f"Successfully processed {total_config_count} configs at {datetime.now(timezone.utc)}")

            for protocol, count in fetcher.protocol_counts.items():
                if count > 0:
                    logger.info(f"-> Found {count} {protocol.replace('://','')} configs")
        else:
            logger.warning("No valid configs found!")

        save_channel_stats(config)
        logger.info("Process finished.")

    except Exception as e:
        logger.error(f"Error in main execution: {str(e)}")

if __name__ == '__main__':
    main()
