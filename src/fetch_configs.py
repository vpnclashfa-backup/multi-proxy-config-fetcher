import re
import os
import time
import json
import logging
import base64
from datetime import datetime, timedelta
from typing import List, Dict, Set, Optional, Tuple
import requests
from bs4 import BeautifulSoup
from urllib.parse import unquote

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('proxy_fetcher.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ConfigValidator:
    @staticmethod
    def is_base64(s: str) -> bool:
        try:
            s = s.rstrip('=')
            return bool(re.match(r'^[A-Za-z0-9+/\-_]*$', s))
        except:
            return False

    @staticmethod
    def decode_base64_url(s: str) -> Optional[bytes]:
        try:
            s = s.replace('-', '+').replace('_', '/')
            padding = 4 - (len(s) % 4)
            if padding != 4:
                s += '=' * padding
            return base64.b64decode(s)
        except:
            return None

    @staticmethod
    def clean_config(config: str) -> str:
        config = re.sub(r'[\U0001F300-\U0001F9FF]', '', config)
        config = re.sub(r'[\x00-\x08\x0B-\x1F\x7F-\x9F]', '', config)
        config = config.strip()
        if '#' in config:
            config = config.split('#')[0]
        return config

    @classmethod
    def validate_protocol_config(cls, config: str, protocol: str) -> bool:
        try:
            if protocol in ['vmess://', 'vless://', 'ss://']:
                base64_part = config[len(protocol):]
                decoded_url = unquote(base64_part)
                if cls.is_base64(decoded_url) or cls.is_base64(base64_part):
                    return True
                if cls.decode_base64_url(base64_part) or cls.decode_base64_url(decoded_url):
                    return True
            elif protocol in ['trojan://', 'hysteria2://', 'wireguard://']:
                return '@' in config and ':' in config
            return False
        except:
            return False

class ConfigFetcher:
    def __init__(self, config: ProxyConfig):
        self.config = config
        self.validator = ConfigValidator()
        self.protocol_counts: Dict[str, int] = {p: 0 for p in config.SUPPORTED_PROTOCOLS}

    def extract_config(self, text: str, start_index: int, protocol: str) -> Optional[str]:
        try:
            remaining_text = text[start_index:]
            possible_endings = [' ', '\n', '\r', '\t', '🔹', '♾', '🛜', '<', '>', '"', "'"]
            end_index = len(remaining_text)
            
            for ending in possible_endings:
                pos = remaining_text.find(ending)
                if pos != -1 and pos < end_index:
                    end_index = pos
            
            config = remaining_text[:end_index].strip()
            config = self.validator.clean_config(config)
            
            if self.validator.validate_protocol_config(config, protocol):
                return config
            
            return None
        except Exception as e:
            logger.error(f"Error in extract_config: {str(e)}")
            return None

    def fetch_configs_from_channel(self, channel: ChannelConfig) -> List[str]:
        configs: List[str] = []
        
        for attempt in range(self.config.MAX_RETRIES):
            try:
                response = requests.get(
                    channel.url,
                    headers=self.config.HEADERS,
                    timeout=self.config.REQUEST_TIMEOUT
                )
                response.raise_for_status()
                
                soup = BeautifulSoup(response.text, 'html.parser')
                messages = soup.find_all('div', class_='tgme_widget_message_text')
                
                for message in messages:
                    if not message or not message.text:
                        continue
                    
                    message_date = self.extract_date_from_message(message)
                    if not self.is_config_valid(message.text, message_date):
                        continue
                    
                    text = message.text
                    current_position = 0
                    
                    while current_position < len(text):
                        found_config = False
                        
                        for protocol in self.config.SUPPORTED_PROTOCOLS:
                            if self.protocol_counts[protocol] >= self.config.SUPPORTED_PROTOCOLS[protocol]["max_configs"]:
                                continue
                                
                            protocol_index = text.find(protocol, current_position)
                            
                            if protocol_index != -1:
                                config = self.extract_config(text, protocol_index, protocol)
                                if config:
                                    configs.append(config)
                                    self.protocol_counts[protocol] += 1
                                    current_position = protocol_index + len(config)
                                    found_config = True
                                    break
                        
                        if not found_config:
                            current_position += 1
                
                if len(configs) >= self.config.MIN_CONFIGS_PER_CHANNEL:
                    self.config.update_channel_stats(channel, True)
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
        
        total_configs = len(configs)
        min_configs_per_protocol = max(
            self.config.MIN_CONFIGS_PER_CHANNEL,
            int(total_configs * self.config.MIN_PROTOCOL_RATIO)
        )
        
        balanced_configs: List[str] = []
        for protocol, protocol_config_list in protocol_configs.items():
            if len(protocol_config_list) < min_configs_per_protocol:
                logger.warning(f"Insufficient configs for {protocol}: {len(protocol_config_list)}/{min_configs_per_protocol}")
            balanced_configs.extend(protocol_config_list[:self.config.SUPPORTED_PROTOCOLS[protocol]["max_configs"]])
        
        return balanced_configs

    def fetch_all_configs(self) -> List[str]:
        all_configs: List[str] = []
        enabled_channels = self.config.get_enabled_channels()
        
        for channel in enabled_channels:
            logger.info(f"Fetching configs from {channel.url}")
            channel_configs = self.fetch_configs_from_channel(channel)
            all_configs.extend(channel_configs)
        
        if all_configs:
            all_configs = self.balance_protocols(sorted(set(all_configs)))
            final_configs = []
            for i, config in enumerate(all_configs):
                if '#' not in config:
                    config = f"{config}#Anon{i+1}"
                final_configs.append(config)
            
            return final_configs
        
        return []

def save_configs(configs: List[str], config: ProxyConfig):
    try:
        os.makedirs(os.path.dirname(config.OUTPUT_FILE), exist_ok=True)
        with open(config.OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write('\n\n'.join(configs))
        logger.info(f"Successfully saved {len(configs)} configs to {config.OUTPUT_FILE}")
    except Exception as e:
        logger.error(f"Error saving configs: {str(e)}")

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
            
        # Save channel statistics
        save_channel_stats(config)
            
    except Exception as e:
        logger.error(f"Error in main execution: {str(e)}")

def save_channel_stats(config: ProxyConfig):
    """Save channel statistics to a JSON file for monitoring"""
    try:
        stats = {
            'timestamp': datetime.now().isoformat(),
            'channels': []
        }
        
        for channel in config.TELEGRAM_CHANNELS:
            channel_stats = {
                'url': channel.url,
                'enabled': channel.enabled,
                'retry_count': channel.retry_count,
                'success_rate': channel.success_rate
            }
            stats['channels'].append(channel_stats)
            
        os.makedirs(os.path.dirname(config.STATS_FILE), exist_ok=True)
        with open(config.STATS_FILE, 'w', encoding='utf-8') as f:
            json.dump(stats, f, indent=2)
            
        logger.info(f"Channel statistics saved to {config.STATS_FILE}")
    except Exception as e:
        logger.error(f"Error saving channel statistics: {str(e)}")

if __name__ == '__main__':
    main()