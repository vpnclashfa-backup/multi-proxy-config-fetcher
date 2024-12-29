import re
import os
import time
import json
import logging
import base64
import asyncio
import aiohttp
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Set
from bs4 import BeautifulSoup
from urllib.parse import unquote
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

def add_config_name(config: str, index: int) -> str:
    is_base64, protocol = ConfigValidator.is_base64_config(config)
    
    if is_base64:
        return config
    elif '#' not in config:
        return f"{config}#Anon{index+1}"
    
    return config

class ConfigFetcher:
    def __init__(self, config: ProxyConfig):
        self.config = config
        self.validator = ConfigValidator()
        self.protocol_counts: Dict[str, int] = {p: 0 for p in config.SUPPORTED_PROTOCOLS}
        self.session: Optional[aiohttp.ClientSession] = None
        self.configs_seen: Set[str] = set()

    async def create_session(self):
        if not self.session:
            timeout = aiohttp.ClientTimeout(total=self.config.REQUEST_TIMEOUT)
            self.session = aiohttp.ClientSession(timeout=timeout, headers=self.config.HEADERS)

    async def close_session(self):
        if self.session:
            await self.session.close()
            self.session = None

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
            
            if config in self.configs_seen:
                return None
                
            if self.validator.validate_protocol_config(config, protocol):
                self.configs_seen.add(config)
                return config
            
            return None
        except Exception as e:
            logger.error(f"Error in extract_config: {str(e)}")
            return None

    async def fetch_configs_from_channel(self, channel: ChannelConfig) -> List[str]:
        configs: List[str] = []
        
        for attempt in range(self.config.MAX_RETRIES):
            try:
                async with self.session.get(channel.url) as response:
                    if response.status != 200:
                        raise Exception(f"HTTP {response.status}")
                    
                    text = await response.text()
                    soup = BeautifulSoup(text, 'html.parser')
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
                    await asyncio.sleep(self.config.RETRY_DELAY)
                
            except Exception as e:
                logger.error(f"Attempt {attempt + 1}/{self.config.MAX_RETRIES} failed for {channel.url}: {str(e)}")
                if attempt < self.config.MAX_RETRIES - 1:
                    await asyncio.sleep(self.config.RETRY_DELAY)
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

    async def fetch_all_configs(self) -> List[str]:
        await self.create_session()
        
        try:
            all_configs: List[str] = []
            enabled_channels = self.config.get_enabled_channels()
            
            tasks = [self.fetch_configs_from_channel(channel) for channel in enabled_channels]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for channel_configs in results:
                if isinstance(channel_configs, list):
                    all_configs.extend(channel_configs)
            
            if all_configs:
                all_configs = self.balance_protocols(sorted(set(all_configs)))
                final_configs = []
                for i, config in enumerate(all_configs):
                    final_configs.append(add_config_name(config, i))
                
                return final_configs
            
            return []
        finally:
            await self.close_session()

def save_configs(configs: List[str], config: ProxyConfig):
    try:
        os.makedirs(os.path.dirname(config.OUTPUT_FILE), exist_ok=True)
        with open(config.OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write('\n\n'.join(configs))
        logger.info(f"Successfully saved {len(configs)} configs to {config.OUTPUT_FILE}")
    except Exception as e:
        logger.error(f"Error saving configs: {str(e)}")

def save_channel_stats(config: ProxyConfig):
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

async def main():
    try:
        config = ProxyConfig()
        fetcher = ConfigFetcher(config)
        configs = await fetcher.fetch_all_configs()
        
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
    asyncio.run(main())