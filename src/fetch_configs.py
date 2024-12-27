import re
import os
import time
import logging
import base64
from datetime import datetime, timedelta
import requests
from bs4 import BeautifulSoup
from urllib.parse import unquote
from config import (
    TELEGRAM_CHANNELS,
    SUPPORTED_PROTOCOLS,
    MIN_CONFIGS_PER_CHANNEL,
    MAX_CONFIG_AGE_DAYS,
    OUTPUT_FILE,
    HEADERS
)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def is_base64(s):
    try:
        s = s.rstrip('=')
        return bool(re.match(r'^[A-Za-z0-9+/\-_]*$', s))
    except:
        return False

def decode_base64_url(s):
    try:
        s = s.replace('-', '+').replace('_', '/')
        padding = 4 - (len(s) % 4)
        if padding != 4:
            s += '=' * padding
        return base64.b64decode(s)
    except:
        return None

def clean_config(config):
    config = re.sub(r'[\U0001F300-\U0001F9FF]', '', config)
    config = re.sub(r'[\x00-\x08\x0B-\x1F\x7F-\x9F]', '', config)
    config = config.strip()
    if '#' in config:
        config = config.split('#')[0]
    return config

def validate_protocol_config(config, protocol):
    try:
        if protocol in ['vmess://', 'vless://', 'ss://']:
            base64_part = config[len(protocol):]
            decoded_url = unquote(base64_part)
            if is_base64(decoded_url) or is_base64(base64_part):
                return True
            if decode_base64_url(base64_part) or decode_base64_url(decoded_url):
                return True
        elif protocol == 'trojan://':
            if '@' in config and ':' in config:
                return True
        elif protocol == 'hysteria2://' or protocol == 'wireguard://':
            if '@' in config or ':' in config:
                return True
        return False
    except:
        return False

def extract_config(text, start_index, protocol):
    try:
        remaining_text = text[start_index:]
        
        possible_endings = [' ', '\n', '\r', '\t', '🔹', '♾', '🛜', '<', '>', '"', "'"]
        end_index = len(remaining_text)
        
        for ending in possible_endings:
            pos = remaining_text.find(ending)
            if pos != -1 and pos < end_index:
                end_index = pos
        
        config = remaining_text[:end_index].strip()
        config = clean_config(config)
        
        if validate_protocol_config(config, protocol):
            return config
        
        return None
    except Exception as e:
        logger.error(f"Error in extract_config: {str(e)}")
        return None

def fetch_configs_from_channel(channel_url):
    configs = []
    max_retries = 3
    retry_delay = 5
    
    for attempt in range(max_retries):
        try:
            response = requests.get(channel_url, headers=HEADERS, timeout=30)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.text, 'html.parser')
            messages = soup.find_all('div', class_='tgme_widget_message_text')
            
            for message in messages:
                if not message or not message.text:
                    continue
                
                message_date = extract_date_from_message(message)
                if not is_config_valid(message.text, message_date):
                    continue
                
                text = message.text
                current_position = 0
                
                while current_position < len(text):
                    found_config = False
                    
                    for protocol in SUPPORTED_PROTOCOLS:
                        protocol_index = text.find(protocol, current_position)
                        
                        if protocol_index != -1:
                            config = extract_config(text, protocol_index, protocol)
                            if config:
                                configs.append(config)
                                current_position = protocol_index + len(config)
                                found_config = True
                                break
                    
                    if not found_config:
                        current_position += 1
            
            if len(configs) >= MIN_CONFIGS_PER_CHANNEL:
                break
            elif attempt < max_retries - 1:
                logger.warning(f"Not enough configs found in {channel_url}, retrying...")
                time.sleep(retry_delay)
            
        except Exception as e:
            logger.error(f"Attempt {attempt + 1}/{max_retries} failed for {channel_url}: {str(e)}")
            if attempt < max_retries - 1:
                time.sleep(retry_delay)
            continue
    
    return configs

def process_configs(configs):
    processed = []
    seen = set()
    
    for config in configs:
        config = clean_config(config)
        
        if config in seen:
            continue
            
        for protocol in SUPPORTED_PROTOCOLS:
            if config.startswith(protocol):
                if validate_protocol_config(config, protocol):
                    processed.append(config)
                    seen.add(config)
                break
    
    return processed

def extract_date_from_message(message):
    try:
        time_element = message.find_parent('div', class_='tgme_widget_message').find('time')
        if time_element and 'datetime' in time_element.attrs:
            return datetime.fromisoformat(time_element['datetime'].replace('Z', '+00:00'))
    except Exception:
        pass
    return None

def is_config_valid(config_text, date):
    if not date:
        return True
    
    cutoff_date = datetime.now(date.tzinfo) - timedelta(days=MAX_CONFIG_AGE_DAYS)
    return date >= cutoff_date

def fetch_all_configs():
    all_configs = []
    
    for channel in TELEGRAM_CHANNELS:
        logger.info(f"Fetching configs from {channel}")
        channel_configs = fetch_configs_from_channel(channel)
        processed_configs = process_configs(channel_configs)
        
        if len(processed_configs) < MIN_CONFIGS_PER_CHANNEL:
            logger.warning(f"Only found {len(processed_configs)} valid configs in {channel}")
        
        all_configs.extend(processed_configs)
    
    if all_configs:
        all_configs = sorted(set(all_configs))
        final_configs = []
        for i, config in enumerate(all_configs):
            if '#' not in config:
                config = f"{config}#Anon{i+1}"
            final_configs.append(config)
        
        return final_configs
    
    return []

def save_configs(configs):
    try:
        os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write('\n\n'.join(configs))
        logger.info(f"Successfully saved {len(configs)} configs to {OUTPUT_FILE}")
    except Exception as e:
        logger.error(f"Error saving configs: {str(e)}")

def main():
    try:
        configs = fetch_all_configs()
        if configs:
            save_configs(configs)
            logger.info(f"Successfully processed {len(configs)} configs at {datetime.now()}")
        else:
            logger.error("No valid configs found!")
    except Exception as e:
        logger.error(f"Error in main execution: {str(e)}")

if __name__ == '__main__':
    main()