import re
import os
import time
import logging
import base64
from datetime import datetime, timedelta
import requests
from bs4 import BeautifulSoup
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

def is_standard_base64(s):
    base64_pattern = re.compile(r'^[A-Za-z0-9+/]*={0,2}$')
    return bool(base64_pattern.match(s))

def is_valid_config(config, protocol):
    if not config.startswith(protocol):
        return False
    
    base64_part = config[len(protocol):]
    
    if protocol in ['vmess://', 'vless://', 'ss://']:
        return is_standard_base64(base64_part)
    else:
        standard_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~:/?#[]@!$&\'()*+,;=')
        return all(char in standard_chars for char in base64_part)

def extract_config(text, start_index, protocol):
    try:
        remaining_text = text[start_index:]
        possible_endings = [' ', '\n', '\r', '\t']
        end_index = len(remaining_text)
        
        for ending in possible_endings:
            pos = remaining_text.find(ending)
            if pos != -1 and pos < end_index:
                end_index = pos
        
        config = remaining_text[:end_index].strip()
        
        if is_valid_config(config, protocol):
            return config
        
        if protocol in ['vmess://', 'vless://', 'ss://']:
            base64_part = config[len(protocol):]
            equal_pos = base64_part.rfind('=')
            if equal_pos != -1:
                config = protocol + base64_part[:equal_pos + 1]
                if is_valid_config(config, protocol):
                    return config
        
        return None
    except Exception:
        return None

def process_configs(configs):
    processed = set()
    for config in configs:
        for protocol in SUPPORTED_PROTOCOLS:
            if config.startswith(protocol):
                clean_config = config.split('#')[0].strip()
                if is_valid_config(clean_config, protocol):
                    processed.add(clean_config)
                break
    return list(processed)

def fetch_configs_from_channel(channel_url):
    try:
        response = requests.get(channel_url, headers=HEADERS)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        messages = soup.find_all('div', class_='tgme_widget_message_text')
        
        configs = []
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
        
        return configs
        
    except Exception as e:
        logger.error(f"Error fetching from {channel_url}: {str(e)}")
        return []

def merge_with_existing_configs(new_configs):
    existing_configs = set()
    if os.path.exists(OUTPUT_FILE):
        with open(OUTPUT_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    config = line.split('#')[0].strip()
                    if any(config.startswith(p) for p in SUPPORTED_PROTOCOLS):
                        if is_valid_config(config, config[:config.find('://') + 3]):
                            existing_configs.add(config)
    
    existing_configs.update(new_configs)
    return list(existing_configs)

def fetch_all_configs():
    all_configs = []
    
    for channel in TELEGRAM_CHANNELS:
        logger.info(f"Fetching configs from {channel}")
        channel_configs = fetch_configs_from_channel(channel)
        processed_configs = process_configs(channel_configs)
        
        if len(processed_configs) >= MIN_CONFIGS_PER_CHANNEL:
            all_configs.extend(processed_configs)
        else:
            logger.warning(f"Not enough valid configs found in {channel}")
    
    if all_configs:
        all_configs = merge_with_existing_configs(all_configs)
        final_configs = [f"{config}#Anon{i+1}" for i, config in enumerate(all_configs)]
        return final_configs
    
    return []

def save_configs(configs):
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n\n'.join(configs))

def extract_date_from_message(message):
    try:
        time_element = message.find_parent('div', class_='tgme_widget_message').find('time')
        if time_element and 'datetime' in time_element.attrs:
            return datetime.fromisoformat(time_element['datetime'].replace('Z', '+00:00'))
    except Exception:
        return None
    return None

def is_config_valid(config_text, date):
    if not date:
        return False
    
    cutoff_date = datetime.now(date.tzinfo) - timedelta(days=MAX_CONFIG_AGE_DAYS)
    return date >= cutoff_date

def main():
    try:
        configs = fetch_all_configs()
        if configs:
            save_configs(configs)
            logger.info(f"Successfully saved {len(configs)} configs at {datetime.now()}")
        else:
            logger.error("No valid configs found!")
    except Exception as e:
        logger.error(f"Error in main execution: {str(e)}")

if __name__ == '__main__':
    main()