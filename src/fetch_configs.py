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

def is_base64(s):
    try:
        s = s.rstrip('=')
        if not bool(re.match(r'^[A-Za-z0-9+/]*$', s)):
            return False
        if len(s) % 4 == 1:
            return False
        try:
            base64.b64decode(s + '=' * (-len(s) % 4))
            return True
        except:
            return False
    except:
        return False

def clean_config(config):
    config = re.sub(r'[\U0001F300-\U0001F9FF]', '', config)
    config = re.sub(r'[\x00-\x08\x0B-\x1F\x7F-\x9F]', '', config)
    return config.strip()

def extract_config(text, start_index, protocol):
    try:
        remaining_text = text[start_index:]
        
        if protocol in ['vmess://', 'vless://', 'ss://']:
            current_pos = 0
            base64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
            
            while current_pos < len(remaining_text):
                if remaining_text[current_pos] not in base64_chars:
                    break
                current_pos += 1
            
            while current_pos < len(remaining_text) and remaining_text[current_pos] == '=':
                current_pos += 1
            
            config = remaining_text[:current_pos].strip()
            
            if is_base64(config[len(protocol):]):
                return config
                
        else:
            valid_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~:/?#[]@!$&\'()*+,;=')
            current_pos = 0
            
            while current_pos < len(remaining_text):
                if remaining_text[current_pos] not in valid_chars:
                    break
                current_pos += 1
            
            config = remaining_text[:current_pos].strip()
            
            while config and config[-1] not in valid_chars:
                config = config[:-1]
            
            if len(config) > len(protocol) and config.startswith(protocol):
                return config
        
        return None
        
    except Exception as e:
        logger.error(f"Error in extract_config: {str(e)}")
        return None

def process_configs(configs):
    processed = []
    seen = set()
    
    for config in configs:
        config = clean_config(config)
        
        if config in seen:
            continue
            
        for protocol in SUPPORTED_PROTOCOLS:
            if config.startswith(protocol):
                if protocol in ['vmess://', 'vless://', 'ss://']:
                    base64_part = config[len(protocol):]
                    if is_base64(base64_part):
                        processed.append(config)
                        seen.add(config)
                else:
                    processed.append(config)
                    seen.add(config)
                break
                
    return processed

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
        
        return configs
        
    except Exception as e:
        logger.error(f"Error fetching from {channel_url}: {str(e)}")
        return []

def fetch_all_configs():
    all_configs = []
    
    for channel in TELEGRAM_CHANNELS:
        logger.info(f"Fetching configs from {channel}")
        channel_configs = fetch_configs_from_channel(channel)
        processed_configs = process_configs(channel_configs)
        all_configs.extend(processed_configs)
    
    if all_configs:
        all_configs = sorted(set(all_configs))
        final_configs = []
        for i, config in enumerate(all_configs):
            if any(config.startswith(p) for p in ['vmess://', 'vless://', 'ss://']) and is_base64(config.split('://', 1)[1]):
                final_configs.append(config)
            else:
                if '#' in config:
                    config = config.split('#')[0]
                final_configs.append(f"{config}#Anon{i+1}")
        
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