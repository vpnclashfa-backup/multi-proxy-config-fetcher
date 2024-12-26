import re
import os
import logging
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

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def extract_date_from_message(message):
    try:
        time_element = message.find_parent('div', class_='tgme_widget_message').find('time')
        if time_element and 'datetime' in time_element.attrs:
            return datetime.fromisoformat(time_element['datetime'].replace('Z', '+00:00'))
    except Exception as e:
        logger.warning(f"Error extracting date: {e}")
    return None

def is_config_valid(config_text, date):
    if not date:
        return False
    cutoff_date = datetime.now(date.tzinfo) - timedelta(days=MAX_CONFIG_AGE_DAYS)
    return date >= cutoff_date

def process_config(config):
    base_config = config.split('#')[0].strip() # حذف فاصله های خالی ابتدا و انتها
    return base_config

def fetch_configs_from_channel(channel_url):
    try:
        response = requests.get(channel_url, headers=HEADERS)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        messages = soup.find_all('div', class_='tgme_widget_message_text')
        
        configs = []
        for message in messages:
            if not message:
                continue
            
            message_date = extract_date_from_message(message)
            if not is_config_valid(message.text, message_date):
                continue
            
            for protocol in SUPPORTED_PROTOCOLS:
                matches = re.finditer(f'{protocol}[^\s]+', message.text)
                for match in matches:
                    config = process_config(match.group(0))
                    configs.append(config)
            
            if len(configs) >= MIN_CONFIGS_PER_CHANNEL:
                break
        
        return configs
        
    except Exception as e:
        logger.error(f"Error fetching from {channel_url}: {str(e)}")
        return []

def fetch_all_configs():
    all_configs = []
    
    for channel in TELEGRAM_CHANNELS:
        logger.info(f"Fetching configs from {channel}")
        channel_configs = fetch_configs_from_channel(channel)
        
        if len(channel_configs) >= MIN_CONFIGS_PER_CHANNEL:
            all_configs.extend(channel_configs)
        else:
            logger.warning(f"Not enough valid configs found in {channel}")
    
    unique_configs = list(dict.fromkeys(all_configs)) #حذف موارد تکراری
    
    return unique_configs

def save_configs(configs):
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    try:
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            if configs:
                for i, config in enumerate(configs):
                    f.write(f"{config}#Anon{i+1}\n\n") #نوشتن کانفیگ با نامگذاری
            else:
                f.write("") #خالی کردن فایل در صورت نبود کانفیگ
        logger.info(f"Configs successfully saved to {OUTPUT_FILE}")
    except Exception as e:
        logger.error(f"Error saving configs to file: {e}")

def main():
    try:
        configs = fetch_all_configs()
        save_configs(configs)
        if configs:
            logger.info(f"Successfully saved {len(configs)} configs at {datetime.now()}")
        else:
            logger.info("No valid configs found, output file cleared.") #پیغام واضح تر
    except Exception as e:
        logger.error(f"Error in main execution: {str(e)}")

if __name__ == '__main__':
    main()