import re
import os
import time
import logging
import base64
from datetime import datetime, timedelta
import requests
from bs4 import BeautifulSoup

# تنظیمات (در فایل config.py قرار دارند)
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
        base64.b64decode(s)
        return True
    except (base64.binascii.Error, UnicodeDecodeError):
        return False

def is_valid_config(config, protocol):
    if not config.startswith(protocol):
        return False

    config_part = config[len(protocol):]

    if protocol in ['vmess://', 'vless://', 'ss://']:
        return is_base64(config_part)
    elif protocol == 'wireguard://':  # بررسی بیشتر برای WireGuard
        parts = config_part.split('@')
        if len(parts) != 2:
            return False
        return True
    elif protocol == 'hysteria2://':
        parts = config_part.split('?')
        if len(parts) < 1:
            return False
        return True
    elif protocol == 'trojan://':
        parts = config_part.split('@')
        if len(parts) != 2:
            return False
        return True
    else:
        return True

def extract_config(text, start_index, protocol):
    try:
        remaining_text = text[start_index:]
        end_index = re.search(r'(?:\s|$)', remaining_text)
        if end_index:
            end_index = end_index.start()
        else:
            end_index = len(remaining_text)

        config = remaining_text[:end_index].strip()

        if is_valid_config(config, protocol):
            return config
        return None
    except Exception as e:
        logger.error(f"Error extracting config: {e}")
        return None

def process_configs(configs):
    processed = set()
    for config in configs:
        for protocol in SUPPORTED_PROTOCOLS:
            if config.startswith(protocol):
                if is_valid_config(config, protocol):
                    processed.add(config)
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
            for protocol in SUPPORTED_PROTOCOLS:
                for match in re.finditer(re.escape(protocol), text):
                    config = extract_config(text, match.start(), protocol)
                    if config:
                        configs.append(config)
        return configs

    except requests.exceptions.RequestException as e:
        logger.error(f"Request error for {channel_url}: {e}")
        return []
    except Exception as e:
        logger.error(f"Error fetching from {channel_url}: {e}")
        return []

def merge_with_existing_configs(new_configs):
    existing_configs = set()
    if os.path.exists(OUTPUT_FILE):
        try:
            with open(OUTPUT_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        existing_configs.add(line.split('#')[0].strip())
        except FileNotFoundError:
            pass
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
            logger.info("No valid configs found!")
    except Exception as e:
        logger.error(f"Error in main execution: {str(e)}")

if __name__ == '__main__':
    main()