import re
import os
import time
import logging
import base64
from datetime import datetime, timedelta
import requests
from bs4 import BeautifulSoup

# از فایل config.py تنظیمات را بخوانید
try:
    from config import (
        TELEGRAM_CHANNELS,
        SUPPORTED_PROTOCOLS,
        MIN_CONFIGS_PER_CHANNEL,
        MAX_CONFIG_AGE_DAYS,
        OUTPUT_FILE,
        HEADERS
    )
except ImportError:
    print("Error: config.py file not found. Please create it.")
    exit()

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

    base64_part = config[len(protocol):]
    if protocol in ['vmess://', 'vless://', 'ss://']:
        return is_base64(base64_part)
    elif protocol in ['trojan://', 'hysteria2://', 'wireguard://']:
        return True # برای این پروتکل ها بررسی خاصی نیاز نیست
    return False

def extract_config(text, start_index, protocol):
    try:
        remaining_text = text[start_index:]
        end_index = re.search(r"[ \n\r\t#]", remaining_text)
        if end_index:
            end_index = end_index.start()
        else:
            end_index = len(remaining_text)
            
        config = remaining_text[:end_index].strip()
        if is_valid_config(config, protocol):
            return config
        return None
    except Exception as e:
        logger.error(f"Error in extract_config: {e}")
        return None

def process_configs(configs):
    processed = set()
    for config in configs:
        for protocol in SUPPORTED_PROTOCOLS:
            if config.startswith(protocol):
                clean_config = config.strip()
                if is_valid_config(clean_config, protocol):
                    processed.add(clean_config)
                break
    return list(processed)

def fetch_configs_from_channel(channel_url):
    try:
        response = requests.get(channel_url, headers=HEADERS, timeout=10) #اضافه کردن timeout
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser') #استفاده از response.content
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
            if len(configs) >= MIN_CONFIGS_PER_CHANNEL:
                break
        return configs
    except requests.exceptions.RequestException as e: # مدیریت خطاهای درخواست
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
                        existing_configs.add(line)
        except Exception as e:
            logger.error(f"Error reading existing configs: {e}")
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
    return all_configs

def save_configs(configs):
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        for i, config in enumerate(configs):
            f.write(f"{config}#Anon{i+1}\n\n")

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
            final_configs = merge_with_existing_configs(configs)
            save_configs(final_configs)
            logger.info(f"Successfully saved {len(final_configs)} configs at {datetime.now()}")
        else:
            logger.error("No valid configs found!")
    except Exception as e:
        logger.error(f"Error in main execution: {e}")

if __name__ == '__main__':
    main()