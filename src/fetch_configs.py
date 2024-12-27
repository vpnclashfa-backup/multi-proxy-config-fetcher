# fetch_configs.py
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
    """بررسی اعتبار رشته base64 با در نظر گرفتن استثناها"""
    try:
        s = s.rstrip('=')
        return bool(re.match(r'^[A-Za-z0-9+/\-_]*$', s))
    except:
        return False

def decode_base64_url(s):
    """دیکد کردن base64 با پشتیبانی از فرمت URL-safe"""
    try:
        s = s.replace('-', '+').replace('_', '/')
        padding = 4 - (len(s) % 4)
        if padding != 4:
            s += '=' * padding
        return base64.b64decode(s)
    except:
        return None

def clean_config(config):
    """پاکسازی و نرمال‌سازی کانفیگ"""
    config = re.sub(r'[\U0001F300-\U0001F9FF]', '', config)
    config = re.sub(r'[\x00-\x08\x0B-\x1F\x7F-\x9F]', '', config)
    return config.strip()

def split_vmess_configs(text):
    """جداسازی کانفیگ‌های vmess چسبیده به هم"""
    configs = []
    pattern = r'vmess://[A-Za-z0-9+/\-_=]+'
    
    # پیدا کردن همه کانفیگ‌های vmess
    matches = re.finditer(pattern, text)
    
    for match in matches:
        config = match.group()
        # پاکسازی و اعتبارسنجی کانفیگ
        config = clean_config(config)
        if validate_vmess_config(config):
            configs.append(config)
    
    return configs

def validate_vmess_config(config):
    """اعتبارسنجی ساختار کانفیگ vmess"""
    try:
        if not config.startswith('vmess://'):
            return False
            
        base64_part = config[8:]  # حذف vmess://
        decoded = decode_base64_url(base64_part)
        if not decoded:
            return False
            
        # تلاش برای پارس کردن JSON
        import json
        config_data = json.loads(decoded)
        
        # بررسی فیلدهای ضروری
        required_fields = ['add', 'port', 'id', 'net']
        return all(field in config_data for field in required_fields)
        
    except Exception:
        return False

def validate_protocol_config(config, protocol):
    """اعتبارسنجی کانفیگ بر اساس پروتکل"""
    try:
        if protocol == 'vmess://':
            return validate_vmess_config(config)
            
        elif protocol in ['vless://', 'ss://']:
            base64_part = config[len(protocol):]
            # URLدیکد کردن برای کانفیگ‌های 
            decoded_url = unquote(base64_part)
            # بررسی اعتبار base64
            if is_base64(decoded_url) or is_base64(base64_part):
                return True
            # تلاش برای دیکد کردن
            if decode_base64_url(base64_part) or decode_base64_url(decoded_url):
                return True
                
        elif protocol == 'trojan://':
            # بررسی ساختار اصلی trojan
            if '@' in config and ':' in config:
                return True
                
        elif protocol == 'hysteria2://' or protocol == 'wireguard://':
            # بررسی ساده برای سایر پروتکل‌ها
            if '@' in config or ':' in config:
                return True
                
        return False
    except:
        return False

def extract_configs_from_text(text):
    """استخراج تمام کانفیگ‌ها از متن با پشتیبانی از کانفیگ‌های چسبیده"""
    configs = []
    current_position = 0
    
    while current_position < len(text):
        found_config = False
        
        for protocol in SUPPORTED_PROTOCOLS:
            protocol_index = text.find(protocol, current_position)
            
            if protocol_index != -1:
                if protocol == 'vmess://':
                    # استخراج و تفکیک کانفیگ‌های vmess چسبیده
                    vmess_configs = split_vmess_configs(text[protocol_index:])
                    if vmess_configs:
                        configs.extend(vmess_configs)
                        current_position = protocol_index + len(vmess_configs[0])
                        found_config = True
                        break
                else:
                    # پردازش سایر پروتکل‌ها
                    remaining_text = text[protocol_index:]
                    end_markers = [' ', '\n', '\r', '\t', '#', 'vmess://', 'vless://', 'ss://', 'trojan://', 'hysteria2://', 'wireguard://']
                    end_index = len(remaining_text)
                    
                    for marker in end_markers:
                        pos = remaining_text.find(marker, 1)  # شروع از بعد از اول پروتکل
                        if pos != -1 and pos < end_index:
                            end_index = pos
                    
                    config = remaining_text[:end_index].strip()
                    if validate_protocol_config(config, protocol):
                        configs.append(config)
                        current_position = protocol_index + end_index
                        found_config = True
                        break
        
        if not found_config:
            current_position += 1
    
    return configs

def fetch_configs_from_channel(channel_url):
    """دریافت کانفیگ‌ها از کانال با تلاش مجدد در صورت خطا"""
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
                
                # استخراج کانفیگ‌ها از متن پیام
                message_configs = extract_configs_from_text(message.text)
                configs.extend(message_configs)
            
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

def extract_date_from_message(message):
    """استخراج تاریخ پیام از HTML"""
    try:
        time_element = message.find_parent('div', class_='tgme_widget_message').find('time')
        if time_element and 'datetime' in time_element.attrs:
            return datetime.fromisoformat(time_element['datetime'].replace('Z', '+00:00'))
    except Exception:
        pass
    return None

def is_config_valid(config_text, date):
    """بررسی اعتبار تاریخ کانفیگ"""
    if not date:
        return True
    
    cutoff_date = datetime.now(date.tzinfo) - timedelta(days=MAX_CONFIG_AGE_DAYS)
    return date >= cutoff_date

def process_configs(configs):
    """حذف کانفیگ‌های تکراری و نامعتبر"""
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

def fetch_all_configs():
    """دریافت و پردازش تمام کانفیگ‌ها از همه کانال‌ها"""
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
    """ذخیره کانفیگ‌ها در فایل با دو خط فاصله بین هر کانفیگ"""
    try:
        os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write('\n\n'.join(configs))
        logger.info(f"Successfully saved {len(configs)} configs to {OUTPUT_FILE}")
    except Exception as e:
        logger.error(f"Error saving configs: {str(e)}")

def main():
    """تابع اصلی برنامه"""
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