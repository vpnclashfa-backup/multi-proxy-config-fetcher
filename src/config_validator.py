import re
import base64
import json
from typing import Optional, Tuple, List
from urllib.parse import unquote, urlparse

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
    def clean_vmess_config(config: str) -> str:
        if "vmess://" in config:
            base64_part = config[8:]
            base64_clean = re.split(r'[^A-Za-z0-9+/=_-]', base64_part)[0]
            return f"vmess://{base64_clean}"
        return config

    @staticmethod
    def is_vmess_config(config: str) -> bool:
        try:
            if not config.startswith('vmess://'):
                return False
            base64_part = config[8:]
            decoded = ConfigValidator.decode_base64_url(base64_part)
            if decoded:
                if isinstance(decoded, bytes):
                    decoded = decoded.decode('utf-8')
                json_data = json.loads(decoded)
                return all(key in json_data for key in ['add', 'port', 'id'])
            return False
        except:
            return False

    @staticmethod
    def is_tuic_config(config: str) -> bool:
        try:
            if config.startswith('tuic://'):
                parsed = urlparse(config)
                return bool(parsed.netloc and ':' in parsed.netloc and parsed.query)
            return False
        except:
            return False

    @staticmethod
    def convert_ssconf_to_https(url: str) -> str:
        if url.startswith('ssconf://'):
            return url.replace('ssconf://', 'https://', 1)
        return url

    @staticmethod
    def is_base64_config(config: str) -> Tuple[bool, str]:
        protocols = ['vmess://', 'vless://', 'ss://', 'tuic://']
        for protocol in protocols:
            if config.startswith(protocol):
                base64_part = config[len(protocol):]
                decoded_url = unquote(base64_part)
                if (ConfigValidator.is_base64(decoded_url) or 
                    ConfigValidator.is_base64(base64_part)):
                    return True, protocol[:-3]
        return False, ''

    @staticmethod
    def split_configs(text: str) -> List[str]:
        protocols = ['vmess://', 'vless://', 'ss://', 'trojan://', 'hysteria2://', 'wireguard://', 'tuic://', 'ssconf://']
        configs = []
        current_pos = 0
        text_length = len(text)
        
        while current_pos < text_length:
            next_config_start = text_length
            matching_protocol = None
            
            for protocol in protocols:
                protocol_pos = text.find(protocol, current_pos)
                if protocol_pos != -1 and protocol_pos < next_config_start:
                    next_config_start = protocol_pos
                    matching_protocol = protocol
            
            if matching_protocol:
                if current_pos < next_config_start and configs:
                    current_config = text[current_pos:next_config_start].strip()
                    if ConfigValidator.is_valid_config(current_config):
                        configs.append(current_config)
                
                current_pos = next_config_start
                next_protocol_pos = text_length
                
                for protocol in protocols:
                    pos = text.find(protocol, next_config_start + len(matching_protocol))
                    if pos != -1 and pos < next_protocol_pos:
                        next_protocol_pos = pos
                
                current_config = text[next_config_start:next_protocol_pos].strip()
                if matching_protocol == "vmess://":
                    current_config = ConfigValidator.clean_vmess_config(current_config)
                if ConfigValidator.is_valid_config(current_config):
                    configs.append(current_config)
                
                current_pos = next_protocol_pos
            else:
                break
                
        return configs

    @staticmethod
    def clean_config(config: str) -> str:
        config = re.sub(r'[\U0001F300-\U0001F9FF]', '', config)
        config = re.sub(r'[\x00-\x08\x0B-\x1F\x7F-\x9F]', '', config)
        config = re.sub(r'[^\S\r\n]+', ' ', config)
        config = config.strip()
        return config

    @staticmethod
    def is_valid_config(config: str) -> bool:
        if not config:
            return False
            
        protocols = ['vmess://', 'vless://', 'ss://', 'trojan://', 'hysteria2://', 'wireguard://', 'tuic://', 'ssconf://']
        valid = any(config.startswith(p) for p in protocols)
        
        if valid:
            clean_config = ConfigValidator.clean_config(config)
            if clean_config != config:
                return False
                
            if config.startswith('vmess://'):
                return ConfigValidator.is_vmess_config(config)
            elif config.startswith('tuic://'):
                return ConfigValidator.is_tuic_config(config)
                
        return valid

    @staticmethod
    def validate_protocol_config(config: str, protocol: str) -> bool:
        try:
            if protocol in ['vmess://', 'vless://', 'ss://', 'tuic://']:
                if protocol == 'vmess://':
                    return ConfigValidator.is_vmess_config(config)
                if protocol == 'tuic://':
                    return ConfigValidator.is_tuic_config(config)
                    
                base64_part = config[len(protocol):]
                decoded_url = unquote(base64_part)
                
                if ConfigValidator.is_base64(decoded_url) or ConfigValidator.is_base64(base64_part):
                    return True
                    
                decoded = ConfigValidator.decode_base64_url(base64_part)
                if decoded:
                    try:
                        if isinstance(decoded, bytes):
                            decoded = decoded.decode('utf-8')
                        if '"' in decoded or '{' in decoded:
                            json.loads(decoded)
                        return True
                    except:
                        pass
                        
                return False
                
            elif protocol in ['trojan://', 'hysteria2://', 'wireguard://']:
                parsed = urlparse(config)
                return bool(parsed.netloc and ('@' in parsed.netloc or ':' in parsed.netloc))
                
            elif protocol == 'ssconf://':
                return True
                
            return False
            
        except:
            return False