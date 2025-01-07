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
    def is_vmess_config(config: str) -> bool:
        try:
            if not config.startswith('vmess://'):
                return False
            
            base64_part = config[8:]
            if '=' in base64_part:
                base64_part = base64_part.split('=')[0] + '='
            elif '==' in base64_part:
                base64_part = base64_part.split('==')[0] + '=='
                
            decoded = ConfigValidator.decode_base64_url(base64_part)
            if decoded:
                json.loads(decoded)
                return True
            return False
        except:
            return False

    @staticmethod
    def is_base64_config(config: str) -> Tuple[bool, str]:
        protocols = ['vmess://', 'vless://', 'ss://']
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
        protocols = ['vmess://', 'vless://', 'ss://', 'trojan://', 'hysteria2://', 'wireguard://']
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
                        if current_config.startswith('vmess://'):
                            if '=' in current_config:
                                current_config = current_config.split('=')[0] + '='
                            elif '==' in current_config:
                                current_config = current_config.split('==')[0] + '=='
                        configs.append(current_config)
                
                current_pos = next_config_start
                next_protocol_pos = text_length
                
                for protocol in protocols:
                    pos = text.find(protocol, next_config_start + len(matching_protocol))
                    if pos != -1 and pos < next_protocol_pos:
                        next_protocol_pos = pos
                
                current_config = text[next_config_start:next_protocol_pos].strip()
                if ConfigValidator.is_valid_config(current_config):
                    if current_config.startswith('vmess://'):
                        if '=' in current_config:
                            current_config = current_config.split('=')[0] + '='
                        elif '==' in current_config:
                            current_config = current_config.split('==')[0] + '=='
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
        if config.startswith('vmess://'):
            if '=' in config:
                config = config.split('=')[0] + '='
            elif '==' in config:
                config = config.split('==')[0] + '=='
        config = config.strip()
        return config

    @staticmethod
    def is_valid_config(config: str) -> bool:
        if not config:
            return False
            
        protocols = ['vmess://', 'vless://', 'ss://', 'trojan://', 'hysteria2://', 'wireguard://']
        return any(config.startswith(p) for p in protocols)

    @classmethod
    def validate_protocol_config(cls, config: str, protocol: str) -> bool:
        try:
            if protocol in ['vmess://', 'vless://', 'ss://']:
                if protocol == 'vmess://':
                    return cls.is_vmess_config(config)
                base64_part = config[len(protocol):]
                decoded_url = unquote(base64_part)
                if cls.is_base64(decoded_url) or cls.is_base64(base64_part):
                    return True
                if cls.decode_base64_url(base64_part) or cls.decode_base64_url(decoded_url):
                    return True
            elif protocol in ['trojan://', 'hysteria2://', 'wireguard://']:
                parsed = urlparse(config)
                return bool(parsed.netloc and '@' in parsed.netloc)
            return False
        except:
            return False