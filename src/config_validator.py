import re
import base64
import json
from typing import Optional, Tuple, List
from urllib.parse import unquote, urlparse

class ConfigValidator:
    @staticmethod
    def is_base64(s: str) -> bool:
        try:
            # Allow for URL-safe Base64 characters as well
            s = s.rstrip('=')
            return bool(re.match(r'^[A-Za-z0-9+/_-]*$', s))
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
    def decode_base64_text(text: str) -> Optional[str]:
        try:
            if ConfigValidator.is_base64(text):
                decoded = ConfigValidator.decode_base64_url(text)
                if decoded:
                    return decoded.decode('utf-8')
            return None
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
    def normalize_hysteria2_protocol(config: str) -> str:
        if config.startswith('hy2://'):
            return config.replace('hy2://', 'hysteria2://', 1)
        return config

    @staticmethod
    def is_vmess_config(config: str) -> bool:
        try:
            if not config.startswith('vmess://'):
                return False
            base64_part = config[8:]
            decoded = ConfigValidator.decode_base64_url(base64_part)
            if decoded:
                json.loads(decoded)
                return True
            return False
        except:
            return False

    @staticmethod
    def is_tuic_config(config: str) -> bool:
        try:
            if config.startswith('tuic://'):
                parsed = urlparse(config)
                return bool(parsed.netloc and ':' in parsed.netloc)
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
        protocols = ['vmess://', 'vless://', 'ss://', 'tuic://', 'ssr://']
        for protocol in protocols:
            if config.startswith(protocol):
                base64_part = config[len(protocol):]
                decoded_url = unquote(base64_part)
                if (ConfigValidator.is_base64(decoded_url) or 
                    ConfigValidator.is_base64(base64_part)):
                    return True, protocol[:-3]
        return False, ''

    @staticmethod
    def check_base64_content(text: str) -> Optional[str]:
        try:
            decoded_text = ConfigValidator.decode_base64_text(text)
            if decoded_text:
                protocols = ['vmess://', 'vless://', 'ss://', 'trojan://', 'hysteria2://', 'hy2://', 
                             'wireguard://', 'tuic://', 'ssconf://', 'ssr://', 'hysteria://', 'snell://',
                             'ssh://', 'mieru://', 'anytls://', 'warp://', 'juicity://'] # <-- Added juicity
                for protocol in protocols:
                    if protocol in decoded_text:
                        return decoded_text
            return None
        except:
            return None

    @staticmethod
    def split_configs(text: str) -> List[str]:
        all_protocols = [
            'vmess://', 'vless://', 'ss://', 'trojan://', 'hysteria2://', 'hy2://', 
            'wireguard://', 'tuic://', 'ssconf://', 'ssr://', 'hysteria://', 'snell://',
            'ssh://', 'mieru://', 'anytls://', 'warp://', 'juicity://' # <-- Added juicity
        ]
        
        configs = []
        potential_configs = re.split(r'[\s\n]+', text)

        for p_config in potential_configs:
            p_config = p_config.strip()
            if not p_config:
                continue

            decoded_content = ConfigValidator.check_base64_content(p_config)
            if decoded_content:
                configs.extend(ConfigValidator.split_configs(decoded_content))
                continue

            for protocol in all_protocols:
                if p_config.lower().startswith(protocol):
                    if ConfigValidator.is_valid_config(p_config):
                        clean_conf = ConfigValidator.clean_config(p_config)
                        if clean_conf.startswith("vmess://"):
                            clean_conf = ConfigValidator.clean_vmess_config(clean_conf)
                        elif clean_conf.startswith("hy2://"):
                            clean_conf = ConfigValidator.normalize_hysteria2_protocol(clean_conf)
                        configs.append(clean_conf)
                    break
        
        seen = set()
        return [x for x in configs if not (x in seen or seen.add(x))]


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

        protocols = [
            'vmess://', 'vless://', 'ss://', 'trojan://', 'hysteria2://', 'hy2://', 
            'wireguard://', 'tuic://', 'ssconf://', 'ssr://', 'hysteria://', 'snell://',
            'ssh://', 'mieru://', 'anytls://', 'warp://', 'juicity://' # <-- Added juicity
        ]
        return any(config.startswith(p) for p in protocols)

    @classmethod
    def validate_protocol_config(cls, config: str, protocol: str) -> bool:
        try:
            if protocol in ['vmess://', 'vless://', 'ss://', 'tuic://', 'ssr://']:
                if protocol == 'vmess://':
                    return cls.is_vmess_config(config)
                if protocol == 'tuic://':
                    return cls.is_tuic_config(config)
                
                base64_part = config[len(protocol):]
                if not base64_part: return False
                
                decoded_url = unquote(base64_part)
                return cls.is_base64(decoded_url) or cls.is_base64(base64_part)

            elif protocol in ['trojan://', 'hysteria2://', 'hy2://', 'wireguard://', 
                              'hysteria://', 'snell://', 'ssh://', 'anytls://', 'mieru://', 'warp://',
                              'juicity://']: # <-- Added juicity
                if protocol == 'warp://':
                    return True

                parsed = urlparse(config)
                if not parsed.netloc:
                    return False
                # These protocols require user info (e.g., password@host)
                if protocol in ['trojan://', 'hysteria://', 'ssh://', 'snell://', 'anytls://', 'juicity://']:
                    return '@' in parsed.netloc
                return True

            elif protocol == 'ssconf://':
                return True

            return False
        except:
            return False
