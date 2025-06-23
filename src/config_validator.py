import re
import base64
import json
import logging
from typing import Optional, Tuple, List
from urllib.parse import unquote, urlparse

logger = logging.getLogger(__name__)

class ConfigValidator:
    @staticmethod
    def is_base64(s: str) -> bool:
        try:
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
    def check_base64_content(text: str) -> Optional[str]:
        try:
            decoded_text = ConfigValidator.decode_base64_text(text)
            if decoded_text:
                protocols = [
                    'vmess://', 'vless://', 'ss://', 'trojan://', 'hysteria2://', 'hy2://',
                    'wireguard://', 'tuic://', 'ssconf://', 'ssr://', 'hysteria://', 'snell://',
                    'ssh://', 'mieru://', 'anytls://', 'warp://', 'juicity://'
                ]
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
            'ssh://', 'mieru://', 'anytls://', 'warp://', 'juicity://'
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
            
            is_valid_protocol_start = False
            for protocol in all_protocols:
                if p_config.lower().startswith(protocol):
                    is_valid_protocol_start = True
                    break
            
            if is_valid_protocol_start:
                clean_conf = ConfigValidator.clean_config(p_config)
                configs.append(clean_conf)

        seen = set()
        return [x for x in configs if not (x in seen or seen.add(x))]

    @staticmethod
    def clean_config(config: str) -> str:
        config = re.sub(r'[\U0001F300-\U0001F9FF]', '', config)
        config = re.sub(r'[\x00-\x08\x0B-\x1F\x7F-\x9F]', '', config)
        config = re.sub(r'[^\S\r\n]+', ' ', config)
        return config.strip()

    @classmethod
    def validate_protocol_config(cls, config: str, protocol: str) -> bool:
        """
        REWRITTEN: A more flexible and robust validation logic.
        """
        is_valid = False
        try:
            parsed_uri = urlparse(config)
            
            # Rule 1: Protocols that are almost always Base64
            if protocol in ['vmess://', 'ssr://']:
                return cls.is_base64(config[len(protocol):])

            # Rule 2: Protocols that can be URL-based or Base64-based
            # A valid URL structure is the primary check.
            if not parsed_uri.scheme or not (parsed_uri.hostname or '@' in parsed_uri.netloc):
                 # If it doesn't look like a URL, maybe it's Base64? (for ss://)
                 if protocol == 'ss://' and cls.is_base64(config[len(protocol):]):
                     return True
                 is_valid = False
            else:
                is_valid = True

        except Exception:
            is_valid = False

        if not is_valid:
            logger.debug(f"[REJECTED] Config failed validation for protocol {protocol}: {config[:80]}...")
        
        return is_valid
