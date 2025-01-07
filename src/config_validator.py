import re
import base64
import json
from typing import Optional, Tuple, List
from urllib.parse import unquote, urlparse
import requests

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
                json.loads(decoded)
                return True
            return False
        except:
            return False

    @staticmethod
    def fetch_ss_from_ssconf(ssconf_url: str) -> Optional[str]:
        try:
            https_url = ssconf_url.replace("ssconf://", "https://")
            response = requests.get(https_url, timeout=10)
            response.raise_for_status()
            content = response.text.strip()
            if content.startswith("ss://"):
                return content
            return None
        except requests.exceptions.RequestException:
            return None

    @staticmethod
    def is_valid_config(config: str) -> bool:
        if not config:
            return False
        protocols = ['vmess://', 'vless://', 'ss://', 'trojan://', 'hysteria2://', 'wireguard://', 'tuic://', 'ssconf://']
        return any(config.startswith(p) for p in protocols)

    @classmethod
    def validate_protocol_config(cls, config: str, protocol: str) -> bool:
        try:
            if protocol == "ssconf://":
                ss_config = cls.fetch_ss_from_ssconf(config)
                return ss_config is not None
            elif protocol in ['vmess://', 'vless://', 'ss://', 'tuic://']:
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