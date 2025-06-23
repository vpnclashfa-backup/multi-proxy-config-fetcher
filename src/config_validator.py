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
        # Updated to include ssr
        protocols = ['vmess://', 'vless://', 'ss://', 'tuic://', 'ssr://']
        for protocol in protocols:
            if config.startswith(protocol):
                base64_part = config[len(protocol):]
                decoded_url = unquote(base64_part)
                if (ConfigValidator.is_base64(decoded_url) or 
                    ConfigValidator.is_base64(base64_part)):
                    return True, protocol[:-3] # Return protocol name without '://'
        return False, ''

    @staticmethod
    def check_base64_content(text: str) -> Optional[str]:
        try:
            decoded_text = ConfigValidator.decode_base64_text(text)
            if decoded_text:
                # Add all new protocols here
                protocols = ['vmess://', 'vless://', 'ss://', 'trojan://', 'hysteria2://', 'hy2://', 
                             'wireguard://', 'tuic://', 'ssconf://', 'ssr://', 'hysteria://', 'snell://',
                             'ssh://', 'mieru://', 'anytls://', 'warp://']
                for protocol in protocols:
                    if protocol in decoded_text:
                        return decoded_text
            return None
        except:
            return None

    @staticmethod
    def split_configs(text: str) -> List[str]:
        # Define the list of all supported protocols for splitting
        all_protocols = [
            'vmess://', 'vless://', 'ss://', 'trojan://', 'hysteria2://', 'hy2://', 
            'wireguard://', 'tuic://', 'ssconf://', 'ssr://', 'hysteria://', 'snell://',
            'ssh://', 'mieru://', 'anytls://', 'warp://'
        ]
        
        configs = []
        # First, try to split by common delimiters like newline or whitespace
        potential_configs = re.split(r'[\s\n]+', text)

        for p_config in potential_configs:
            p_config = p_config.strip()
            if not p_config:
                continue

            # Check if the potential config is a Base64 encoded subscription
            decoded_content = ConfigValidator.check_base64_content(p_config)
            if decoded_content:
                # If it is, recursively call split_configs on the decoded content
                configs.extend(ConfigValidator.split_configs(decoded_content))
                continue

            # Check if the line starts with any of the known protocols
            for protocol in all_protocols:
                if p_config.lower().startswith(protocol):
                    if ConfigValidator.is_valid_config(p_config):
                        clean_conf = ConfigValidator.clean_config(p_config)
                        # Specific normalizations
                        if clean_conf.startswith("vmess://"):
                            clean_conf = ConfigValidator.clean_vmess_config(clean_conf)
                        elif clean_conf.startswith("hy2://"):
                            clean_conf = ConfigValidator.normalize_hysteria2_protocol(clean_conf)
                        configs.append(clean_conf)
                    # Break after finding a match to avoid multiple additions of the same line
                    break
        
        # Remove duplicates while preserving order
        seen = set()
        return [x for x in configs if not (x in seen or seen.add(x))]


    @staticmethod
    def clean_config(config: str) -> str:
        # Removes emojis and other non-essential characters from the config string
        config = re.sub(r'[\U0001F300-\U0001F9FF]', '', config)
        config = re.sub(r'[\x00-\x08\x0B-\x1F\x7F-\x9F]', '', config)
        config = re.sub(r'[^\S\r\n]+', ' ', config)
        config = config.strip()
        return config

    @staticmethod
    def is_valid_config(config: str) -> bool:
        if not config:
            return False

        # Add all new protocols to this list
        protocols = [
            'vmess://', 'vless://', 'ss://', 'trojan://', 'hysteria2://', 'hy2://', 
            'wireguard://', 'tuic://', 'ssconf://', 'ssr://', 'hysteria://', 'snell://',
            'ssh://', 'mieru://', 'anytls://', 'warp://'
        ]
        return any(config.startswith(p) for p in protocols)

    @classmethod
    def validate_protocol_config(cls, config: str, protocol: str) -> bool:
        try:
            # Original protocols with Base64 content
            if protocol in ['vmess://', 'vless://', 'ss://', 'tuic://', 'ssr://']:
                if protocol == 'vmess://':
                    return cls.is_vmess_config(config)
                if protocol == 'tuic://':
                    return cls.is_tuic_config(config)
                
                # General Base64 check for vless, ss, ssr
                base64_part = config[len(protocol):]
                if not base64_part: return False
                
                decoded_url = unquote(base64_part)
                return cls.is_base64(decoded_url) or cls.is_base64(base64_part)

            # Original protocols with URL-like structure
            elif protocol in ['trojan://', 'hysteria2://', 'hy2://', 'wireguard://', 
                              'hysteria://', 'snell://', 'ssh://', 'anytls://', 'mieru://', 'warp://']:
                # For warp, host can be 'auto', so netloc might be empty
                if protocol == 'warp://':
                    return True # Assume warp links are valid if they start with the scheme

                parsed = urlparse(config)
                # Most URL-based protocols require a host/port part (netloc)
                if not parsed.netloc:
                    return False
                # Protocols like trojan, ssh, hysteria often require user info part
                if protocol in ['trojan://', 'hysteria://', 'ssh://', 'snell://', 'anytls://']:
                    return '@' in parsed.netloc
                return True

            elif protocol == 'ssconf://':
                return True

            return False
        except:
            return False
