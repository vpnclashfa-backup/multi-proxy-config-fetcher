import re
import os
import time
import json
import logging
import base64
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional, Set
import requests
from bs4 import BeautifulSoup
import yaml # <-- Import the new library
from urllib.parse import urlencode, quote

# These imports should already be correct from your existing setup
from config import ProxyConfig, ChannelConfig
from config_validator import ConfigValidator

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('proxy_fetcher.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class ClashConverter:
    """A helper class to convert Clash proxy definitions (dict) to URI links."""

    @staticmethod
    def to_uri(proxy: Dict) -> Optional[str]:
        """Master converter that dispatches to the correct method based on proxy type."""
        proxy_type = proxy.get("type")
        
        converters = {
            "vless": ClashConverter.to_vless,
            "vmess": ClashConverter.to_vmess,
            "ss": ClashConverter.to_ss,
            "trojan": ClashConverter.to_trojan,
            "ssr": ClashConverter.to_ssr,
            "hysteria2": ClashConverter.to_hysteria2,
            "tuic": ClashConverter.to_tuic,
        }

        if proxy_type in converters:
            try:
                return converters[proxy_type](proxy)
            except Exception as e:
                # logger.warning(f"Could not convert Clash proxy '{proxy.get('name')}': {e}")
                return None
        return None

    @staticmethod
    def to_vless(proxy: Dict) -> str:
        server = proxy.get("server", "")
        port = proxy.get("port", "")
        uuid = proxy.get("uuid", "")
        name = quote(proxy.get("name", ""))
        
        params = {
            "type": proxy.get("network"),
            "security": "tls" if proxy.get("tls") else "reality" if proxy.get("reality-opts") else "none",
            "sni": proxy.get("servername"),
            "flow": proxy.get("flow"),
            "path": proxy.get("ws-opts", {}).get("path"),
            "host": proxy.get("ws-opts", {}).get("headers", {}).get("Host"),
            "serviceName": proxy.get("grpc-opts", {}).get("grpc-service-name"),
            "pbk": proxy.get("reality-opts", {}).get("public-key"),
            "sid": proxy.get("reality-opts", {}).get("short-id"),
        }
        
        # Filter out None values
        params = {k: v for k, v in params.items() if v}
        query_string = urlencode(params)
        
        return f"vless://{uuid}@{server}:{port}?{query_string}#{name}"

    @staticmethod
    def to_vmess(proxy: Dict) -> str:
        name = proxy.get("name", "")
        # Create the JSON part for VMess
        vmess_json = {
            "v": "2",
            "ps": name,
            "add": proxy.get("server"),
            "port": proxy.get("port"),
            "id": proxy.get("uuid"),
            "aid": proxy.get("alterId", 0),
            "net": proxy.get("network"),
            "type": "none", # http header type
            "host": proxy.get("ws-opts", {}).get("headers", {}).get("Host"),
            "path": proxy.get("ws-opts", {}).get("path"),
            "tls": "tls" if proxy.get("tls") else "",
            "sni": proxy.get("servername"),
        }
        # Filter out None/empty values
        vmess_json = {k: v for k, v in vmess_json.items() if v}
        
        encoded_json = base64.b64encode(json.dumps(vmess_json).encode("utf-8")).decode("utf-8")
        return f"vmess://{encoded_json}"

    @staticmethod
    def to_ss(proxy: Dict) -> str:
        server = proxy.get("server", "")
        port = proxy.get("port", "")
        password = proxy.get("password", "")
        cipher = proxy.get("cipher", "")
        name = quote(proxy.get("name", ""))
        
        # Base64 encode 'cipher:password'
        user_info = base64.b64encode(f"{cipher}:{password}".encode("utf-8")).decode("utf-8").rstrip("=")
        
        plugin_opts = ""
        if "plugin" in proxy:
            plugin_params = {
                "plugin": proxy["plugin"],
                "obfs": proxy.get("plugin-opts", {}).get("mode"),
                "obfs-host": proxy.get("plugin-opts", {}).get("host"),
            }
            # Filter and encode plugin options
            plugin_params = {k: v for k, v in plugin_params.items() if v}
            plugin_opts = "&" + urlencode(plugin_params)

        return f"ss://{user_info}@{server}:{port}{plugin_opts}#{name}"

    @staticmethod
    def to_trojan(proxy: Dict) -> str:
        server = proxy.get("server", "")
        port = proxy.get("port", "")
        password = quote(proxy.get("password", ""))
        name = quote(proxy.get("name", ""))
        
        params = {
            "sni": proxy.get("sni"),
            "type": proxy.get("network"),
            "path": proxy.get("ws-opts", {}).get("path"),
            "host": proxy.get("ws-opts", {}).get("headers", {}).get("Host"),
            "serviceName": proxy.get("grpc-opts", {}).get("grpc-service-name"),
        }
        
        params = {k: v for k, v in params.items() if v}
        query_string = urlencode(params)
        
        return f"trojan://{password}@{server}:{port}?{query_string}#{name}"
    
    # Add other converters for ssr, hysteria2, etc. following the same pattern
    @staticmethod
    def to_hysteria2(proxy: dict) -> str:
        server = proxy.get("server", "")
        port = proxy.get("port", "")
        auth = proxy.get("password", "")
        name = quote(proxy.get("name", ""))
        sni = proxy.get("sni", "")

        return f"hysteria2://{auth}@{server}:{port}?sni={sni}#{name}"

    @staticmethod
    def to_tuic(proxy: dict) -> str:
        server = proxy.get("server", "")
        port = proxy.get("port", "")
        uuid = proxy.get("uuid", "")
        password = quote(proxy.get("password", ""))
        name = quote(proxy.get("name", ""))
        sni = proxy.get("sni", "")
        alpn = proxy.get("alpn", [""])[0]

        return f"tuic://{uuid}:{password}@{server}:{port}?sni={sni}&alpn={alpn}#{name}"
    
    @staticmethod
    def to_ssr(proxy: dict) -> str:
        # ssr://server:port:proto:method:obfs:password_base64/?obfsparam=obfsparam_base64&protoparam=protoparam_base64&remarks=remarks_base64&group=group_base64
        # This is a complex conversion and might need more specific examples
        # For now, creating a placeholder
        return "" # Placeholder, needs full implementation


class ConfigFetcher:
    def __init__(self, config: ProxyConfig):
        self.config = config
        self.validator = ConfigValidator()
        self.session = requests.Session()
        self.session.headers.update(config.HEADERS)
        self.seen_configs: Set[str] = set()

    # ... (fetch_with_retry, fetch_ssconf_configs etc. remain unchanged) ...
    def fetch_with_retry(self, url: str) -> Optional[requests.Response]:
        # ... (code is unchanged) ...
        pass
    
    def process_config(self, config: str, channel: ChannelConfig) -> List[str]:
        # ... (code is unchanged) ...
        pass
        
    def extract_date_from_message(self, message) -> Optional[datetime]:
        # ... (code is unchanged) ...
        pass

    def is_config_valid(self, config_text: str, date: Optional[datetime]) -> bool:
        # ... (code is unchanged) ...
        pass

    def fetch_configs_from_source(self, channel: ChannelConfig) -> List[str]:
        """
        MODIFIED: This function now detects and parses Clash YAML subscriptions.
        """
        configs: List[str] = []
        channel.metrics.total_configs = 0
        channel.metrics.valid_configs = 0
        
        start_time = time.time()
        response = self.fetch_with_retry(channel.url)
        if not response:
            self.config.update_channel_stats(channel, False)
            return configs
        
        response_time = time.time() - start_time
        content = response.text

        # --- YAML Detection and Parsing Logic ---
        is_yaml = False
        try:
            # A simple heuristic: if it starts with common clash keys, treat as YAML
            if content.lstrip().startswith(('proxies:', 'proxy-groups:', 'rules:')):
                data = yaml.safe_load(content)
                if isinstance(data, dict) and 'proxies' in data:
                    is_yaml = True
                    clash_proxies = data.get('proxies', [])
                    channel.metrics.total_configs = len(clash_proxies)
                    for proxy in clash_proxies:
                        uri = ClashConverter.to_uri(proxy)
                        if uri:
                            configs.append(uri)
                    logger.info(f"Parsed {len(configs)} configs from Clash YAML source: {channel.url}")
        except yaml.YAMLError:
            is_yaml = False # It's not valid YAML, treat as plain text
        except Exception as e:
            logger.error(f"Error parsing potential YAML from {channel.url}: {e}")
            is_yaml = False

        # --- Plain Text / Fallback Logic ---
        if not is_yaml:
            if channel.is_telegram:
                # ... (Telegram parsing logic remains unchanged) ...
                soup = BeautifulSoup(response.text, 'html.parser')
                messages = soup.find_all('div', class_='tgme_widget_message_text')
                for message in messages:
                     # Add configs from message.text using validator
                    found_configs = self.validator.split_configs(message.get_text())
                    configs.extend(found_configs)
            else:
                 # Standard text or base64 subscription
                if self.validator.is_base64(content):
                    decoded_content = self.validator.decode_base64_text(content)
                    if decoded_content:
                        content = decoded_content
                
                found_configs = self.validator.split_configs(content)
                configs.extend(found_configs)

            channel.metrics.total_configs = len(configs)
        
        # --- Final Processing ---
        unique_configs = list(set(configs))
        valid_configs = []
        for config_str in unique_configs:
            # Use the existing process_config to validate and count
            processed = self.process_config(config_str, channel)
            if processed:
                valid_configs.extend(processed)

        if len(valid_configs) >= self.config.MIN_CONFIGS_PER_CHANNEL:
            self.config.update_channel_stats(channel, True, response_time)
        else:
            self.config.update_channel_stats(channel, False)
            logger.warning(f"Not enough valid configs found in {channel.url}: {len(valid_configs)} configs")

        return valid_configs
    
    # ... The rest of the ConfigFetcher class (balance_protocols, fetch_all_configs) ...
    # ... and module-level functions (save_configs, save_channel_stats, main) remain the same as the last step ...
    def balance_protocols(self, configs: List[str]) -> Dict[str, List[str]]:
        # ... (code is unchanged) ...
        pass

    def fetch_all_configs(self) -> Dict[str, List[str]]:
        # ... (code is unchanged) ...
        pass

def save_configs(categorized_configs: Dict[str, List[str]], config: ProxyConfig):
    # ... (code is unchanged) ...
    pass

def save_channel_stats(config: ProxyConfig):
    # ... (code is unchanged) ...
    pass

def main():
    # ... (code is unchanged) ...
    pass
