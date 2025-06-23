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
import yaml
from urllib.parse import urlencode, quote, unquote

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
    @staticmethod
    def to_uri(proxy: Dict) -> Optional[str]:
        proxy_type = proxy.get("type")
        converters = {
            "vless": ClashConverter.to_vless,
            "vmess": ClashConverter.to_vmess,
            "ss": ClashConverter.to_ss,
            "trojan": ClashConverter.to_trojan,
            "ssr": ClashConverter.to_ssr,
            "hysteria2": ClashConverter.to_hysteria2,
            "tuic": ClashConverter.to_tuic,
            "wireguard": ClashConverter.to_wireguard,
            "anytls": ClashConverter.to_anytls,
        }
        if proxy_type in converters:
            try:
                return converters[proxy_type](proxy)
            except Exception:
                return None
        return None

    @staticmethod
    def to_vless(proxy: Dict) -> str:
        server, port, uuid = proxy.get("server", ""), proxy.get("port", ""), proxy.get("uuid", "")
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
        params = {k: v for k, v in params.items() if v}
        return f"vless://{uuid}@{server}:{port}?{urlencode(params)}#{name}"

    @staticmethod
    def to_vmess(proxy: Dict) -> str:
        name = proxy.get("name", "")
        vmess_json = {
            "v": "2", "ps": name, "add": proxy.get("server"), "port": proxy.get("port"), "id": proxy.get("uuid"),
            "aid": proxy.get("alterId", 0), "net": proxy.get("network"), "type": "none",
            "host": proxy.get("ws-opts", {}).get("headers", {}).get("Host"),
            "path": proxy.get("ws-opts", {}).get("path"), "tls": "tls" if proxy.get("tls") else "",
            "sni": proxy.get("servername"),
        }
        vmess_json = {k: v for k, v in vmess_json.items() if v}
        return f"vmess://{base64.b64encode(json.dumps(vmess_json, separators=(',', ':')).encode('utf-8')).decode('utf-8')}"

    @staticmethod
    def to_ss(proxy: Dict) -> str:
        server, port, password, cipher = proxy.get("server", ""), proxy.get("port", ""), proxy.get("password", ""), proxy.get("cipher", "")
        name = quote(proxy.get("name", ""))
        user_info = base64.b64encode(f"{cipher}:{password}".encode("utf-8")).decode("utf-8").rstrip("=")
        plugin_opts = ""
        if "plugin" in proxy:
            plugin_params = {
                "plugin": proxy["plugin"],
                "obfs": proxy.get("plugin-opts", {}).get("mode"),
                "obfs-host": proxy.get("plugin-opts", {}).get("host"),
            }
            plugin_params = {k: v for k, v in plugin_params.items() if v}
            plugin_opts = "&" + urlencode(plugin_params)
        return f"ss://{user_info}@{server}:{port}?{plugin_opts}#{name}"

    @staticmethod
    def to_trojan(proxy: Dict) -> str:
        server, port, password = proxy.get("server", ""), proxy.get("port", ""), quote(proxy.get("password", ""))
        name = quote(proxy.get("name", ""))
        params = {
            "sni": proxy.get("sni"), "type": proxy.get("network"),
            "path": proxy.get("ws-opts", {}).get("path"),
            "host": proxy.get("ws-opts", {}).get("headers", {}).get("Host"),
            "serviceName": proxy.get("grpc-opts", {}).get("grpc-service-name"),
        }
        params = {k: v for k, v in params.items() if v}
        return f"trojan://{password}@{server}:{port}?{urlencode(params)}#{name}"

    @staticmethod
    def to_hysteria2(proxy: dict) -> str:
        server, port, auth = proxy.get("server", ""), proxy.get("port", ""), proxy.get("password", "") or proxy.get("auth-str", "")
        name, sni = quote(proxy.get("name", "")), proxy.get("sni", "")
        return f"hysteria2://{auth}@{server}:{port}?sni={sni}#{name}"

    @staticmethod
    def to_tuic(proxy: dict) -> str:
        server, port, uuid, password = proxy.get("server", ""), proxy.get("port", ""), proxy.get("uuid", ""), quote(proxy.get("password", ""))
        name, sni, alpn = quote(proxy.get("name", "")), proxy.get("sni", ""), (proxy.get("alpn") or [""])[0]
        return f"tuic://{uuid}:{password}@{server}:{port}?sni={sni}&alpn={alpn}#{name}"

    @staticmethod
    def to_ssr(proxy: dict) -> str:
        password_b64 = base64.b64encode(str(proxy.get('password', '')).encode('utf-8')).decode('utf-8')
        parts = [proxy.get('server'), str(proxy.get('port')), proxy.get('protocol'), proxy.get('cipher'), proxy.get('obfs'), password_b64]
        main_part = ":".join(map(str, parts))
        params = {
            "obfsparam": base64.b64encode(str(proxy.get('obfs-param', '')).encode('utf-8')).decode('utf-8'),
            "protoparam": base64.b64encode(str(proxy.get('protocol-param', '')).encode('utf-8')).decode('utf-8'),
            "remarks": base64.b64encode(str(proxy.get('name', '')).encode('utf-8')).decode('utf-8')
        }
        query_string = urlencode({k: v for k, v in params.items() if v})
        return f"ssr://{base64.b64encode(f'{main_part}/?{query_string}'.encode('utf-8')).decode('utf-8')}"

    @staticmethod
    def to_wireguard(proxy: dict) -> str:
        private_key = quote(proxy.get('private-key', ''), safe='')
        server, port = proxy.get('server', ''), proxy.get('port', '')
        name = quote(proxy.get('name', ''))
        params = {'publicKey': proxy.get('public-key', ''), 'address': proxy.get('ip', ''), 'presharedKey': proxy.get('pre-shared-key', '')}
        params = {k: v for k, v in params.items() if v}
        return f"wireguard://{private_key}@{server}:{port}?{urlencode(params)}#{name}"

    @staticmethod
    def to_anytls(proxy: dict) -> str:
        password, server, port = quote(proxy.get('password', '')), proxy.get('server', ''), proxy.get('port', '')
        name = quote(proxy.get('name', ''))
        params = {'sni': proxy.get('sni'), 'fp': proxy.get('client-fingerprint'), 'insecure': 1 if proxy.get('skip-cert-verify') else 0}
        params = {k: v for k, v in params.items() if v is not None}
        return f"anytls://{password}@{server}:{port}?{urlencode(params)}#{name}"


class ConfigFetcher:
    def __init__(self, config: ProxyConfig):
        self.config = config
        self.validator = ConfigValidator()
        self.protocol_counts: Dict[str, int] = {p: 0 for p in config.SUPPORTED_PROTOCOLS}
        self.seen_configs: Set[str] = set()
        self.channel_protocol_counts: Dict[str, Dict[str, int]] = {}
        self.session = requests.Session()
        self.session.headers.update(config.HEADERS)

    def fetch_with_retry(self, url: str) -> Optional[requests.Response]:
        backoff = 1
        for attempt in range(self.config.MAX_RETRIES):
            try:
                response = self.session.get(url, timeout=self.config.REQUEST_TIMEOUT)
                response.raise_for_status()
                return response
            except requests.RequestException as e:
                if attempt == self.config.MAX_RETRIES - 1:
                    logger.error(f"Failed to fetch {url} after {self.config.MAX_RETRIES} attempts: {str(e)}")
                    return None
                wait_time = min(self.config.RETRY_DELAY * backoff, 60)
                logger.warning(f"Attempt {attempt + 1} for {url} failed, retrying in {wait_time}s: {str(e)}")
                time.sleep(wait_time)
                backoff *= 2
        return None

    def fetch_configs_from_source(self, channel: ChannelConfig) -> List[str]:
        configs: List[str] = []
        channel.metrics.total_configs = 0
        channel.metrics.valid_configs = 0
        channel.metrics.protocol_counts = {p: 0 for p in self.config.SUPPORTED_PROTOCOLS}
        start_time = time.time()
        response = self.fetch_with_retry(channel.url)
        if not response:
            self.config.update_channel_stats(channel, False)
            return configs
        response_time = time.time() - start_time
        content = response.text
        is_yaml = False
        try:
            if content.lstrip().startswith(('proxies:', 'proxy-groups:', 'rules:')):
                data = yaml.safe_load(content)
                if isinstance(data, dict) and 'proxies' in data:
                    is_yaml = True
                    clash_proxies = data.get('proxies', [])
                    for proxy in clash_proxies:
                        uri = ClashConverter.to_uri(proxy)
                        if uri:
                            configs.append(uri)
                    logger.info(f"Parsed {len(configs)} configs from Clash YAML: {channel.url}")
        except yaml.YAMLError:
            is_yaml = False
        except Exception as e:
            logger.error(f"Error parsing YAML from {channel.url}: {e}")
            is_yaml = False
        if not is_yaml:
            if channel.is_telegram:
                soup = BeautifulSoup(content, 'html.parser')
                messages = soup.find_all('div', class_='tgme_widget_message_text')
                for message in messages:
                    found_configs = self.validator.split_configs(message.get_text(separator='\n'))
                    configs.extend(found_configs)
            else:
                if self.validator.is_base64(content.strip()):
                    decoded_content = self.validator.decode_base64_text(content.strip())
                    if decoded_content:
                        content = decoded_content
                configs.extend(self.validator.split_configs(content))
        unique_configs = list(dict.fromkeys(configs))
        channel.metrics.total_configs = len(unique_configs)
        valid_configs = []
        for config_str in unique_configs:
            processed = self.process_config(config_str, channel)
            if processed:
                valid_configs.extend(processed)
        if len(valid_configs) >= self.config.MIN_CONFIGS_PER_CHANNEL:
            self.config.update_channel_stats(channel, True, response_time)
        else:
            self.config.update_channel_stats(channel, False, response_time)
        return valid_configs

    def process_config(self, config: str, channel: ChannelConfig) -> List[str]:
        processed_configs = []
        if config.startswith('hy2://'):
            config = self.validator.normalize_hysteria2_protocol(config)
        for protocol in self.config.SUPPORTED_PROTOCOLS:
            if config.startswith(protocol) and self.config.is_protocol_enabled(protocol):
                clean_config = self.validator.clean_config(config)
                if self.validator.validate_protocol_config(clean_config, protocol):
                    channel.metrics.valid_configs += 1
                    channel.metrics.protocol_counts[protocol] = channel.metrics.protocol_counts.get(protocol, 0) + 1
                    if clean_config not in self.seen_configs:
                        self.seen_configs.add(clean_config)
                        processed_configs.append(clean_config)
                        self.protocol_counts[protocol] = self.protocol_counts.get(protocol, 0) + 1
                break
        return processed_configs

    def extract_date_from_message(self, message) -> Optional[datetime]:
        try:
            time_element = message.find_parent('div', class_='tgme_widget_message').find('time')
            if time_element and 'datetime' in time_element.attrs:
                return datetime.fromisoformat(time_element['datetime'].replace('Z', '+00:00'))
        except:
            return None

    def is_config_valid(self, config_text: str, date: Optional[datetime]) -> bool:
        if not date:
            return True
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=self.config.MAX_CONFIG_AGE_DAYS)
        return date >= cutoff_date

    def balance_protocols(self, configs: List[str]) -> Dict[str, List[str]]:
        protocol_configs: Dict[str, List[str]] = {p: [] for p in self.config.SUPPORTED_PROTOCOLS}
        for config in configs:
            normalized_config = self.validator.normalize_hysteria2_protocol(config)
            for protocol in self.config.SUPPORTED_PROTOCOLS:
                if normalized_config.startswith(protocol):
                    protocol_configs[protocol].append(config)
                    break
        return protocol_configs

    def fetch_all_configs(self) -> Dict[str, List[str]]:
        all_configs: List[str] = []
        enabled_channels = self.config.get_enabled_channels()
        for idx, channel in enumerate(enabled_channels, 1):
            logger.info(f"Fetching from {channel.url} ({idx}/{len(enabled_channels)})")
            try:
                channel_configs = self.fetch_configs_from_source(channel)
                all_configs.extend(channel_configs)
            except Exception as e:
                logger.error(f"Failed to fetch or process {channel.url}: {e}")
            if idx < len(enabled_channels):
                time.sleep(2)
        unique_configs = sorted(list(dict.fromkeys(all_configs)))
        return self.balance_protocols(unique_configs)


def save_configs(categorized_configs: Dict[str, List[str]], config: ProxyConfig):
    try:
        output_dir = os.path.dirname(config.OUTPUT_FILE)
        os.makedirs(output_dir, exist_ok=True)
        all_configs_list = []
        logger.info("--- Starting to save per-protocol files (text and base64) ---")
        for protocol_scheme, configs_list in categorized_configs.items():
            if not configs_list:
                continue
            all_configs_list.extend(configs_list)
            protocol_name = protocol_scheme.replace("://", "")
            protocol_filename = os.path.join(output_dir, f"{protocol_name}_configs.txt")
            try:
                with open(protocol_filename, 'w', encoding='utf-8') as f:
                    f.write('\n\n'.join(configs_list))
                logger.info(f"-> SUCCESS: Saved {len(configs_list)} configs to {protocol_filename}")
            except Exception as e:
                logger.error(f"-> FAILED: Could not save protocol file {protocol_filename}: {e}")
            base64_filename = os.path.join(output_dir, f"{protocol_name}_configs_base64.txt")
            try:
                base64_content = base64.b64encode('\n'.join(configs_list).encode('utf-8')).decode('utf-8')
                with open(base64_filename, 'w', encoding='utf-8') as f:
                    f.write(base64_content)
                logger.info(f"-> SUCCESS: Saved Base64 version to {base64_filename}")
            except Exception as e:
                logger.error(f"-> FAILED: Could not save Base64 file {base64_filename}: {e}")
        if not all_configs_list:
            logger.warning("No total configs to save in the main file.")
            return
        sorted_all_configs = sorted(all_configs_list)
        header = """//profile-title: base64:8J+RvUFub255bW91cy3wnZWP
//profile-update-interval: 1
//subscription-userinfo: upload=0; download=0; total=10737418240000000; expire=2546249531
//support-url: https://t.me/BXAMbot
//profile-web-page-url: https://github.com/4n0nymou3

"""
        with open(config.OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write(header)
            f.write('\n\n'.join(sorted_all_configs))
        logger.info(f"-> SUCCESS: Saved {len(sorted_all_configs)} total configs to {config.OUTPUT_FILE}")
        main_base64_filename = os.path.join(output_dir, "proxy_configs_base64.txt")
        try:
            main_base64_content = base64.b64encode('\n'.join(sorted_all_configs).encode('utf-8')).decode('utf-8')
            with open(main_base64_filename, 'w', encoding='utf-8') as f:
                f.write(main_base64_content)
            logger.info(f"-> SUCCESS: Saved Base64 version of main config to {main_base64_filename}")
        except Exception as e:
            logger.error(f"-> FAILED: Could not save main Base64 file {main_base64_filename}: {e}")
    except Exception as e:
        logger.error(f"-> FAILED: A critical error occurred in save_configs function: {str(e)}")

def save_channel_stats(config: ProxyConfig):
    try:
        stats = {'timestamp': datetime.now(timezone.utc).isoformat(), 'channels': []}
        for channel in config.SOURCE_URLS:
            channel_stats = {
                'url': channel.url,
                'enabled': channel.enabled,
                'metrics': {
                    'total_configs': channel.metrics.total_configs,
                    'valid_configs': channel.metrics.valid_configs,
                    'unique_configs': channel.metrics.unique_configs,
                    'avg_response_time': round(channel.metrics.avg_response_time, 2),
                    'success_count': channel.metrics.success_count,
                    'fail_count': channel.metrics.fail_count,
                    'overall_score': round(channel.metrics.overall_score, 2),
                    'last_success': channel.metrics.last_success_time.isoformat() if channel.metrics.last_success_time else None,
                    'protocol_counts': channel.metrics.protocol_counts,
                },
            }
            stats['channels'].append(channel_stats)
        output_dir = os.path.dirname(config.STATS_FILE)
        os.makedirs(output_dir, exist_ok=True)
        with open(config.STATS_FILE, 'w', encoding='utf-8') as f:
            json.dump(stats, f, indent=2)
        logger.info(f"Channel statistics saved to {config.STATS_FILE}")
    except Exception as e:
        logger.error(f"Error saving channel statistics: {str(e)}")

def main():
    try:
        config = ProxyConfig()
        fetcher = ConfigFetcher(config)
        logger.info("Starting config fetching process...")
        categorized_configs = fetcher.fetch_all_configs()
        total_config_count = sum(len(v) for v in categorized_configs.values())
        if total_config_count > 0:
            save_configs(categorized_configs, config)
            logger.info(f"Successfully processed {total_config_count} configs.")
            for protocol, configs in categorized_configs.items():
                if len(configs) > 0:
                    logger.info(f"-> Found {len(configs)} {protocol.replace('://','')} configs")
        else:
            logger.warning("No valid configs found!")
        save_channel_stats(config)
        logger.info("Process finished.")
    except Exception as e:
        logger.error(f"Error in main execution: {str(e)}", exc_info=True)

if __name__ == '__main__':
    main()
