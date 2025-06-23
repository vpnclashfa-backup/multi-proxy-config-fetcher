import re
import os
import time
import json
import logging
import base64
import socket
import random
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional, Set, Union
import requests
from bs4 import BeautifulSoup
import yaml
from urllib.parse import urlencode, quote, unquote, urlparse, urlunparse

# Import custom modules
# Assuming config.py and config_validator.py exist in the same directory (src/)
try:
    from config import ProxyConfig, ChannelConfig
    from config_validator import ConfigValidator
except ImportError:
    # Fallback for standalone execution or testing without full project structure
    # Define dummy classes or raise an error if critical for functionality
    print("Error: Required modules (config.py, config_validator.py) not found.")
    print("Please ensure these files are in the same directory or accessible via PYTHONPATH.")
    # For now, we will exit or define minimal dummy classes to allow syntax check
    # In a real scenario, this would likely be an unrecoverable error.
    class ProxyConfig:
        def __init__(self):
            self.MAX_RETRIES = 3
            self.RETRY_DELAY = 5
            self.REQUEST_TIMEOUT = 30
            self.MIN_CONFIGS_PER_CHANNEL = 1
            self.MAX_CONFIG_AGE_DAYS = 7
            self.use_maximum_power = False
            self.specific_config_count = 50
            self.OUTPUT_FILE = 'configs/proxy_configs.txt'
            self.STATS_FILE = 'configs/channel_stats.json'
            self.HEADERS = {'User-Agent': 'Mozilla/5.0'}
            self.SOURCE_URLS = []
            self.SUPPORTED_PROTOCOLS = {
                "vless://": {"priority": 2, "aliases": [], "enabled": True},
                "vmess://": {"priority": 1, "aliases": [], "enabled": True},
                "ss://": {"priority": 2, "aliases": [], "enabled": True},
                "trojan://": {"priority": 2, "aliases": [], "enabled": True},
                "hysteria2://": {"priority": 2, "aliases": ["hy2://"], "enabled": True},
                "tuic://": {"priority": 1, "aliases": [], "enabled": True},
                "wireguard://": {"priority": 1, "aliases": [], "enabled": False}, # Default to False if not specified
                "ssr://": {"priority": 2, "aliases": [], "enabled": True},
                "hysteria://": {"priority": 2, "aliases": [], "enabled": True},
                "snell://": {"priority": 2, "aliases": [], "enabled": True},
                "ssh://": {"priority": 1, "aliases": [], "enabled": True},
                "mieru://": {"priority": 2, "aliases": [], "enabled": True},
                "anytls://": {"priority": 2, "aliases": [], "enabled": True},
                "warp://": {"priority": 1, "aliases": [], "enabled": True},
                "juicity://": {"priority": 2, "aliases": [], "enabled": True},
            }
        def get_enabled_channels(self): return []
        def is_protocol_enabled(self, protocol): return self.SUPPORTED_PROTOCOLS.get(protocol, {}).get("enabled", False)
        def update_channel_stats(self, channel, success, response_time=0): pass # Dummy
    
    class ChannelConfig:
        def __init__(self, url):
            self.url = url
            self.enabled = True
            self.is_telegram = 't.me/s' in url
            self.metrics = self.DummyMetrics()
        class DummyMetrics:
            total_configs = 0
            valid_configs = 0
            unique_configs = 0
            avg_response_time = 0
            last_success_time = None
            fail_count = 0
            success_count = 0
            overall_score = 0.0
            protocol_counts = {}
        def calculate_overall_score(self): pass # Dummy

    class ConfigValidator:
        @staticmethod
        def is_base64(s): return True # Simplified for dummy
        @staticmethod
        def decode_base64_text(s): return s # Simplified for dummy
        @staticmethod
        def clean_vmess_config(s): return s # Simplified for dummy
        @staticmethod
        def normalize_hysteria2_protocol(s): return s # Simplified for dummy
        @staticmethod
        def check_base64_content(s): return s # Simplified for dummy
        @staticmethod
        def split_configs(s): return s.split('\n') # Simplified for dummy
        @staticmethod
        def clean_config(s): return s # Simplified for dummy
        @staticmethod
        def validate_protocol_config(config_str, protocol): return True # Simplified for dummy

# Configure logging for better debugging and information
logging.basicConfig(
    level=logging.INFO, # Set logging level to INFO
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('proxy_fetcher.log'), # Log to file
        logging.StreamHandler() # Log to console
    ]
)
logger = logging.getLogger(__name__)

class ClashConverter:
    """
    کلاس کمکی برای تبدیل دیکشنری‌های پیکربندی Clash به فرمت URI پروکسی مربوطه.
    این کلاس برای استخراج پیکربندی‌ها از فایل‌های Clash YAML و تبدیل آن‌ها
    به فرمت‌های استاندارد URI که می‌توانند پردازش شوند، استفاده می‌شود.
    """
    @staticmethod
    def to_uri(proxy: Dict) -> Optional[str]:
        """
        یک دیکشنری پیکربندی پروکسی Clash را به فرمت URI مربوطه تبدیل می‌کند.
        """
        proxy_type = proxy.get("type")
        converters = {
            "vless": ClashConverter.to_vless,
            "vmess": ClashConverter.to_vmess,
            "ss": ClashConverter.to_ss,
            "trojan": ClashConverter.to_trojan,
            "ssr": ClashConverter.to_ssr,
            "hysteria": ClashConverter.to_hysteria, # Added Hysteria
            "hysteria2": ClashConverter.to_hysteria2,
            "tuic": ClashConverter.to_tuic,
            "wireguard": ClashConverter.to_wireguard,
            "anytls": ClashConverter.to_anytls,
            "snell": ClashConverter.to_snell, # Added Snell
            "ssh": ClashConverter.to_ssh, # Added SSH
            "mieru": ClashConverter.to_mieru, # Added Mieru
            "juicity": ClashConverter.to_juicity, # Added Juicity
        }
        if proxy_type in converters:
            try:
                return converters[proxy_type](proxy)
            except Exception as e:
                logger.error(f"Error converting Clash proxy to URI for type '{proxy_type}': {e}")
                return None
        else:
            logger.debug(f"[SKIPPED_CLASH] Unsupported Clash proxy type for URI conversion: '{proxy_type}'")
        return None

    @staticmethod
    def to_vless(proxy: Dict) -> str:
        """تبدیل دیکشنری Clash VLESS به URI VLESS."""
        server, port, uuid = proxy.get("server", ""), proxy.get("port", ""), proxy.get("uuid", "")
        name = quote(proxy.get("name", ""), safe='') # Ensure name is URL-safe
        
        params = {
            "type": proxy.get("network", "tcp"), # Default to tcp
            "security": "none",
            "flow": proxy.get("flow"),
        }

        # TLS/Reality settings
        if proxy.get("tls"):
            if proxy.get("reality-opts"):
                params["security"] = "reality"
                params["pbk"] = proxy["reality-opts"].get("public-key")
                params["sid"] = proxy["reality-opts"].get("short-id")
                params["fp"] = proxy.get("client-fingerprint") # Reality needs client-fingerprint
                if proxy["reality-opts"].get("spiderx"): params["spx"] = proxy["reality-opts"]["spiderx"]
                if proxy["reality-opts"].get("dest"): params["dest"] = proxy["reality-opts"]["dest"]
            else:
                params["security"] = "tls"
                params["sni"] = proxy.get("servername")
                if proxy.get("alpn"): params["alpn"] = ",".join(proxy["alpn"])
                if proxy.get("client-fingerprint"): params["fp"] = proxy["client-fingerprint"]
                if proxy.get("skip-cert-verify"): params["allowinsecure"] = "1"
        
        # Network specific options
        if params["type"] == "ws":
            ws_opts = proxy.get("ws-opts", {})
            params["path"] = ws_opts.get("path", "/")
            params["host"] = ws_opts.get("headers", {}).get("Host")
            if ws_opts.get("max-early-data"): params["ed"] = str(ws_opts["max-early-data"])
        elif params["type"] == "grpc":
            grpc_opts = proxy.get("grpc-opts", {})
            params["serviceName"] = grpc_opts.get("grpc-service-name")
            if grpc_opts.get("xver"): params["xver"] = str(grpc_opts["xver"])
        elif params["type"] == "http": # for direct http (rare for Vless)
            http_opts = proxy.get("http-opts", {})
            if http_opts.get("path"): params["path"] = http_opts["path"][0] # Take first path
            if http_opts.get("headers") and http_opts["headers"].get("Host"):
                params["host"] = http_opts["headers"]["Host"][0]

        # Clean up None values and encode
        params = {k: v for k, v in params.items() if v is not None and v != ''}
        query_string = urlencode(params, quote_via=quote)
        return f"vless://{uuid}@{server}:{port}?{query_string}#{name}"

    @staticmethod
    def to_vmess(proxy: Dict) -> str:
        """تبدیل دیکشنری Clash VMess به URI VMess."""
        name = proxy.get("name", "")
        vmess_json = {
            "v": "2", # VMess protocol version
            "ps": name, # Profile Name
            "add": proxy.get("server"), # Server address
            "port": str(proxy.get("port")), # Server port (as string)
            "id": proxy.get("uuid"), # UUID
            "aid": str(proxy.get("alterId", 0)), # AlterId (as string)
            "net": proxy.get("network", "tcp"), # Network type (tcp, ws, http, quic, grpc)
            "type": "none", # Header type (none, http, srtp, utp, wechat-video, dtls, wireguard) - default none
            "host": "", # Host header for HTTP/WS
            "path": "", # Path for WS/HTTP/gRPC
            "tls": "", # "tls" if TLS enabled
            "sni": "", # Server Name Indication
            "fp": "", # Fingerprint
            "scy": proxy.get("cipher", "auto"), # Security cipher (auto, aes-128-gcm, chacha20-poly1305, none)
            "alpn": [], # ALPN for TLS
            "xver": "1", # gRPC Xver
            # Reality options for VMess
            "pbk": "",
            "sid": "",
            "spx": "",
            "dest": "",
        }

        # Network specific options
        if vmess_json["net"] == "ws":
            ws_opts = proxy.get("ws-opts", {})
            vmess_json["path"] = ws_opts.get("path", "/")
            vmess_json["host"] = ws_opts.get("headers", {}).get("Host")
        elif vmess_json["net"] == "h2":
            h2_opts = proxy.get("h2-opts", {})
            if h2_opts.get("host"): vmess_json["host"] = h2_opts["host"][0]
            if h2_opts.get("path"): vmess_json["path"] = h2_opts["path"]
        elif vmess_json["net"] == "grpc":
            grpc_opts = proxy.get("grpc-opts", {})
            vmess_json["path"] = grpc_opts.get("grpc-service-name")
            if grpc_opts.get("xver"): vmess_json["xver"] = str(grpc_opts["xver"])

        # TLS settings
        if proxy.get("tls"):
            vmess_json["tls"] = "tls"
            vmess_json["sni"] = proxy.get("servername")
            if proxy.get("client-fingerprint"): vmess_json["fp"] = proxy["client-fingerprint"]
            if proxy.get("alpn"): vmess_json["alpn"] = proxy["alpn"]
            if proxy.get("skip-cert-verify"): vmess_json["allowInsecure"] = 1

            # Reality settings for VMess (if applicable)
            if proxy.get("reality-opts"):
                vmess_json["tls"] = "reality" # Overwrite tls to reality
                reality_opts = proxy["reality-opts"]
                vmess_json["pbk"] = reality_opts.get("public-key", "")
                vmess_json["sid"] = reality_opts.get("short-id", "")
                vmess_json["spx"] = reality_opts.get("spiderx", "")
                vmess_json["dest"] = reality_opts.get("dest", "")
        
        # Remove empty or default values to keep JSON compact
        final_vmess_json = {k: v for k, v in vmess_json.items() if v != "" and v != "none" and v != "0" and v != []}
        
        # Special handling for "aid": 0 and "xver": "1" if they are explicit defaults
        if proxy.get("alterId", 0) == 0 and "aid" not in final_vmess_json:
            final_vmess_json["aid"] = "0"
        if proxy.get("grpc-opts", {}).get("xver", "1") == "1" and "xver" not in final_vmess_json:
            final_vmess_json["xver"] = "1"

        json_str = json.dumps(final_vmess_json, separators=(',', ':')).encode('utf-8')
        return f"vmess://{base64.b64encode(json_str).decode('utf-8')}"

    @staticmethod
    def to_ss(proxy: Dict) -> str:
        """تبدیل دیکشنری Clash SS به URI SS."""
        server, port, password, cipher = proxy.get("server", ""), proxy.get("port", ""), proxy.get("password", ""), proxy.get("cipher", "")
        name = quote(proxy.get("name", ""), safe='')

        user_info = f"{cipher}:{password}"
        plugin_opts_str = ""

        if "plugin" in proxy:
            plugin_params = {"plugin": proxy["plugin"]}
            plugin_opts = proxy.get("plugin-opts", {})

            if proxy["plugin"] == "obfs":
                plugin_params["obfs"] = plugin_opts.get("mode")
                plugin_params["obfs-host"] = plugin_opts.get("host")
            elif proxy["plugin"] == "v2ray-plugin":
                plugin_params["mode"] = plugin_opts.get("mode", "websocket")
                if plugin_opts.get("tls"): plugin_params["tls"] = "true"
                plugin_params["path"] = plugin_opts.get("path")
                plugin_params["host"] = plugin_opts.get("host")
                if plugin_opts.get("mux"): plugin_params["mux"] = "true"
                if plugin_opts.get("client-fingerprint"): plugin_params["fp"] = plugin_opts["client-fingerprint"]
                if plugin_opts.get("servername"): plugin_params["sni"] = plugin_opts["servername"]
            elif proxy["plugin"] == "shadow-tls":
                plugin_params["password"] = plugin_opts.get("password")
                if plugin_opts.get("version"): plugin_params["version"] = str(plugin_opts["version"])
                if plugin_opts.get("server_name"): plugin_params["host"] = plugin_opts["server_name"] # Map to 'host' for URI

            plugin_params = {k: v for k, v in plugin_params.items() if v is not None and v != ''}
            if plugin_params:
                plugin_opts_str = "?" + urlencode(plugin_params, quote_via=quote)
        
        # Base64 encode user_info for some SS clients/formats if needed, but not standard for Clash output to URI
        # Sticking to plain for direct SS URI
        return f"ss://{quote(user_info)}@{server}:{port}{plugin_opts_str}#{name}"

    @staticmethod
    def to_trojan(proxy: Dict) -> str:
        """تبدیل دیکشنری Clash Trojan به URI Trojan."""
        server, port, password = proxy.get("server", ""), proxy.get("port", ""), proxy.get("password", "")
        name = quote(proxy.get("name", ""), safe='')

        params = {}
        # TLS settings
        if proxy.get("tls"):
            params["security"] = "tls"
            params["sni"] = proxy.get("servername")
            if proxy.get("alpn"): params["alpn"] = ",".join(proxy["alpn"])
            if proxy.get("client-fingerprint"): params["fp"] = proxy["client-fingerprint"]
            if proxy.get("skip-cert-verify"): params["allowinsecure"] = "1"
        
        # Reality settings for Trojan (if applicable)
        if proxy.get("reality-opts"):
            params["security"] = "reality"
            reality_opts = proxy["reality-opts"]
            params["pbk"] = reality_opts.get("public-key", "")
            params["sid"] = reality_opts.get("short-id", "")
            params["fp"] = proxy.get("client-fingerprint", "chrome") # Ensure default fp for reality
            if reality_opts.get("spiderx"): params["spx"] = reality_opts["spiderx"]
            if reality_opts.get("dest"): params["dest"] = reality_opts["dest"]

        # Network type
        network = proxy.get("network", "tcp")
        params["type"] = network

        # Network specific options
        if network == "ws":
            ws_opts = proxy.get("ws-opts", {})
            params["path"] = ws_opts.get("path", "/")
            params["host"] = ws_opts.get("headers", {}).get("Host")
            if ws_opts.get("max-early-data"): params["ed"] = str(ws_opts["max-early-data"])
        elif network == "grpc":
            grpc_opts = proxy.get("grpc-opts", {})
            params["serviceName"] = grpc_opts.get("grpc-service-name")
        elif network == "http": # Direct HTTP
            http_opts = proxy.get("http-opts", {})
            if http_opts.get("path"): params["path"] = http_opts["path"][0]
            if http_opts.get("headers") and http_opts["headers"].get("Host"):
                params["host"] = http_opts["headers"]["Host"][0]
        elif network == "tcp" and proxy.get("tcp-opts", {}).get("header", {}).get("type") == "http":
            tcp_header_opts = proxy["tcp-opts"]["header"]
            if tcp_header_opts.get("request", {}).get("path"):
                params["path"] = tcp_header_opts["request"]["path"][0] # Take first path
            if tcp_header_opts.get("request", {}).get("headers", {}).get("Host"):
                params["host"] = tcp_header_opts["request"]["headers"]["Host"][0]
            params["headerType"] = "http" # Indicate HTTP header type

        params = {k: v for k, v in params.items() if v is not None and v != ''}
        query_string = urlencode(params, quote_via=quote)
        return f"trojan://{quote(password)}@{server}:{port}?{query_string}#{name}"

    @staticmethod
    def to_hysteria(proxy: dict) -> str:
        """تبدیل دیکشنری Clash Hysteria به URI Hysteria."""
        server, port = proxy.get("server", ""), proxy.get("port", "")
        auth_str = proxy.get("auth-str", "")
        name = quote(proxy.get("name", ""), safe='')

        params = {
            "auth": auth_str,
            "upmbps": proxy.get("up"),
            "downmbps": proxy.get("down"),
            "protocol": proxy.get("protocol"),
            "sni": proxy.get("sni"),
            "insecure": "1" if proxy.get("skip-cert-verify") else None,
            "peer": proxy.get("sni"), # Often peer is same as SNI for Hysteria
            "obfs": proxy.get("obfs"),
            "obfs-password": proxy.get("obfs-password"),
            "alpn": ",".join(proxy["alpn"]) if proxy.get("alpn") else None,
            "fp": proxy.get("fingerprint"),
        }
        params = {k: v for k, v in params.items() if v is not None and v != ''}
        query_string = urlencode(params, quote_via=quote)
        return f"hysteria://{server}:{port}?{query_string}#{name}"


    @staticmethod
    def to_hysteria2(proxy: dict) -> str:
        """تبدیل دیکشنری Clash Hysteria2 به URI Hysteria2."""
        server, port, password = proxy.get("server", ""), proxy.get("port", ""), proxy.get("password", "")
        name = quote(proxy.get("name", ""), safe='')

        params = {
            "sni": proxy.get("sni"),
            "insecure": "1" if proxy.get("skip-cert-verify") else None,
            "pinSHA256": proxy.get("fingerprint"), # H2 uses pinSHA256
            "obfs": proxy.get("obfs"),
            "obfs-password": proxy.get("obfs-password"),
            "alpn": ",".join(proxy["alpn"]) if proxy.get("alpn") else None,
        }
        params = {k: v for k, v in params.items() if v is not None and v != ''}
        query_string = urlencode(params, quote_via=quote)
        return f"hysteria2://{quote(password)}@{server}:{port}?{query_string}#{name}"

    @staticmethod
    def to_tuic(proxy: dict) -> str:
        """تبدیل دیکشنری Clash TUIC به URI TUIC."""
        server, port = proxy.get("server", ""), proxy.get("port", "")
        name = quote(proxy.get("name", ""), safe='')

        # Authentication can be UUID:Password or just token (password field)
        auth_part = ""
        if proxy.get("uuid") and proxy.get("password"):
            auth_part = f"{proxy['uuid']}:{quote(proxy['password'])}"
        elif proxy.get("token"): # For TUIC v5 with token
            auth_part = quote(proxy["token"])
        elif proxy.get("password"): # Older TUIC versions might use password as token
             auth_part = quote(proxy["password"])

        params = {
            "sni": proxy.get("sni"),
            "alpn": ",".join(proxy["alpn"]) if proxy.get("alpn") else None,
            "insecure": "1" if proxy.get("skip-cert-verify") else None,
            "udp_relay_mode": proxy.get("udp-relay-mode"),
            "congestion_control": proxy.get("congestion-control"),
            "disable_sni": "1" if proxy.get("disable-sni") else None,
            "multiplex": "1" if proxy.get("enable-multiplex") else None,
            "fp": proxy.get("fingerprint"),
            "version": proxy.get("version"), # TUIC protocol version
        }
        params = {k: v for k, v in params.items() if v is not None and v != ''}
        query_string = urlencode(params, quote_via=quote)
        return f"tuic://{auth_part}@{server}:{port}?{query_string}#{name}"

    @staticmethod
    def to_ssr(proxy: dict) -> str:
        """تبدیل دیکشنری Clash SSR به URI SSR."""
        password_b64 = base64.b64encode(str(proxy.get('password', '')).encode('utf-8')).decode('utf-8').rstrip("=")
        
        # Assemble main SSR parts
        parts = [
            proxy.get('server', ''),
            str(proxy.get('port', '')),
            proxy.get('protocol', ''),
            proxy.get('cipher', ''),
            proxy.get('obfs', ''),
            password_b64 # Base64 encoded password
        ]
        main_part = ":".join(map(str, parts))

        # Assemble query parameters, base64 encode their values
        params = {}
        if proxy.get('obfs-param'):
            params["obfsparam"] = base64.b64encode(str(proxy['obfs-param']).encode('utf-8')).decode('utf-8').rstrip("=")
        if proxy.get('protocol-param'):
            params["protoparam"] = base64.b64encode(str(proxy['protocol-param']).encode('utf-8')).decode('utf-8').rstrip("=")
        if proxy.get('name'):
            params["remarks"] = base64.b64encode(str(proxy['name']).encode('utf-8')).decode('utf-8').rstrip("=")
        # Add other potential SSR params if they exist in Clash config
        if proxy.get('group'):
             params["group"] = base64.b64encode(str(proxy['group']).encode('utf-8')).decode('utf-8').rstrip("=")

        query_string = urlencode({k: v for k, v in params.items() if v}, quote_via=quote)
        
        # Combine and base64 encode the final SSR URI string
        full_ssr_string = f"{main_part}/?{query_string}" if query_string else main_part
        return f"ssr://{base64.b64encode(full_ssr_string.encode('utf-8')).decode('utf-8').rstrip('=')}"


    @staticmethod
    def to_wireguard(proxy: dict) -> str:
        """تبدیل دیکشنری Clash WireGuard به URI WireGuard."""
        private_key = quote(proxy.get('private-key', ''), safe='')
        server, port = proxy.get('server', ''), proxy.get('port', '')
        name = quote(proxy.get('name', ''), safe='')

        params = {
            'publicKey': proxy.get('public-key', ''),
            'presharedKey': proxy.get('pre-shared-key', ''),
            'mtu': str(proxy.get('mtu')) if proxy.get('mtu') else None,
        }
        
        # Handle IP addresses (local client IP)
        addresses = []
        if proxy.get('ip'): addresses.append(proxy['ip'])
        if proxy.get('ipv6'): addresses.append(proxy['ipv6'])
        if addresses: params['address'] = ",".join(addresses)

        # Handle DNS servers
        if proxy.get('dns'): params['dns'] = ",".join(proxy['dns'])

        params = {k: v for k, v in params.items() if v is not None and v != ''}
        query_string = urlencode(params, quote_via=quote)
        return f"wireguard://{private_key}@{server}:{port}?{query_string}#{name}"

    @staticmethod
    def to_anytls(proxy: dict) -> str:
        """تبدیل دیکشنری Clash Anytls به URI Anytls."""
        password, server, port = proxy.get('password', ''), proxy.get('server', ''), proxy.get('port', '')
        name = quote(proxy.get('name', ''), safe='')
        
        params = {
            'sni': proxy.get('sni'),
            'fp': proxy.get('client-fingerprint'),
            'alpn': ",".join(proxy["alpn"]) if proxy.get("alpn") else None,
            'insecure': "1" if proxy.get('skip-cert-verify') else None,
            'version': str(proxy.get('version')) if proxy.get('version') else None, # Anytls version
        }
        params = {k: v for k, v in params.items() if v is not None and v != ''}
        query_string = urlencode(params, quote_via=quote)
        return f"anytls://{quote(password)}@{server}:{port}?{query_string}#{name}"

    @staticmethod
    def to_snell(proxy: Dict) -> str:
        """تبدیل دیکشنری Clash Snell به URI Snell."""
        server, port, psk = proxy.get("server", ""), proxy.get("port", ""), proxy.get("psk", "")
        name = quote(proxy.get("name", ""), safe='')

        params = {
            "version": str(proxy.get("version", 3)),
        }
        if proxy.get("obfs"):
            params["obfs"] = proxy["obfs"]
            if proxy.get("obfs-host"):
                params["obfs-host"] = proxy["obfs-host"]

        params = {k: v for k, v in params.items() if v is not None and v != ''}
        query_string = urlencode(params, quote_via=quote)
        return f"snell://{quote(psk)}@{server}:{port}?{query_string}#{name}"

    @staticmethod
    def to_ssh(proxy: Dict) -> str:
        """تبدیل دیکشنری Clash SSH به URI SSH."""
        server, port = proxy.get("server", ""), proxy.get("port", "")
        username = quote(proxy.get("username", ""), safe='')
        password = quote(proxy.get("password", ""), safe='') if proxy.get("password") else None
        name = quote(proxy.get("name", ""), safe='')
        
        # URI structure for SSH is ssh://[user:pass@]host:port[?params]#name
        user_pass_part = ""
        if username:
            user_pass_part = username
            if password:
                user_pass_part += f":{password}"
            user_pass_part += "@"

        params = {
            "key-path": proxy.get("key-path"),
            "key-passphrase": proxy.get("key-passphrase"),
            "host-key": proxy.get("host-key"),
            "fingerprint": proxy.get("fingerprint"),
            "udp-over-tcp": "1" if proxy.get("udp-over-tcp") else None,
        }
        params = {k: v for k, v in params.items() if v is not None and v != ''}
        query_string = urlencode(params, quote_via=quote)

        return f"ssh://{user_pass_part}{server}:{port}?{query_string}#{name}"
    
    @staticmethod
    def to_mieru(proxy: Dict) -> str:
        """تبدیل دیکشنری Clash Mieru به URI Mieru."""
        server, port = proxy.get("server", ""), proxy.get("port", "")
        uuid = quote(proxy.get("username", ""), safe='') # Mieru typically uses UUID as username
        name = quote(proxy.get("name", ""), safe='')

        params = {
            "password": quote(proxy.get("password", ""), safe=''),
            "transport": proxy.get("transport"),
            "multiplexing": proxy.get("multiplexing"),
            "security": proxy.get("tls"), # If 'tls' is boolean, map to 'security=tls'
            "sni": proxy.get("sni"),
            "fp": proxy.get("fingerprint"),
            "insecure": "1" if proxy.get("skip-cert-verify") else None,
        }
        params = {k: v for k, v in params.items() if v is not None and v != ''}
        query_string = urlencode(params, quote_via=quote)
        return f"mieru://{uuid}@{server}:{port}?{query_string}#{name}"

    @staticmethod
    def to_juicity(proxy: Dict) -> str:
        """تبدیل دیکشنری Clash Juicity به URI Juicity."""
        server, port = proxy.get("server", ""), proxy.get("port", "")
        uuid = quote(proxy.get("uuid", ""), safe='')
        name = quote(proxy.get("name", ""), safe='')

        params = {
            "password": quote(proxy.get("password", ""), safe=''),
            "congestion_control": proxy.get("congestion-control"),
            "security": proxy.get("tls"), # If 'tls' is boolean, map to 'security=tls'
            "sni": proxy.get("sni"),
            "fp": proxy.get("client-fingerprint"),
            "insecure": "1" if proxy.get("skip-cert-verify") else None,
        }
        params = {k: v for k, v in params.items() if v is not None and v != ''}
        query_string = urlencode(params, quote_via=quote)
        return f"juicity://{uuid}@{server}:{port}?{query_string}#{name}"


class ConfigFetcher:
    """
    این کلاس مسئول دریافت پیکربندی‌های پروکسی از منابع مختلف،
    اعتبارسنجی آن‌ها، حذف موارد تکراری و سازماندهی آن‌ها بر اساس پروتکل است.
    همچنین شامل منطق برای دریافت اطلاعات جغرافیایی IP و به روز رسانی آمار کانال است.
    """
    def __init__(self, config: ProxyConfig):
        self.config = config
        self.validator = ConfigValidator() # استفاده از کلاس ConfigValidator برای اعتبارسنجی
        self.protocol_counts: Dict[str, int] = {p: 0 for p in config.SUPPORTED_PROTOCOLS} # شمارش کلی پیکربندی‌ها بر اساس پروتکل
        self.seen_configs: Set[str] = set() # برای ردیابی پیکربندی‌های دیده شده و جلوگیری از موارد تکراری
        self.channel_protocol_counts: Dict[str, Dict[str, int]] = {} # شمارش پیکربندی‌های هر کانال بر اساس پروتکل
        self.session = requests.Session() # استفاده از Session برای درخواست‌های HTTP به منظور حفظ کوکی‌ها و هدرها
        self.session.headers.update(config.HEADERS) # به روز رسانی هدرهای Session با هدرهای پیکربندی
        self.ip_location_cache: Dict[str, Tuple[str, str]] = {} # کش برای ذخیره موقعیت جغرافیایی IPها


    def get_hostname_from_uri(self, uri: str) -> Optional[str]:
        """
        نام هاست (آدرس سرور) را از یک URI پروکسی استخراج می‌کند.
        برای URI‌های Base64 رمزگذاری شده (مانند VMess, SSR) نیز منطق خاصی دارد.
        """
        try:
            if uri.lower().startswith("vmess://"):
                decoded_str = self.validator.decode_base64_text(uri[8:])
                if decoded_str:
                    try:
                        return json.loads(decoded_str).get('add')
                    except json.JSONDecodeError:
                        logger.debug(f"Failed to parse VMess JSON from: {decoded_str[:50]}...")
                        return None
            elif uri.lower().startswith("ssr://"):
                decoded_str = self.validator.decode_base64_text(uri[6:])
                if decoded_str:
                    # SSR format is typically host:port:protocol:method:obfs:base64pass/?params#name
                    # So, host is the first part before the first colon
                    return decoded_str.split(':')[0]
            else:
                # For standard URL-like URIs (vless, trojan, ss, etc.)
                return urlparse(uri).hostname
        except Exception as e:
            logger.debug(f"Error extracting hostname from URI '{uri[:80]}...': {e}")
        return None

    def batch_get_locations(self, hostnames: List[str]):
        """
        موقعیت جغرافیایی مجموعه‌ای از نام‌های هاست یا آدرس‌های IP را به صورت دسته‌ای دریافت می‌کند.
        از سرویس ip-api.com برای این کار استفاده می‌کند و نتایج را در کش ذخیره می‌کند.
        """
        logger.info(f"Resolving {len(hostnames)} unique hostnames to IP addresses...")
        unique_ips = set()
        hostname_to_ip_map = {}

        for hostname in hostnames:
            if not hostname or any(len(label) > 63 for label in hostname.split('.')):
                logger.warning(f"Skipping invalid hostname (e.g., label too long or empty): {hostname[:100]}...")
                self.ip_location_cache[hostname] = ("🏳️", "Unknown") # پرچم سفید و نام کشور ناشناس
                continue
            
            # Check if it's already an IP address
            is_ip = False
            try:
                socket.inet_pton(socket.AF_INET6, hostname)
                is_ip = True
            except socket.error:
                try:
                    socket.inet_pton(socket.AF_INET, hostname)
                    is_ip = True
                except socket.error:
                    is_ip = False
            
            if is_ip:
                unique_ips.add(hostname)
            else:
                # Resolve hostname to IP
                try:
                    ip = socket.gethostbyname(hostname)
                    unique_ips.add(ip)
                    hostname_to_ip_map[hostname] = ip
                except (socket.error, UnicodeEncodeError) as e:
                    logger.warning(f"Could not resolve hostname '{hostname}': {e}")
                    self.ip_location_cache[hostname] = ("🏳️", "Unknown") # Mark as unknown if resolution fails

        # Filter out IPs already in cache
        ips_to_query = list(unique_ips - set(self.ip_location_cache.keys()))
        if not ips_to_query:
            logger.info("All IP locations already resolved or cached. Skipping batch query.")
            return

        logger.info(f"Querying locations for {len(ips_to_query)} new IPs in batches...")
        # Split IPs into chunks for batch querying (ip-api.com limits to 100 per request)
        chunks = [ips_to_query[i:i + 100] for i in range(0, len(ips_to_query), 100)]
        
        for chunk in chunks:
            try:
                # Use POST request for batch query
                response = requests.post('http://ip-api.com/batch', json=chunk, timeout=20)
                response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
                
                for res in response.json():
                    ip_addr = res.get('query')
                    status = res.get('status')
                    if status == 'success' and res.get('countryCode'):
                        # Convert countryCode to emoji flag
                        flag = ''.join(chr(ord('🇦') + ord(c.upper()) - ord('A')) for c in res['countryCode'])
                        self.ip_location_cache[ip_addr] = (flag, res['country'])
                    else:
                        self.ip_location_cache[ip_addr] = ("🏳️", "Unknown") # Default for failed lookups
            except requests.RequestException as e:
                logger.error(f"Batch IP location query failed: {e}")
                # Mark all IPs in the failed chunk as unknown
                for ip in chunk:
                    self.ip_location_cache[ip] = ("🏳️", "Unknown")
        
        # Populate cache for original hostnames using their resolved IPs
        for hostname, ip in hostname_to_ip_map.items():
            if ip in self.ip_location_cache:
                self.ip_location_cache[hostname] = self.ip_location_cache[ip]
        
        logger.info("Batch location fetching complete.")

    def get_location_from_cache(self, address: str) -> Tuple[str, str]:
        """
        موقعیت جغرافیایی (پرچم ایموجی، نام کشور) را از کش موقعیت‌یابی IP برمی‌گرداند.
        """
        return self.ip_location_cache.get(address, ("🏳️", "Unknown"))

    def rename_configs_with_flags(self, uris: List[str]) -> List[str]:
        """
        URI‌های پروکسی را با اضافه کردن پرچم ایموجی کشور مربوطه به نام آن‌ها، تغییر نام می‌دهد.
        این کار خوانایی و مرتب‌سازی پروکسی‌ها را آسان‌تر می‌کند.
        """
        renamed_uris = []
        for uri in uris:
            try:
                parsed = urlparse(uri)
                hostname = self.get_hostname_from_uri(uri)
                
                if not hostname:
                    renamed_uris.append(uri)
                    continue
                
                flag, country = self.get_location_from_cache(hostname)
                original_name = unquote(parsed.fragment) or hostname # از نام موجود یا hostname استفاده می‌کند
                
                # فقط اگر نام فعلی با پرچم شروع نمی‌شود، پرچم را اضافه کنید
                if not re.match(r'^[\U0001F1E6-\U0001F1FF]{2}', original_name):
                    new_name = f"{flag} {original_name}"
                else:
                    new_name = original_name # نام از قبل پرچم دارد
                
                # ساخت URI جدید با نام تغییر یافته
                new_uri = urlunparse(parsed._replace(fragment=quote(new_name, safe='')))
                renamed_uris.append(new_uri)
            except Exception as e:
                logger.warning(f"Error renaming URI with flag '{uri[:80]}...': {e}. Appending original URI.")
                renamed_uris.append(uri) # اگر خطا رخ داد، URI اصلی را اضافه کنید
        return renamed_uris

    def fetch_with_retry(self, url: str) -> Optional[requests.Response]:
        """
        یک درخواست HTTP GET را با قابلیت تلاش مجدد و مکانیزم Backoff انجام می‌دهد.
        """
        backoff = 1 # ضریب افزایشی برای تاخیر
        for attempt in range(self.config.MAX_RETRIES):
            try:
                logger.debug(f"Attempt {attempt + 1} to fetch {url} (timeout: {self.config.REQUEST_TIMEOUT}s)")
                response = self.session.get(url, timeout=self.config.REQUEST_TIMEOUT)
                response.raise_for_status() # برای کدهای وضعیت 4xx/5xx خطا ایجاد می‌کند
                return response
            except requests.RequestException as e:
                if attempt == self.config.MAX_RETRIES - 1:
                    logger.error(f"Failed to fetch {url} after {self.config.MAX_RETRIES} attempts: {str(e)}")
                    return None
                wait_time = min(self.config.RETRY_DELAY * backoff, 60) # حداکثر تاخیر 60 ثانیه
                logger.warning(f"Attempt {attempt + 1} for {url} failed, retrying in {wait_time}s: {str(e)}")
                time.sleep(wait_time)
                backoff *= 2 # افزایش نمایی تاخیر
        return None

    def fetch_configs_from_source(self, channel: ChannelConfig) -> List[str]:
        """
        پیکربندی‌های پروکسی را از یک کانال منبع مشخص (URL) دریافت می‌کند.
        این تابع URLهای عادی، اشتراک‌های Base64 و کانال‌های تلگرام را مدیریت می‌کند.
        همچنین فایل‌های Clash YAML را نیز پردازش می‌کند.
        """
        configs: List[str] = []
        channel.metrics.total_configs = 0
        channel.metrics.valid_configs = 0
        channel.metrics.protocol_counts = {p: 0 for p in self.config.SUPPORTED_PROTOCOLS} # بازنشانی شمارنده پروتکل برای کانال
        
        start_time = time.time()
        response = self.fetch_with_retry(channel.url)
        
        if not response:
            self.config.update_channel_stats(channel, False) # بروزرسانی آمار کانال (ناموفق)
            return configs # بازگشت لیست خالی در صورت عدم موفقیت درخواست
        
        response_time = time.time() - start_time
        content = response.text
        is_yaml = False

        # Attempt to parse as Clash YAML
        try:
            # Check if content looks like a YAML file (e.g., starts with specific keys)
            if content.lstrip().startswith(('proxies:', 'proxy-groups:', 'rules:', '- ')): # Added '- ' for list start
                data = yaml.safe_load(content)
                if isinstance(data, dict) and 'proxies' in data:
                    is_yaml = True
                    clash_proxies = data.get('proxies', [])
                    for proxy in clash_proxies:
                        # Convert Clash proxy dictionary back to URI
                        uri = ClashConverter.to_uri(proxy)
                        if uri:
                            configs.append(uri)
                    logger.info(f"Parsed {len(configs)} configs from Clash YAML: {channel.url}")
        except yaml.YAMLError as e:
            logger.debug(f"Content from {channel.url} is not valid YAML: {e}")
            is_yaml = False
        except Exception as e:
            logger.error(f"Error processing potential YAML from {channel.url}: {e}")
            is_yaml = False

        # If not YAML, process as plain text or Telegram channel
        if not is_yaml:
            if channel.is_telegram:
                # Scrape configurations from Telegram channel HTML
                soup = BeautifulSoup(content, 'html.parser')
                messages = soup.find_all('div', class_='tgme_widget_message_text')
                for message in messages:
                    # Extract text content and split configs
                    found_configs = self.validator.split_configs(message.get_text(separator='\n'))
                    configs.extend(found_configs)
                logger.info(f"Parsed {len(configs)} configs from Telegram channel: {channel.url}")
            else:
                # Check if content is Base64 encoded subscription link
                cleaned_content = content.strip()
                if self.validator.is_base64(cleaned_content):
                    decoded_content = self.validator.decode_base64_text(cleaned_content)
                    if decoded_content:
                        content = decoded_content # Use decoded content for splitting
                        logger.info(f"Decoded Base64 content from {channel.url}")
                
                # Split and process configs from the (possibly decoded) content
                extracted_configs = self.validator.split_configs(content)
                configs.extend(extracted_configs)
                logger.info(f"Parsed {len(extracted_configs)} configs from raw/Base64 source: {channel.url}")

        # Deduplicate and validate configs obtained from the source
        unique_configs = list(dict.fromkeys(configs)) # حفظ ترتیب
        channel.metrics.total_configs = len(unique_configs)
        
        valid_configs = []
        for config_str in unique_configs:
            processed = self.process_config(config_str, channel)
            if processed:
                valid_configs.extend(processed)

        # Update channel statistics based on the number of valid configs found
        if len(valid_configs) >= self.config.MIN_CONFIGS_PER_CHANNEL:
            self.config.update_channel_stats(channel, True, response_time)
            logger.info(f"Channel {channel.url} successfully fetched {len(valid_configs)} valid configs.")
        else:
            self.config.update_channel_stats(channel, False, response_time)
            logger.warning(f"Channel {channel.url} yielded only {len(valid_configs)} valid configs (below min {self.config.MIN_CONFIGS_PER_CHANNEL}). Marked as failed.")

        return valid_configs

    def process_config(self, config: str, channel: ChannelConfig) -> List[str]:
        """
        یک رشته پیکربندی را پردازش می‌کند: آن را عادی‌سازی، اعتبارسنجی و در صورت موفقیت
        به لیست پیکربندی‌های دیده شده و شمارنده‌های پروتکل اضافه می‌کند.
        """
        processed_configs = []
        
        # عادی‌سازی پروتکل‌های مستعار (مانند hy2:// به hysteria2://)
        config = self.validator.normalize_hysteria2_protocol(config)
        # پاکسازی خاص برای Vmess
        config = self.validator.clean_vmess_config(config)
        # پاکسازی عمومی
        config = self.validator.clean_config(config)

        # بررسی هر پروتکل پشتیبانی شده
        for protocol_scheme, protocol_info in self.config.SUPPORTED_PROTOCOLS.items():
            # فقط اگر پیکربندی با طرحواره پروتکل شروع می‌شود و پروتکل فعال است
            if config.lower().startswith(protocol_scheme) and protocol_info.get("enabled", False):
                # اعتبارسنجی دقیق پروتکل
                if self.validator.validate_protocol_config(config, protocol_scheme):
                    # اگر پیکربندی از قبل دیده نشده باشد
                    if config not in self.seen_configs:
                        self.seen_configs.add(config) # اضافه کردن به مجموعه پیکربندی‌های دیده شده
                        processed_configs.append(config) # اضافه کردن به لیست پیکربندی‌های پردازش شده
                        
                        # به روز رسانی شمارنده‌های عمومی پروتکل
                        self.protocol_counts[protocol_scheme] = self.protocol_counts.get(protocol_scheme, 0) + 1
                        
                        # به روز رسانی شمارنده‌های پروتکل خاص کانال
                        if channel.url not in self.channel_protocol_counts:
                            self.channel_protocol_counts[channel.url] = {p: 0 for p in self.config.SUPPORTED_PROTOCOLS}
                        self.channel_protocol_counts[channel.url][protocol_scheme] = \
                            self.channel_protocol_counts[channel.url].get(protocol_scheme, 0) + 1
                        
                        channel.metrics.valid_configs += 1 # افزایش شمارنده پیکربندی‌های معتبر کانال
                        channel.metrics.unique_configs += 1 # افزایش شمارنده پیکربندی‌های یکتا کانال
                    else:
                        logger.debug(f"Skipping duplicate config: {config[:80]}...")
                else:
                    logger.debug(f"Config failed validation for protocol {protocol_scheme}: {config[:80]}...")
                break # پس از یافتن یک پروتکل مطابقت‌دار، از حلقه خارج شوید
        return processed_configs


    def extract_date_from_message(self, message) -> Optional[datetime]:
        """
        تاریخ را از عنصر HTML پیام تلگرام استخراج می‌کند.
        """
        try:
            time_element = message.find_parent('div', class_='tgme_widget_message').find('time')
            if time_element and 'datetime' in time_element.attrs:
                # تبدیل رشته ISO 8601 به شی datetime و اضافه کردن اطلاعات منطقه زمانی
                return datetime.fromisoformat(time_element['datetime'].replace('Z', '+00:00'))
        except Exception as e:
            logger.debug(f"Error extracting date from message: {e}")
        return None

    def is_config_valid(self, config_text: str, date: Optional[datetime]) -> bool:
        """
        بررسی می‌کند که آیا یک پیکربندی بر اساس تاریخ انتشار آن هنوز معتبر است یا خیر.
        اگر تاریخ ارائه نشده باشد، همیشه True برمی‌گرداند.
        """
        if not date:
            return True # اگر تاریخی وجود ندارد، فرض می‌کنیم معتبر است
        
        # مطمئن شوید که تاریخ با منطقه زمانی آگاه است
        if date.tzinfo is None:
            # اگر تاریخ بدون منطقه زمانی است، آن را به UTC تبدیل کنید
            date = date.replace(tzinfo=timezone.utc)
        
        # تاریخ برش (cutoff date) را بر اساس حداکثر عمر پیکربندی محاسبه کنید
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=self.config.MAX_CONFIG_AGE_DAYS)
        
        return date >= cutoff_date # اگر تاریخ پیکربندی بعد از تاریخ برش باشد، معتبر است

    def balance_protocols(self, configs: List[str]) -> Dict[str, List[str]]:
        """
        پیکربندی‌ها را بر اساس پروتکل گروه‌بندی و متعادل می‌کند.
        اگر حالت 'use_maximum_power' فعال باشد، همه پیکربندی‌ها را بدون محدودیت برمی‌گرداند.
        در غیر این صورت، سعی می‌کند تعداد مشخصی از پیکربندی‌ها را با اولویت‌بندی پروتکل‌ها انتخاب کند.
        """
        protocol_configs: Dict[str, List[str]] = {p: [] for p in self.config.SUPPORTED_PROTOCOLS}
        
        # گروه‌بندی پیکربندی‌ها بر اساس پروتکل
        for config_str in configs:
            # عادی‌سازی برای مطابقت با طرحواره‌های استاندارد
            normalized_config = self.validator.normalize_hysteria2_protocol(config_str)
            
            for protocol_scheme in self.config.SUPPORTED_PROTOCOLS:
                if normalized_config.lower().startswith(protocol_scheme):
                    protocol_configs[protocol_scheme].append(config_str)
                    break
        
        # اگر حالت حداکثر توان فعال است یا تعداد پیکربندی مشخص نشده، همه را برگردانید
        if self.config.use_maximum_power or self.config.specific_config_count <= 0:
            return protocol_configs

        # حالت متعادل‌سازی: انتخاب تعداد مشخصی پیکربندی
        balanced_categorized_configs: Dict[str, List[str]] = {p: [] for p in self.config.SUPPORTED_PROTOCOLS}
        total_added_configs = 0

        # مرتب‌سازی پروتکل‌ها بر اساس اولویت (اولویت کمتر، اولویت بالاتر)
        sorted_protocols = sorted(protocol_configs.keys(),
                                  key=lambda p: self.config.SUPPORTED_PROTOCOLS.get(p, {}).get("priority", 99))

        for protocol in sorted_protocols:
            if total_added_configs >= self.config.specific_config_count:
                break # اگر به تعداد هدف رسیدیم، متوقف می‌شویم

            configs_for_this_protocol = protocol_configs[protocol]
            random.shuffle(configs_for_this_protocol) # تصادفی کردن برای توزیع بهتر

            # محاسبه تعداد جایگاه‌های باقی‌مانده و تعداد پیکربندی برای گرفتن از این پروتکل
            remaining_slots = self.config.specific_config_count - total_added_configs
            num_to_take = min(len(configs_for_this_protocol), remaining_slots)

            # اطمینان از رعایت حداقل پیکربندی برای هر پروتکل فعال
            min_for_protocol = self.config.SUPPORTED_PROTOCOLS[protocol].get("min_configs", 1)
            num_to_take = max(num_to_take, min(min_for_protocol, len(configs_for_this_protocol)))
            
            # اطمینان از عدم تجاوز از حداکثر پیکربندی برای هر پروتکل
            max_for_protocol = self.config.SUPPORTED_PROTOCOLS[protocol].get("max_configs", len(configs_for_this_protocol))
            num_to_take = min(num_to_take, max_for_protocol)

            if num_to_take > 0:
                balanced_categorized_configs[protocol] = configs_for_this_protocol[:num_to_take]
                total_added_configs += num_to_take
                logger.info(f"Added {num_to_take} {protocol} configs. Total: {total_added_configs}")
        
        # اگر هنوز جای خالی داریم، می‌توانیم از پروتکل‌های موجود به صورت چرخشی اضافه کنیم
        # این بخش برای اطمینان از رسیدن به specific_config_count در صورت امکان است.
        if total_added_configs < self.config.specific_config_count:
            remaining_needed = self.config.specific_config_count - total_added_configs
            all_remaining_potential_configs = []
            for protocol in sorted_protocols:
                # Add configs that were not taken in the first pass
                taken_count = len(balanced_categorized_configs[protocol])
                all_remaining_potential_configs.extend(protocol_configs[protocol][taken_count:])
            
            random.shuffle(all_remaining_potential_configs)
            # Add up to remaining_needed from the combined pool, respecting limits
            for config_str in all_remaining_potential_configs:
                if total_added_configs >= self.config.specific_config_count:
                    break
                
                # Re-identify protocol for this config
                current_protocol_scheme = None
                for p_scheme in self.config.SUPPORTED_PROTOCOLS:
                    if config_str.lower().startswith(p_scheme):
                        current_protocol_scheme = p_scheme
                        break
                
                if current_protocol_scheme:
                    max_for_current_protocol = self.config.SUPPORTED_PROTOCOLS[current_protocol_scheme].get("max_configs", float('inf'))
                    if len(balanced_categorized_configs[current_protocol_scheme]) < max_for_current_protocol:
                        balanced_categorized_configs[current_protocol_scheme].append(config_str)
                        total_added_configs += 1
        
        logger.info(f"Final balanced total configs: {total_added_configs} out of target {self.config.specific_config_count}")
        return balanced_categorized_configs


    def fetch_all_configs(self) -> Dict[str, List[str]]:
        """
        تمام پیکربندی‌های پروکسی را از تمام کانال‌های منبع فعال دریافت می‌کند،
        آن‌ها را پردازش، یکتا و متعادل می‌کند و سپس موقعیت جغرافیایی سرورها را دریافت می‌کند.
        """
        all_configs: List[str] = []
        enabled_channels = self.config.get_enabled_channels()
        
        if not enabled_channels:
            logger.warning("No enabled channels found in config. Skipping fetching process.")
            return {}

        logger.info(f"Starting to fetch configs from {len(enabled_channels)} enabled channels.")
        
        for idx, channel in enumerate(enabled_channels, 1):
            logger.info(f"Fetching from {channel.url} ({idx}/{len(enabled_channels)})")
            try:
                channel_configs = self.fetch_configs_from_source(channel)
                all_configs.extend(channel_configs)
                # Update channel's protocol counts based on what was found
                channel.metrics.protocol_counts = self.channel_protocol_counts.get(channel.url, {p: 0 for p in self.config.SUPPORTED_PROTOCOLS})
            except Exception as e:
                logger.error(f"Failed to fetch or process {channel.url}: {e}", exc_info=True)
            
            # Small delay between channel fetches to be polite and avoid rate limits
            if idx < len(enabled_channels):
                time.sleep(self.config.RETRY_DELAY) # Use configured retry delay as inter-channel delay

        # Final deduplication across all channels
        unique_configs = sorted(list(dict.fromkeys(all_configs)))
        logger.info(f"Found a total of {len(unique_configs)} unique configs before balancing protocols.")

        # Balance protocols based on configuration
        balanced_configs = self.balance_protocols(unique_configs)
        
        # Collect all hostnames from the final balanced set for geo-location
        all_hostnames_to_lookup = set()
        for protocol_scheme, P_configs in balanced_configs.items():
            for uri in P_configs:
                hostname = self.get_hostname_from_uri(uri)
                if hostname:
                    all_hostnames_to_lookup.add(hostname)
        
        # Fetch locations in batch for all collected hostnames
        self.batch_get_locations(list(all_hostnames_to_lookup))
        
        # Rename configs with flags based on the fetched locations
        final_renamed_configs = {}
        for protocol, configs_list in balanced_configs.items():
            if configs_list: # Only process if there are configs for this protocol
                final_renamed_configs[protocol] = self.rename_configs_with_flags(configs_list)
        
        return final_renamed_configs

def save_configs(categorized_configs: Dict[str, List[str]], config: ProxyConfig):
    """
    پیکربندی‌های پروکسی دسته‌بندی شده را در فایل‌های متنی و Base64 ذخیره می‌کند.
    شامل یک فایل اصلی ترکیب شده و فایل‌های جداگانه برای هر پروتکل.
    """
    try:
        output_dir = os.path.dirname(config.OUTPUT_FILE)
        os.makedirs(output_dir, exist_ok=True) # اطمینان از وجود دایرکتوری خروجی

        all_configs_list = [] # لیست برای نگهداری تمام پیکربندی‌ها برای فایل اصلی

        logger.info("--- Starting to save per-protocol files (text and base64) ---")
        for protocol_scheme, configs_list in categorized_configs.items():
            if not configs_list:
                continue # رد کردن پروتکل‌هایی که هیچ پیکربندی ندارند

            all_configs_list.extend(configs_list) # اضافه کردن به لیست کلی
            protocol_name = protocol_scheme.replace("://", "") # نام پروتکل بدون طرحواره (مثلاً "vless")

            # ذخیره فایل متنی برای هر پروتکل
            protocol_filename = os.path.join(output_dir, f"{protocol_name}_configs.txt")
            try:
                with open(protocol_filename, 'w', encoding='utf-8') as f:
                    f.write('\n\n'.join(configs_list)) # هر پیکربندی در یک خط، با یک خط خالی بین آن‌ها
                logger.info(f"-> SUCCESS: Saved {len(configs_list)} configs to {protocol_filename}")
            except Exception as e:
                logger.error(f"-> FAILED: Could not save protocol file {protocol_filename}: {e}")

            # ذخیره نسخه Base64 برای هر پروتکل
            base64_filename = os.path.join(output_dir, f"{protocol_name}_configs_base64.txt")
            try:
                # محتوای Base64 شامل تمام پیکربندی‌های آن پروتکل است که با خط جدید از هم جدا شده‌اند
                base64_content = base64.b64encode('\n'.join(configs_list).encode('utf-8')).decode('utf-8')
                with open(base64_filename, 'w', encoding='utf-8') as f:
                    f.write(base64_content)
                logger.info(f"-> SUCCESS: Saved Base64 version to {base64_filename}")
            except Exception as e:
                logger.error(f"-> FAILED: Could not save Base64 file {base64_filename}: {e}")

        if not all_configs_list:
            logger.warning("No total configs to save in the main file. All categorized lists were empty.")
            return

        # ذخیره فایل اصلی تمام پیکربندی‌ها
        sorted_all_configs = sorted(list(dict.fromkeys(all_configs_list))) # حذف نهایی موارد تکراری و مرتب‌سازی
        
        # هدر برای فایل اصلی (قابل استفاده در برنامه‌های کلاینت)
        header = """//profile-title: base64:8J+RvUFub255bW91cy3wnZWP
//profile-update-interval: 1
//subscription-userinfo: upload=0; download=0; total=10737418240000000; expire=2546249531
//support-url: https://t.me/BXAMbot
//profile-web-page-url: https://github.com/4n0nymou3

"""
        with open(config.OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write(header)
            f.write('\n\n'.join(sorted_all_configs)) # نوشتن پیکربندی‌ها با دو خط جدید بین آن‌ها
        logger.info(f"-> SUCCESS: Saved {len(sorted_all_configs)} total configs to {config.OUTPUT_FILE}")

        # ذخیره نسخه Base64 فایل اصلی
        main_base64_filename = os.path.join(output_dir, "proxy_configs_base64.txt")
        try:
            main_base64_content = base64.b64encode('\n'.join(sorted_all_configs).encode('utf-8')).decode('utf-8')
            with open(main_base64_filename, 'w', encoding='utf-8') as f:
                f.write(main_base64_content)
            logger.info(f"-> SUCCESS: Saved Base64 version of main config to {main_base64_filename}")
        except Exception as e:
            logger.error(f"-> FAILED: Could not save main Base64 file {main_base64_filename}: {e}")
    except Exception as e:
        logger.error(f"-> FAILED: A critical error occurred in save_configs function: {str(e)}", exc_info=True)


def save_channel_stats(config: ProxyConfig):
    """
    آمارهای کانال را در یک فایل JSON ذخیره می‌کند.
    """
    try:
        stats = {
            'timestamp': datetime.now(timezone.utc).isoformat(), # زمان فعلی با منطقه زمانی UTC
            'channels': []
        }
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
                'last_check_time': channel.last_check_time.isoformat() if channel.last_check_time else None, # اضافه شدن زمان آخرین بررسی
                'error_count': channel.error_count, # اضافه شدن شمارنده خطا
            }
            stats['channels'].append(channel_stats)
        
        output_dir = os.path.dirname(config.STATS_FILE)
        os.makedirs(output_dir, exist_ok=True) # اطمینان از وجود دایرکتوری خروجی
        
        with open(config.STATS_FILE, 'w', encoding='utf-8') as f:
            json.dump(stats, f, indent=2, ensure_ascii=False) # ذخیره به صورت JSON با فرمت زیبا
        logger.info(f"Channel statistics saved to {config.STATS_FILE}")
    except Exception as e:
        logger.error(f"Error saving channel statistics: {str(e)}", exc_info=True)


def main():
    """
    تابع اصلی برای اجرای فرآیند دریافت، پردازش و ذخیره پیکربندی‌های پروکسی.
    """
    try:
        # مقداردهی اولیه پیکربندی‌ها
        config = ProxyConfig()
        # مقداردهی اولیه دریافت کننده پیکربندی‌ها
        fetcher = ConfigFetcher(config)
        
        logger.info("Starting config fetching process...")
        # دریافت و دسته‌بندی تمام پیکربندی‌ها
        categorized_configs = fetcher.fetch_all_configs()
        
        # محاسبه تعداد کل پیکربندی‌های یافت شده
        total_config_count = sum(len(v) for v in categorized_configs.values())
        
        if total_config_count > 0:
            # ذخیره پیکربندی‌ها در فایل
            save_configs(categorized_configs, config)
            logger.info(f"Successfully processed {total_config_count} configs.")
            # گزارش تعداد پیکربندی‌های یافت شده برای هر پروتکل
            for protocol, configs in categorized_configs.items():
                if len(configs) > 0:
                    logger.info(f"-> Found {len(configs)} {protocol.replace('://','').upper()} configs")
        else:
            logger.warning("No valid configs found from any source! Output files will be empty or not generated.")
            # در این حالت، ممکن است نیاز باشد یک فایل proxy_configs.txt خالی ایجاد شود.
            config.save_empty_config_file()


        # ذخیره آمار کانال‌ها
        save_channel_stats(config)
        logger.info("Process finished successfully.")

    except Exception as e:
        logger.error(f"Error in main execution: {str(e)}", exc_info=True)


if __name__ == '__main__':
    main()
