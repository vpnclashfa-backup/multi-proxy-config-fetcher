import json
import base64
import uuid
import re
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs, unquote

class ConfigToSingbox:
    def __init__(self):
        self.output_file = 'configs/singbox_configs.json'

    def decode_vmess(self, config: str) -> Optional[Dict]:
        try:
            encoded = config.replace('vmess://', '')
            decoded = base64.b64decode(encoded).decode('utf-8')
            data = json.loads(decoded)
            
            if not all(key in data for key in ['add', 'port', 'id']):
                return None
                
            return {
                "type": "vmess",
                "tag": f"vmess-{str(uuid.uuid4())[:8]}",
                "server": data['add'],
                "server_port": int(data['port']),
                "uuid": data['id'],
                "security": data.get('scy', 'auto'),
                "alter_id": int(data.get('aid', 0)),
                "transport": {
                    "type": data.get('net', 'tcp'),
                    "path": data.get('path', ''),
                    "headers": {
                        "Host": data.get('host', '')
                    } if data.get('host') else {}
                } if data.get('net') in ['ws', 'grpc', 'http'] else None,
                "tls": {
                    "enabled": data.get('tls') == 'tls',
                    "insecure": True,
                    "server_name": data.get('sni', '') or data.get('host', '') or data['add']
                } if data.get('tls') == 'tls' else None
            }
        except:
            return None

    def parse_vless(self, config: str) -> Optional[Dict]:
        try:
            if '@' not in config:
                return None
                
            userinfo, serverinfo = config.replace('vless://', '').split('@', 1)
            
            if '?' in serverinfo:
                server_addr, params = serverinfo.split('?', 1)
                params = dict(param.split('=', 1) for param in params.split('&') if '=' in param)
            else:
                server_addr, params = serverinfo, {}
                
            if ':' not in server_addr:
                return None
                
            host, port = server_addr.split(':', 1)
            if '/' in port:
                port, _ = port.split('/', 1)
                
            return {
                "type": "vless",
                "tag": f"vless-{str(uuid.uuid4())[:8]}",
                "server": host,
                "server_port": int(port),
                "uuid": userinfo,
                "flow": params.get('flow', ''),
                "transport": {
                    "type": params.get('type', 'tcp'),
                    "path": params.get('path', ''),
                    "headers": {
                        "Host": params.get('host', '')
                    } if params.get('host') else {}
                } if params.get('type') in ['ws', 'grpc', 'http'] else None,
                "tls": {
                    "enabled": True,
                    "insecure": True,
                    "server_name": params.get('sni', '') or params.get('host', '') or host,
                    "utls": {
                        "enabled": True,
                        "fingerprint": params.get('fp', 'chrome')
                    }
                }
            }
        except:
            return None

    def parse_trojan(self, config: str) -> Optional[Dict]:
        try:
            if '@' not in config:
                return None
                
            password, server_info = config.replace('trojan://', '').split('@', 1)
            
            if '?' in server_info:
                server_addr, params = server_info.split('?', 1)
                params = dict(param.split('=', 1) for param in params.split('&') if '=' in param)
            else:
                server_addr, params = server_info, {}
                
            if ':' not in server_addr:
                return None
                
            host, port = server_addr.split(':', 1)
            if '/' in port:
                port, _ = port.split('/', 1)
                
            return {
                "type": "trojan",
                "tag": f"trojan-{str(uuid.uuid4())[:8]}",
                "server": host,
                "server_port": int(port),
                "password": unquote(password),
                "transport": {
                    "type": params.get('type', 'tcp'),
                    "path": params.get('path', ''),
                    "headers": {
                        "Host": params.get('host', '')
                    } if params.get('host') else {}
                } if params.get('type') in ['ws', 'grpc', 'http'] else None,
                "tls": {
                    "enabled": True,
                    "insecure": True,
                    "server_name": params.get('sni', '') or params.get('host', '') or host,
                    "utls": {
                        "enabled": True,
                        "fingerprint": params.get('fp', 'chrome')
                    }
                }
            }
        except:
            return None

    def parse_hysteria2(self, config: str) -> Optional[Dict]:
        try:
            url = urlparse(config.replace('hysteria2://', '').replace('hy2://', ''))
            if not url.hostname or not url.port:
                return None
                
            params = dict(param.split('=', 1) for param in url.query.split('&') if '=' in param) if url.query else {}
            
            return {
                "type": "hysteria2",
                "tag": f"hy2-{str(uuid.uuid4())[:8]}",
                "server": url.hostname,
                "server_port": url.port,
                "password": url.username or params.get('password', ''),
                "tls": {
                    "enabled": True,
                    "insecure": True,
                    "server_name": params.get('sni', '') or url.hostname,
                    "alpn": [params.get('alpn', 'h3')]
                },
                "bandwidth": {
                    "up": params.get('up', '100 mbps'),
                    "down": params.get('down', '100 mbps')
                }
            }
        except:
            return None

    def parse_shadowsocks(self, config: str) -> Optional[Dict]:
        try:
            if '@' not in config:
                return None
                
            userinfo, server = config.replace('ss://', '').split('@', 1)
            try:
                method_pass = base64.b64decode(userinfo).decode()
            except:
                method_pass = unquote(userinfo)
                
            if ':' not in method_pass:
                return None
                
            method, password = method_pass.split(':', 1)
            
            if '#' in server:
                server = server.split('#')[0]
                
            if ':' not in server:
                return None
                
            host, port = server.split(':', 1)
            
            return {
                "type": "shadowsocks",
                "tag": f"ss-{str(uuid.uuid4())[:8]}",
                "server": host,
                "server_port": int(port),
                "method": method,
                "password": password
            }
        except:
            return None

    def convert_to_singbox(self, config: str) -> Optional[Dict]:
        config = config.strip()
        if not config:
            return None
            
        try:
            if config.startswith('vmess://'):
                return self.decode_vmess(config)
            elif config.startswith('vless://'):
                return self.parse_vless(config)
            elif config.startswith('trojan://'):
                return self.parse_trojan(config)
            elif config.startswith(('hysteria2://', 'hy2://')):
                return self.parse_hysteria2(config)
            elif config.startswith('ss://'):
                return self.parse_shadowsocks(config)
            return None
        except:
            return None

    def process_configs(self):
        try:
            with open('configs/proxy_configs.txt', 'r') as f:
                configs = f.read().strip().split('\n')

            outbounds = []
            valid_tags = []

            for config in configs:
                converted = self.convert_to_singbox(config)
                if converted and all(key in converted for key in ['type', 'server', 'server_port']):
                    outbounds.append(converted)
                    valid_tags.append(converted['tag'])

            if not outbounds:
                return

            singbox_config = {
                "dns": {
                    "final": "local-dns",
                    "rules": [
                        {
                            "clash_mode": "Global",
                            "server": "proxy-dns",
                            "source_ip_cidr": ["172.19.0.0/30"]
                        },
                        {
                            "server": "proxy-dns",
                            "source_ip_cidr": ["172.19.0.0/30"]
                        },
                        {
                            "clash_mode": "Direct",
                            "server": "direct-dns"
                        },
                        {
                            "rule_set": ["geosite-ir"],
                            "server": "direct-dns"
                        }
                    ],
                    "servers": [
                        {
                            "address": "tls://208.67.222.123",
                            "address_resolver": "local-dns",
                            "detour": "proxy",
                            "tag": "proxy-dns"
                        },
                        {
                            "address": "local",
                            "detour": "direct",
                            "tag": "local-dns"
                        },
                        {
                            "address": "rcode://success",
                            "tag": "block"
                        },
                        {
                            "address": "local",
                            "detour": "direct",
                            "tag": "direct-dns"
                        }
                    ],
                    "strategy": "prefer_ipv4"
                },
                "inbounds": [
                    {
                        "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
                        "auto_route": True,
                        "endpoint_independent_nat": False,
                        "mtu": 9000,
                        "platform": {
                            "http_proxy": {
                                "enabled": True,
                                "server": "127.0.0.1",
                                "server_port": 2080
                            }
                        },
                        "sniff": True,
                        "stack": "system",
                        "strict_route": False,
                        "type": "tun"
                    },
                    {
                        "listen": "127.0.0.1",
                        "listen_port": 2080,
                        "sniff": True,
                        "type": "mixed",
                        "users": []
                    }
                ],
                "outbounds": [
                    {
                        "tag": "proxy",
                        "type": "selector",
                        "outbounds": ["auto"] + valid_tags + ["direct"]
                    },
                    {
                        "tag": "auto",
                        "type": "urltest",
                        "outbounds": valid_tags,
                        "url": "http://www.gstatic.com/generate_204",
                        "interval": "10m",
                        "tolerance": 50
                    },
                    {
                        "tag": "direct",
                        "type": "direct"
                    },
                    {
                        "tag": "dns-out",
                        "type": "dns"
                    },
                    {
                        "tag": "block",
                        "type": "block"
                    }
                ] + outbounds,
                "route": {
                    "auto_detect_interface": True,
                    "final": "proxy",
                    "rule_set": [
                        {
                            "download_detour": "direct",
                            "format": "binary",
                            "tag": "geosite-ads",
                            "type": "remote",
                            "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/category-ads-all.srs"
                        },
                        {
                            "download_detour": "direct",
                            "format": "binary",
                            "tag": "geosite-private",
                            "type": "remote",
                            "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/private.srs"
                        },
                        {
                            "download_detour": "direct",
                            "format": "binary",
                            "tag": "geosite-ir",
                            "type": "remote",
                            "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/category-ir.srs"
                        },
                        {
                            "download_detour": "direct",
                            "format": "binary",
                            "tag": "geoip-private",
                            "type": "remote",
                            "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/private.srs"
                        },
                        {
                            "download_detour": "direct",
                            "format": "binary",
                            "tag": "geoip-ir",
                            "type": "remote",
                            "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/ir.srs"
                        }
                    ],
                    "rules": [
                        {
                            "clash_mode": "Direct",
                            "outbound": "direct"
                        },
                        {
                            "clash_mode": "Global",
                            "outbound": "proxy"
                        },
                        {
                            "outbound": "dns-out",
                            "protocol": "dns"
                        },
                        {
                            "outbound": "direct",
                            "rule_set": [
                                "geoip-private",
                                "geosite-private",
                                "geosite-ir",
                                "geoip-ir"
                            ]
                        },
                        {
                            "outbound": "block",
                            "rule_set": ["geosite-ads"]
                        }
                    ]
                }
            }

            with open(self.output_file, 'w') as f:
                json.dump(singbox_config, f, indent=2, ensure_ascii=False)

        except Exception as e:
            print(f"Error processing configs: {str(e)}")

def main():
    converter = ConfigToSingbox()
    converter.process_configs()

if __name__ == '__main__':
    main()