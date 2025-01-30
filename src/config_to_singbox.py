import json
import base64
import uuid
import re
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs, unquote, urlunparse

class ConfigToSingbox:
    def __init__(self):
        self.output_file = 'configs/singbox_configs.json'

    def decode_vmess(self, config: str) -> Optional[Dict]:
        try:
            encoded = config.split('vmess://')[1]
            pad = len(encoded) % 4
            encoded += '=' * (4 - pad) if pad else ''
            decoded = base64.b64decode(encoded).decode('utf-8')
            return json.loads(decoded)
        except:
            return None

    def parse_vless(self, config: str) -> Optional[Dict]:
        try:
            url = urlparse(config)
            if url.scheme != 'vless' or not url.hostname:
                return None
            
            netloc = url.netloc.split('@')[-1]
            address, port = netloc.split(':') if ':' in netloc else (netloc, '443')
            params = parse_qs(url.query)
            
            return {
                'uuid': url.username,
                'address': address,
                'port': int(port),
                'flow': params.get('flow', [''])[0],
                'sni': params.get('sni', [address])[0],
                'type': params.get('type', ['tcp'])[0],
                'path': params.get('path', [''])[0],
                'host': params.get('host', [''])[0]
            }
        except:
            return None

    def parse_trojan(self, config: str) -> Optional[Dict]:
        try:
            url = urlparse(config)
            if url.scheme != 'trojan' or not url.hostname:
                return None
            
            port = url.port or 443
            params = parse_qs(url.query)
            
            return {
                'password': url.username,
                'address': url.hostname,
                'port': port,
                'sni': params.get('sni', [url.hostname])[0],
                'alpn': params.get('alpn', [''])[0],
                'type': params.get('type', ['tcp'])[0],
                'path': params.get('path', [''])[0]
            }
        except:
            return None

    def parse_shadowsocks(self, config: str) -> Optional[Dict]:
        try:
            parts = config.split('ss://')[1].split('#', 1)
            encoded = parts[0]
            pad = len(encoded) % 4
            encoded += '=' * (4 - pad) if pad else ''
            decoded = base64.b64decode(encoded).decode('utf-8')
            
            if '@' in decoded:
                method_pass, server = decoded.split('@')
                method, password = method_pass.split(':', 1)
                host, port = server.split(':')
                return {
                    'method': method,
                    'password': password,
                    'address': host,
                    'port': int(port)
                }
            else:  # SIP002 format
                raise ValueError
        except:
            return None

    def convert_to_singbox(self, config: str) -> Optional[Dict]:
        try:
            if config.startswith('vmess://'):
                vmess = self.decode_vmess(config)
                if not vmess: return None
                
                return {
                    "type": "vmess",
                    "tag": f"vmess-{uuid.uuid4().hex[:6]}",
                    "server": vmess.get('add'),
                    "server_port": int(vmess.get('port')),
                    "uuid": vmess.get('id'),
                    "security": vmess.get('scy', 'auto'),
                    "alter_id": int(vmess.get('aid', 0)),
                    "transport": {
                        "type": vmess.get('net', 'tcp'),
                        "path": vmess.get('path', ''),
                        "headers": {"Host": vmess.get('host', '')}
                    } if vmess.get('net') in ['ws', 'h2'] else {},
                    "tls": {
                        "enabled": vmess.get('tls') == 'tls',
                        "server_name": vmess.get('sni', vmess.get('add')),
                        "insecure": True
                    }
                }

            elif config.startswith('vless://'):
                vless = self.parse_vless(config)
                if not vless: return None
                
                out = {
                    "type": "vless",
                    "tag": f"vless-{uuid.uuid4().hex[:6]}",
                    "server": vless['address'],
                    "server_port": vless['port'],
                    "uuid": vless['uuid'],
                    "flow": vless['flow'],
                    "tls": {
                        "enabled": True,
                        "server_name": vless['sni'],
                        "insecure": False
                    },
                    "transport": {}
                }
                
                if vless['type'] == 'ws':
                    out['transport'] = {
                        "type": "ws",
                        "path": vless['path'],
                        "headers": {"Host": vless['host']}
                    }
                return out

            elif config.startswith('trojan://'):
                trojan = self.parse_trojan(config)
                if not trojan: return None
                
                return {
                    "type": "trojan",
                    "tag": f"trojan-{uuid.uuid4().hex[:6]}",
                    "server": trojan['address'],
                    "server_port": trojan['port'],
                    "password": trojan['password'],
                    "tls": {
                        "enabled": True,
                        "server_name": trojan['sni'],
                        "alpn": trojan['alpn'].split(',') if trojan['alpn'] else [],
                        "insecure": False
                    },
                    "transport": {
                        "type": trojan['type'],
                        "path": trojan['path']
                    } if trojan['type'] != 'tcp' else {}
                }

            elif config.startswith('ss://'):
                ss = self.parse_shadowsocks(config)
                if not ss: return None
                
                return {
                    "type": "shadowsocks",
                    "tag": f"ss-{uuid.uuid4().hex[:6]}",
                    "server": ss['address'],
                    "server_port": ss['port'],
                    "method": ss['method'],
                    "password": ss['password']
                }

            return None
        except:
            return None

    def process_configs(self):
        try:
            with open('configs/proxy_configs.txt', 'r') as f:
                configs = [c.strip() for c in f.readlines() if c.strip() and not c.startswith('//')]

            outbounds = []
            valid_tags = []

            for config in configs:
                converted = self.convert_to_singbox(config)
                if converted:
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
                        "type": "tun",
                        "interface_name": "tun0",
                        "mtu": 9000,
                        "stack": "mixed",
                        "endpoint_independent_nat": True,
                        "sniff": True
                    }
                ],
                "outbounds": [
                    {
                        "type": "selector",
                        "tag": "proxy",
                        "outbounds": ["auto"] + valid_tags + ["direct"]
                    },
                    {
                        "type": "urltest",
                        "tag": "auto",
                        "outbounds": valid_tags,
                        "url": "http://www.gstatic.com/generate_204",
                        "interval": "10m",
                        "tolerance": 50
                    },
                    *outbounds,
                    {"type": "direct", "tag": "direct"},
                    {"type": "block", "tag": "block"}
                ],
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
                            "tag": "geosite-ir",
                            "type": "remote",
                            "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/category-ir.srs"
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
                            "outbound": "direct",
                            "rule_set": ["geoip-ir", "geosite-ir"]
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
            print(f"Error: {str(e)}")

def main():
    ConfigToSingbox().process_configs()

if __name__ == '__main__':
    main()