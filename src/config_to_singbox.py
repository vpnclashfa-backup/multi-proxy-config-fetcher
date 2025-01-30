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
            decoded = base64.b64decode(encoded + '=' * (-len(encoded) % 4)).decode('utf-8')
            data = json.loads(decoded)
            return data if all(k in data for k in ['add', 'port', 'id']) else None
        except:
            return None

    def parse_vless(self, config: str) -> Optional[Dict]:
        try:
            url = urlparse(config)
            if url.scheme != 'vless':
                return None
            
            userinfo = url.username
            if not userinfo:
                return None
                
            params = dict(pair.split('=') for pair in url.query.split('&')) if url.query else {}
            return {
                'uuid': userinfo,
                'address': url.hostname,
                'port': url.port,
                'params': params,
                'path': url.path or '/'
            }
        except:
            return None

    def parse_trojan(self, config: str) -> Optional[Dict]:
        try:
            url = urlparse(config)
            if url.scheme != 'trojan':
                return None
            
            params = dict(pair.split('=') for pair in url.query.split('&')) if url.query else {}
            return {
                'password': url.username,
                'address': url.hostname,
                'port': url.port,
                'params': params
            }
        except:
            return None

    def parse_hysteria2(self, config: str) -> Optional[Dict]:
        try:
            url = urlparse(config)
            if url.scheme not in ['hysteria2', 'hy2']:
                return None
                
            params = dict(pair.split('=') for pair in url.query.split('&')) if url.query else {}
            password = url.username or params.get('password')
            auth = password or params.get('auth')
            
            return {
                'address': url.hostname,
                'port': url.port,
                'auth': auth,
                'params': params
            }
        except:
            return None

    def parse_shadowsocks(self, config: str) -> Optional[Dict]:
        try:
            if '#' in config:
                config = config.split('#')[0]
            
            url = urlparse(config)
            if url.scheme != 'ss':
                return None
                
            user_info = base64.b64decode(url.username + '=' * (-len(url.username) % 4)).decode('utf-8')
            method, password = user_info.split(':', 1)
            
            return {
                'method': method,
                'password': password,
                'address': url.hostname,
                'port': url.port
            }
        except:
            return None

    def convert_to_singbox(self, config: str) -> Optional[Dict]:
        try:
            if config.startswith('vmess://'):
                vmess_data = self.decode_vmess(config)
                if not vmess_data:
                    return None
                
                outbound = {
                    "type": "vmess",
                    "tag": f"vmess-{str(uuid.uuid4())[:8]}",
                    "server": vmess_data['add'],
                    "server_port": int(vmess_data['port']),
                    "uuid": vmess_data['id'],
                    "security": vmess_data.get('scy', 'auto'),
                    "alter_id": int(vmess_data.get('aid', 0))
                }

                if vmess_data.get('tls') == 'tls':
                    outbound["tls"] = {
                        "enabled": True,
                        "insecure": True,
                        "server_name": vmess_data.get('sni', '') or vmess_data['add']
                    }

                transport_type = vmess_data.get('net', '')
                if transport_type == 'ws':
                    outbound["transport"] = {
                        "type": "ws",
                        "path": vmess_data.get('path', '/'),
                        "headers": {
                            "Host": vmess_data.get('host', '') or vmess_data.get('sni', '') or vmess_data['add']
                        }
                    }

                return outbound

            elif config.startswith('vless://'):
                vless_data = self.parse_vless(config)
                if not vless_data:
                    return None
                
                params = vless_data['params']
                outbound = {
                    "type": "vless",
                    "tag": f"vless-{str(uuid.uuid4())[:8]}",
                    "server": vless_data['address'],
                    "server_port": vless_data['port'],
                    "uuid": vless_data['uuid'],
                    "flow": params.get('flow', [''])[0],
                    "tls": {
                        "enabled": True,
                        "insecure": True,
                        "server_name": params.get('sni', [''])[0] or vless_data['address'],
                        "utls": {
                            "enabled": True,
                            "fingerprint": params.get('fp', ['chrome'])[0]
                        }
                    }
                }

                transport_type = params.get('type', [''])[0]
                if transport_type == 'ws':
                    outbound["transport"] = {
                        "type": "ws",
                        "path": vless_data['path'],
                        "headers": {
                            "Host": params.get('host', [vless_data['address']])[0]
                        }
                    }

                return outbound

            elif config.startswith('trojan://'):
                trojan_data = self.parse_trojan(config)
                if not trojan_data:
                    return None
                
                params = trojan_data['params']
                outbound = {
                    "type": "trojan",
                    "tag": f"trojan-{str(uuid.uuid4())[:8]}",
                    "server": trojan_data['address'],
                    "server_port": trojan_data['port'],
                    "password": trojan_data['password'],
                    "tls": {
                        "enabled": True,
                        "insecure": True,
                        "server_name": params.get('sni', [''])[0] or trojan_data['address'],
                        "utls": {
                            "enabled": True,
                            "fingerprint": params.get('fp', ['chrome'])[0]
                        }
                    }
                }

                transport_type = params.get('type', [''])[0]
                if transport_type == 'ws':
                    outbound["transport"] = {
                        "type": "ws",
                        "path": params.get('path', ['/'])[0],
                        "headers": {
                            "Host": params.get('host', [trojan_data['address']])[0]
                        }
                    }

                return outbound

            elif config.startswith(('hysteria2://', 'hy2://')):
                hy2_data = self.parse_hysteria2(config)
                if not hy2_data:
                    return None
                
                params = hy2_data['params']
                return {
                    "type": "hysteria2",
                    "tag": f"hysteria2-{str(uuid.uuid4())[:8]}",
                    "server": hy2_data['address'],
                    "server_port": hy2_data['port'],
                    "password": hy2_data['auth'],
                    "tls": {
                        "enabled": True,
                        "insecure": True,
                        "server_name": params.get('sni', [''])[0] or hy2_data['address']
                    }
                }

            elif config.startswith('ss://'):
                ss_data = self.parse_shadowsocks(config)
                if not ss_data:
                    return None
                
                return {
                    "type": "shadowsocks",
                    "tag": f"ss-{str(uuid.uuid4())[:8]}",
                    "server": ss_data['address'],
                    "server_port": ss_data['port'],
                    "method": ss_data['method'],
                    "password": ss_data['password']
                }

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
                config = config.strip()
                if not config or config.startswith('//'):
                    continue
                    
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
                        "tag": "tun-in",
                        "interface_name": "tun0",
                        "inet4_address": "172.19.0.1/30",
                        "inet6_address": "fdfe:dcba:9876::1/126",
                        "mtu": 9000,
                        "auto_route": True,
                        "strict_route": False,
                        "endpoint_independent_nat": False,
                        "stack": "system",
                        "platform": {
                            "http_proxy": {
                                "enabled": True,
                                "server": "127.0.0.1",
                                "server_port": 2080
                            }
                        },
                        "sniff": True
                    },
                    {
                        "type": "mixed",
                        "tag": "mixed-in",
                        "listen": "127.0.0.1",
                        "listen_port": 2080,
                        "sniff": True,
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
                            "tag": "geosite-ads",
                            "type": "remote",
                            "format": "binary",
                            "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/category-ads-all.srs",
                            "download_detour": "direct"
                        },
                        {
                            "tag": "geosite-private",
                            "type": "remote",
                            "format": "binary",
                            "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/private.srs",
                            "download_detour": "direct"
                        },
                        {
                            "tag": "geosite-ir",
                            "type": "remote",
                            "format": "binary",
                            "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/category-ir.srs",
                            "download_detour": "direct"
                        },
                        {
                            "tag": "geoip-private",
                            "type": "remote",
                            "format": "binary",
                            "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/private.srs",
                            "download_detour": "direct"
                        },
                        {
                            "tag": "geoip-ir",
                            "type": "remote",
                            "format": "binary",
                            "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/ir.srs",
                            "download_detour": "direct"
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
                            "protocol": "dns",
                            "outbound": "dns-out"
                        },
                        {
                            "rule_set": [
                                "geoip-private",
                                "geosite-private",
                                "geosite-ir",
                                "geoip-ir"
                            ],
                            "outbound": "direct"
                        },
                        {
                            "rule_set": ["geosite-ads"],
                            "outbound": "block"
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