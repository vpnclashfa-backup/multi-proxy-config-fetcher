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
                'security': params.get('security', ['tls'])[0],
                'sni': params.get('sni', [address])[0],
                'fp': params.get('fp', [''])[0],
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
                'fp': params.get('fp', [''])[0],
                'type': params.get('type', ['tcp'])[0],
                'path': params.get('path', [''])[0]
            }
        except:
            return None

    def parse_hysteria2(self, config: str) -> Optional[Dict]:
        try:
            config = config.replace('hysteria2://', 'hy2://')
            url = urlparse(config)
            if url.scheme != 'hy2' or not url.hostname:
                return None
            
            port = url.port or 443
            params = parse_qs(url.query)
            
            return {
                'password': url.username,
                'address': url.hostname,
                'port': port,
                'sni': params.get('sni', [url.hostname])[0],
                'obfs': params.get('obfs', [''])[0],
                'obfs-password': params.get('obfs-password', [''])[0],
                'insecure': params.get('insecure', ['0'])[0] == '1'
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
            else:
                raise ValueError
            
            return {
                'method': method,
                'password': password,
                'address': host,
                'port': int(port)
            }
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
                    },
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
                        "enabled": vless['security'] == 'tls',
                        "server_name": vless['sni'],
                        "insecure": False,
                        "alpn": ["h2", "http/1.1"]
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

            elif config.startswith(('hysteria2://', 'hy2://')):
                hy2 = self.parse_hysteria2(config)
                if not hy2: return None
                
                return {
                    "type": "hysteria2",
                    "tag": f"hy2-{uuid.uuid4().hex[:6]}",
                    "server": hy2['address'],
                    "server_port": hy2['port'],
                    "password": hy2['password'],
                    "obfs": {
                        "type": "salamander",
                        "password": hy2['obfs-password']
                    } if hy2['obfs'] else None,
                    "tls": {
                        "enabled": True,
                        "server_name": hy2['sni'],
                        "insecure": hy2['insecure']
                    }
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
                    "servers": [
                        {"address": "tls://8.8.8.8", "tag": "dns-foreign"},
                        {"address": "local", "tag": "dns-direct"}
                    ]
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
                        "outbounds": ["auto"] + valid_tags
                    },
                    {
                        "type": "urltest",
                        "tag": "auto",
                        "outbounds": valid_tags,
                        "interval": "10m",
                        "tolerance": 50
                    },
                    *outbounds,
                    {"type": "direct", "tag": "direct"},
                    {"type": "block", "tag": "block"}
                ],
                "route": {
                    "auto_detect_interface": True,
                    "rules": [
                        {
                            "protocol": "dns",
                            "outbound": "dns-foreign"
                        },
                        {
                            "geoip": ["ir"],
                            "outbound": "direct"
                        },
                        {
                            "geosite": ["category-ads"],
                            "outbound": "block"
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