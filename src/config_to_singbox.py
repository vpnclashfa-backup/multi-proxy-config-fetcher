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
            return json.loads(decoded)
        except:
            return None

    def parse_vless(self, config: str) -> Optional[Dict]:
        try:
            parts = config.replace('vless://', '').split('@')
            if len(parts) != 2:
                return None
            
            user_info, server_info = parts
            host, path_part = server_info.split('/', 1) if '/' in server_info else (server_info, '')
            host, port = host.split(':')
            
            if '?' in path_part:
                path, params = path_part.split('?', 1)
                params = parse_qs(params)
            else:
                path, params = path_part, {}
                
            return {
                'uuid': user_info,
                'address': host,
                'port': int(port),
                'path': f'/{path}' if path else '/',
                'params': params
            }
        except:
            return None

    def parse_trojan(self, config: str) -> Optional[Dict]:
        try:
            parts = config.replace('trojan://', '').split('@')
            if len(parts) != 2:
                return None
                
            password, server_info = parts
            host, path_part = server_info.split('/', 1) if '/' in server_info else (server_info, '')
            host, port = host.split(':')
            
            sni = None
            if '?' in path_part:
                params = dict(pair.split('=') for pair in path_part.split('?')[1].split('&'))
                sni = params.get('sni')
            
            return {
                'password': password,
                'address': host,
                'port': int(port),
                'sni': sni
            }
        except:
            return None

    def parse_hysteria2(self, config: str) -> Optional[Dict]:
        try:
            url = urlparse(config.replace('hysteria2://', '').replace('hy2://', ''))
            if not url.hostname or not url.port:
                return None
                
            query = dict(pair.split('=') for pair in url.query.split('&')) if url.query else {}
            
            return {
                'address': url.hostname,
                'port': url.port,
                'password': url.username or query.get('password', ''),
                'sni': query.get('sni', url.hostname)
            }
        except:
            return None

    def parse_shadowsocks(self, config: str) -> Optional[Dict]:
        try:
            parts = config.replace('ss://', '').split('@')
            if len(parts) != 2:
                return None
                
            method_pass = base64.b64decode(parts[0]).decode('utf-8')
            method, password = method_pass.split(':')
            
            server_parts = parts[1].split('#')[0]
            host, port = server_parts.split(':')
            
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
                vmess_data = self.decode_vmess(config)
                if not vmess_data or not vmess_data.get('add') or not vmess_data.get('port') or not vmess_data.get('id'):
                    return None
                
                return {
                    "type": "vmess",
                    "tag": f"vmess-{str(uuid.uuid4())[:8]}",
                    "server": vmess_data['add'],
                    "server_port": int(vmess_data['port']),
                    "uuid": vmess_data['id'],
                    "security": vmess_data.get('scy', 'auto'),
                    "alter_id": int(vmess_data.get('aid', 0)),
                    "tls": {
                        "enabled": vmess_data.get('tls') == 'tls',
                        "insecure": True,
                        "server_name": vmess_data.get('sni', vmess_data['add'])
                    }
                }

            elif config.startswith('vless://'):
                vless_data = self.parse_vless(config)
                if not vless_data or not vless_data['address'] or not vless_data['port']:
                    return None
                
                return {
                    "type": "vless",
                    "tag": f"vless-{str(uuid.uuid4())[:8]}",
                    "server": vless_data['address'],
                    "server_port": vless_data['port'],
                    "uuid": vless_data['uuid'],
                    "flow": vless_data['params'].get('flow', [''])[0],
                    "tls": {
                        "enabled": True,
                        "insecure": True,
                        "server_name": vless_data['params'].get('sni', [vless_data['address']])[0]
                    }
                }

            elif config.startswith('trojan://'):
                trojan_data = self.parse_trojan(config)
                if not trojan_data or not trojan_data['address'] or not trojan_data['port']:
                    return None
                
                return {
                    "type": "trojan",
                    "tag": f"trojan-{str(uuid.uuid4())[:8]}",
                    "server": trojan_data['address'],
                    "server_port": trojan_data['port'],
                    "password": trojan_data['password'],
                    "tls": {
                        "enabled": True,
                        "insecure": True,
                        "server_name": trojan_data['sni'] or trojan_data['address']
                    }
                }

            elif config.startswith(('hysteria2://', 'hy2://')):
                hy2_data = self.parse_hysteria2(config)
                if not hy2_data or not hy2_data['address'] or not hy2_data['port'] or not hy2_data['password']:
                    return None
                
                return {
                    "type": "hysteria2",
                    "tag": f"hysteria2-{str(uuid.uuid4())[:8]}",
                    "server": hy2_data['address'],
                    "server_port": hy2_data['port'],
                    "password": hy2_data['password'],
                    "tls": {
                        "enabled": True,
                        "insecure": True,
                        "server_name": hy2_data['sni']
                    }
                }

            elif config.startswith('ss://'):
                ss_data = self.parse_shadowsocks(config)
                if not ss_data or not ss_data['address'] or not ss_data['port']:
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
                    "servers": [
                        {
                            "tag": "dns-direct",
                            "address": "1.1.1.1",
                            "detour": "direct"
                        }
                    ],
                    "rules": [],
                    "strategy": "prefer_ipv4",
                    "disable_cache": True
                },
                "inbounds": [
                    {
                        "type": "mixed",
                        "tag": "mixed-in",
                        "listen": "127.0.0.1",
                        "listen_port": 2080,
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
                    {
                        "type": "direct",
                        "tag": "direct"
                    },
                    {
                        "type": "block",
                        "tag": "block"
                    },
                    {
                        "type": "dns",
                        "tag": "dns-out"
                    }
                ] + outbounds,
                "route": {
                    "rules": [
                        {
                            "protocol": ["dns"],
                            "outbound": "dns-out"
                        },
                        {
                            "protocol": ["quic"],
                            "outbound": "block"
                        }
                    ],
                    "auto_detect_interface": True,
                    "final": "proxy"
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