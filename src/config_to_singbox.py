import json
import base64
import uuid
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
            
            return {
                'password': password,
                'address': host,
                'port': int(port),
                'params': parse_qs(path_part) if '?' in path_part else {}
            }
        except:
            return None

    def parse_hysteria2(self, config: str) -> Optional[Dict]:
        try:
            parsed = urlparse(config.replace('hysteria2://', '').replace('hy2://', ''))
            if not parsed.hostname or not parsed.port:
                return None
                
            params = parse_qs(parsed.query)
            auth = parsed.username or params.get('auth', [''])[0]
            sni = params.get('sni', [''])[0]
            
            if not auth:
                return None
                
            return {
                'address': parsed.hostname,
                'port': parsed.port,
                'auth': auth,
                'sni': sni
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
                if not vmess_data:
                    return None
                
                if not vmess_data.get('add') or not vmess_data.get('port') or not vmess_data.get('id'):
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
                        "server_name": vmess_data.get('sni', vmess_data.get('host', '')),
                        "insecure": True,
                        "disable_sni": False
                    },
                    "transport": {
                        "type": vmess_data.get('net', 'tcp'),
                        "path": vmess_data.get('path', ''),
                        "headers": {
                            "Host": vmess_data.get('host', '')
                        } if vmess_data.get('host') else {}
                    }
                }
                
            elif config.startswith('vless://'):
                vless_data = self.parse_vless(config)
                if not vless_data:
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
                        "server_name": vless_data['params'].get('sni', [''])[0],
                        "insecure": True,
                        "disable_sni": False
                    }
                }
                
            elif config.startswith('trojan://'):
                trojan_data = self.parse_trojan(config)
                if not trojan_data:
                    return None
                    
                return {
                    "type": "trojan",
                    "tag": f"trojan-{str(uuid.uuid4())[:8]}",
                    "server": trojan_data['address'],
                    "server_port": trojan_data['port'],
                    "password": trojan_data['password'],
                    "tls": {
                        "enabled": True,
                        "server_name": trojan_data['params'].get('sni', [''])[0],
                        "insecure": True,
                        "disable_sni": False
                    }
                }
                
            elif config.startswith(('hysteria2://', 'hy2://')):
                hy2_data = self.parse_hysteria2(config)
                if not hy2_data:
                    return None
                    
                return {
                    "type": "hysteria2",
                    "tag": f"hysteria2-{str(uuid.uuid4())[:8]}",
                    "server": hy2_data['address'],
                    "server_port": hy2_data['port'],
                    "password": hy2_data['auth'],
                    "tls": {
                        "enabled": True,
                        "server_name": hy2_data['sni'] or hy2_data['address'],
                        "insecure": True,
                        "disable_sni": False
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

    def create_base_config(self, outbounds: List[Dict]) -> Dict:
        proxy_outbounds = []
        for outbound in outbounds:
            if outbound and all(key in outbound for key in ['type', 'server', 'server_port']):
                proxy_outbounds.append(outbound)

        if not proxy_outbounds:
            return {}

        tags = [o['tag'] for o in proxy_outbounds]
        
        return {
            "dns": {
                "servers": [
                    {
                        "tag": "dns-remote",
                        "address": "https://8.8.8.8/dns-query",
                        "detour": "proxy"
                    },
                    {
                        "tag": "dns-local",
                        "address": "local",
                        "detour": "direct"
                    }
                ],
                "rules": [
                    {
                        "outbound": "any",
                        "server": "dns-local"
                    }
                ],
                "strategy": "prefer_ipv4"
            },
            "inbounds": [
                {
                    "type": "mixed",
                    "tag": "mixed-in",
                    "listen": "127.0.0.1",
                    "listen_port": 2080
                }
            ],
            "outbounds": [
                {
                    "type": "selector",
                    "tag": "proxy",
                    "outbounds": ["auto"] + tags,
                    "default": "auto"
                },
                {
                    "type": "urltest",
                    "tag": "auto",
                    "outbounds": tags,
                    "url": "https://www.gstatic.com/generate_204",
                    "interval": "5m",
                    "tolerance": 100
                }
            ] + proxy_outbounds + [
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
            ],
            "route": {
                "rules": [
                    {
                        "protocol": "dns",
                        "outbound": "dns-out"
                    }
                ],
                "final": "proxy",
                "auto_detect_interface": True
            }
        }

    def process_configs(self):
        try:
            with open('configs/proxy_configs.txt', 'r') as f:
                configs = f.read().strip().split('\n')

            singbox_configs = []
            for config in configs:
                config = config.strip()
                if not config or config.startswith('//'):
                    continue
                    
                converted = self.convert_to_singbox(config)
                if converted:
                    singbox_configs.append(converted)

            if singbox_configs:
                complete_config = self.create_base_config(singbox_configs)
                if complete_config:
                    with open(self.output_file, 'w') as f:
                        json.dump(complete_config, f, indent=2, ensure_ascii=False)

def main():
    converter = ConfigToSingbox()
    converter.process_configs()

if __name__ == '__main__':
    main()