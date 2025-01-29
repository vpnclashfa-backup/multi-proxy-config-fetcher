import json
import base64
import uuid
import re
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs, unquote

class ConfigToSingbox:
    def __init__(self):
        self.output_file = 'configs/singbox_configs.txt'
        
    def decode_vmess(self, config: str) -> Optional[Dict]:
        try:
            # Remove 'vmess://' prefix and decode base64
            encoded = config.replace('vmess://', '')
            decoded = base64.b64decode(encoded).decode('utf-8')
            return json.loads(decoded)
        except:
            return None

    def parse_vless(self, config: str) -> Optional[Dict]:
        try:
            # Remove 'vless://' prefix
            parts = config.replace('vless://', '').split('@')
            if len(parts) != 2:
                return None
            
            user_info, server_info = parts
            host, path_part = server_info.split('/', 1) if '/' in server_info else (server_info, '')
            
            # Parse host and port
            host, port = host.split(':')
            
            # Parse path and parameters
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
            # Remove 'trojan://' prefix
            parts = config.replace('trojan://', '').split('@')
            if len(parts) != 2:
                return None
                
            password, server_info = parts
            host, path_part = server_info.split('/', 1) if '/' in server_info else (server_info, '')
            
            # Parse host and port
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
            # Remove 'hysteria2://' prefix
            url = urlparse(config.replace('hysteria2://', ''))
            auth = url.username or ''
            
            return {
                'auth': auth,
                'address': url.hostname,
                'port': url.port,
                'params': parse_qs(url.query)
            }
        except:
            return None

    def parse_shadowsocks(self, config: str) -> Optional[Dict]:
        try:
            # Remove 'ss://' prefix and split into parts
            parts = config.replace('ss://', '').split('@')
            if len(parts) != 2:
                return None
                
            # Decode method and password
            method_pass = base64.b64decode(parts[0]).decode('utf-8')
            method, password = method_pass.split(':')
            
            # Parse server info
            server_parts = parts[1].split('#')[0]  # Remove remarks
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
                    
                return {
                    "type": "vmess",
                    "tag": f"vmess-{str(uuid.uuid4())[:8]}",
                    "server": vmess_data.get('add') or vmess_data.get('address'),
                    "server_port": int(vmess_data.get('port')),
                    "uuid": vmess_data.get('id'),
                    "security": vmess_data.get('scy', 'auto'),
                    "alter_id": int(vmess_data.get('aid', 0)),
                    "tls": {
                        "enabled": vmess_data.get('tls') == 'tls',
                        "server_name": vmess_data.get('sni', '')
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
                        "server_name": vless_data['params'].get('sni', [''])[0]
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
                        "server_name": trojan_data['params'].get('sni', [''])[0]
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
                        "server_name": hy2_data['params'].get('sni', [''])[0]
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
        except Exception as e:
            print(f"Error converting config: {str(e)}")
            return None

    def process_configs(self):
        try:
            # Read configs from proxy_configs.txt
            with open('configs/proxy_configs.txt', 'r') as f:
                configs = f.read().strip().split('\n')

            # Convert configs to sing-box format
            singbox_configs = []
            for config in configs:
                config = config.strip()
                if not config or config.startswith('//'):
                    continue
                    
                converted = self.convert_to_singbox(config)
                if converted:
                    singbox_configs.append(converted)

            # Create sing-box configuration
            singbox_json = {
                "outbounds": singbox_configs
            }

            # Save to file
            with open(self.output_file, 'w') as f:
                json.dump(singbox_json, f, indent=2, ensure_ascii=False)
                
            print(f"Successfully converted {len(singbox_configs)} configs to sing-box format")
            
        except Exception as e:
            print(f"Error processing configs: {str(e)}")

def main():
    converter = ConfigToSingbox()
    converter.process_configs()

if __name__ == '__main__':
    main()