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
                'params': params,
                'security': params.get('security', ['tls'])[0],
                'transport': params.get('type', ['tcp'])[0],
                'flow': params.get('flow', [''])[0]
            }
        except:
            return None

    def parse_trojan(self, config: str) -> Optional[Dict]:
        try:
            parts = config.replace('trojan://', '').split('@')
            if len(parts) != 2:
                return None
                
            password, server_info = parts
            host, path_part = server_info.split('?', 1) if '?' in server_info else (server_info, '')
            
            host, port = host.split(':')
            params = parse_qs(path_part) if '?' in server_info else {}
            
            return {
                'password': password,
                'address': host,
                'port': int(port),
                'params': params,
                'security': params.get('security', ['tls'])[0],
                'transport': params.get('type', ['tcp'])[0]
            }
        except:
            return None

    def parse_hysteria2(self, config: str) -> Optional[Dict]:
        try:
            url = urlparse(config.replace('hysteria2://', '').replace('hy2://', ''))
            params = parse_qs(url.query) if url.query else {}
            
            return {
                'auth': url.username or '',
                'address': url.hostname,
                'port': url.port,
                'params': params,
                'sni': params.get('sni', [''])[0],
                'insecure': params.get('insecure', [''])[0].lower() == 'true'
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
                    
                outbound = {
                    "type": "vmess",
                    "tag": f"vmess-{str(uuid.uuid4())[:8]}",
                    "server": vmess_data.get('add') or vmess_data.get('address'),
                    "server_port": int(vmess_data.get('port')),
                    "uuid": vmess_data.get('id'),
                    "security": vmess_data.get('scy', 'auto'),
                    "alter_id": int(vmess_data.get('aid', 0)),
                    "transport": {
                        "type": vmess_data.get('net', 'tcp'),
                        "path": vmess_data.get('path', ''),
                        "headers": {
                            "Host": vmess_data.get('host', '')
                        } if vmess_data.get('host') else {}
                    }
                }
                
                if vmess_data.get('tls') == 'tls':
                    outbound["tls"] = {
                        "enabled": True,
                        "server_name": vmess_data.get('sni', ''),
                        "insecure": True
                    }
                
                return outbound
                
            elif config.startswith('vless://'):
                vless_data = self.parse_vless(config)
                if not vless_data:
                    return None
                    
                outbound = {
                    "type": "vless",
                    "tag": f"vless-{str(uuid.uuid4())[:8]}",
                    "server": vless_data['address'],
                    "server_port": vless_data['port'],
                    "uuid": vless_data['uuid'],
                    "flow": vless_data['flow'],
                    "transport": {
                        "type": vless_data['transport'],
                        "path": vless_data['path'],
                        "headers": {
                            "Host": vless_data['params'].get('host', [''])[0]
                        } if 'host' in vless_data['params'] else {}
                    }
                }
                
                if vless_data['security'] == 'tls':
                    outbound["tls"] = {
                        "enabled": True,
                        "server_name": vless_data['params'].get('sni', [''])[0],
                        "insecure": True
                    }
                
                return outbound
                
            elif config.startswith('trojan://'):
                trojan_data = self.parse_trojan(config)
                if not trojan_data:
                    return None
                    
                outbound = {
                    "type": "trojan",
                    "tag": f"trojan-{str(uuid.uuid4())[:8]}",
                    "server": trojan_data['address'],
                    "server_port": trojan_data['port'],
                    "password": trojan_data['password'],
                    "transport": {
                        "type": trojan_data['transport']
                    }
                }
                
                if trojan_data['security'] == 'tls':
                    outbound["tls"] = {
                        "enabled": True,
                        "server_name": trojan_data['params'].get('sni', [''])[0],
                        "insecure": True
                    }
                
                return outbound
                
            elif config.startswith(('hysteria2://', 'hy2://')):
                hy2_data = self.parse_hysteria2(config)
                if not hy2_data or not hy2_data['address'] or not hy2_data['port']:
                    return None
                    
                outbound = {
                    "type": "hysteria2",
                    "tag": f"hysteria2-{str(uuid.uuid4())[:8]}",
                    "server": hy2_data['address'],
                    "server_port": hy2_data['port'],
                    "password": hy2_data['auth'],
                    "tls": {
                        "enabled": True,
                        "server_name": hy2_data['sni'] or hy2_data['address'],
                        "insecure": hy2_data['insecure']
                    }
                }
                
                if 'obfs' in hy2_data['params']:
                    outbound["obfs"] = {
                        "type": "salamander",
                        "password": hy2_data['params']['obfs'][0]
                    }
                
                return outbound
                
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

            singbox_json = {
                "outbounds": singbox_configs,
                "experimental": {
                    "clash_api": {
                        "external_controller": "127.0.0.1:9090",
                        "external_ui": "yacd",
                        "secret": "",
                        "default_mode": "rule"
                    }
                }
            }

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