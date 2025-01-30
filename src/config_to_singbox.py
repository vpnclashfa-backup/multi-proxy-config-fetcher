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
            encoded = config[8:].split('?')[0]
            padding = 4 - (len(encoded) % 4)
            encoded += '=' * padding
            decoded = base64.b64decode(encoded).decode('utf-8')
            return json.loads(decoded)
        except:
            return None

    def parse_vless(self, config: str) -> Optional[Dict]:
        try:
            url = urlparse(config)
            auth = url.username
            host = url.hostname
            port = url.port or 443
            params = parse_qs(url.query)
            
            return {
                'uuid': auth,
                'address': host,
                'port': port,
                'flow': params.get('flow', [''])[0],
                'sni': params.get('sni', [''])[0],
                'security': params.get('security', ['tls'])[0],
                'fp': params.get('fp', [''])[0]
            }
        except:
            return None

    def parse_trojan(self, config: str) -> Optional[Dict]:
        try:
            url = urlparse(config)
            password = url.username
            host = url.hostname
            port = url.port or 443
            params = parse_qs(url.query)
            
            return {
                'password': password,
                'address': host,
                'port': port,
                'sni': params.get('sni', [''])[0],
                'alpn': params.get('alpn', [''])[0]
            }
        except:
            return None

    def parse_hysteria2(self, config: str) -> Optional[Dict]:
        try:
            url = urlparse(config)
            auth = url.username
            host = url.hostname
            port = url.port or 443
            params = parse_qs(url.query)
            
            return {
                'auth': auth,
                'address': host,
                'port': port,
                'sni': params.get('sni', [''])[0],
                'obfs': params.get('obfs', [''])[0]
            }
        except:
            return None

    def parse_shadowsocks(self, config: str) -> Optional[Dict]:
        try:
            parts = config[5:].split('#', 1)
            decoded = base64.b64decode(parts[0].split('@')[0] + '==').decode()
            method, password = decoded.split(':', 1)
            server = parts[0].split('@')[1].split(':')[0]
            port = int(parts[0].split('@')[1].split(':')[1].split('/')[0])
            
            return {
                'method': method,
                'password': password,
                'address': server,
                'port': port
            }
        except:
            return None

    def convert_to_singbox(self, config: str) -> Optional[Dict]:
        try:
            # VMess
            if config.startswith('vmess://'):
                vmess = self.decode_vmess(config)
                if not vmess or 'add' not in vmess or 'port' not in vmess:
                    return None
                
                return {
                    "type": "vmess",
                    "tag": f"vmess-{str(uuid.uuid4())[:8]}",
                    "server": vmess['add'],
                    "server_port": int(vmess['port']),
                    "uuid": vmess['id'],
                    "security": vmess.get('scy', 'auto'),
                    "alter_id": int(vmess.get('aid', 0)),
                    "transport": {
                        "type": vmess.get('net', 'tcp'),
                        "host": vmess.get('host', ''),
                        "path": vmess.get('path', '')
                    },
                    "tls": {
                        "enabled": vmess.get('tls') == 'tls',
                        "server_name": vmess.get('sni', ''),
                        "insecure": not bool(vmess.get('sni'))
                    }
                }
            
            # VLESS
            elif config.startswith('vless://'):
                vless = self.parse_vless(config)
                if not vless or not vless['uuid']:
                    return None
                
                tls_config = {
                    "enabled": True,
                    "server_name": vless['sni'],
                    "insecure": not bool(vless['sni'])
                } if vless['security'] == 'tls' else {"enabled": False}
                
                return {
                    "type": "vless",
                    "tag": f"vless-{str(uuid.uuid4())[:8]}",
                    "server": vless['address'],
                    "server_port": vless['port'],
                    "uuid": vless['uuid'],
                    "flow": vless['flow'],
                    "tls": tls_config,
                    "transport": {
                        "type": "tcp",
                        "headers": {
                            "Host": [vless['sni']] if vless['sni'] else []
                        }
                    }
                }
            
            # Trojan
            elif config.startswith('trojan://'):
                trojan = self.parse_trojan(config)
                if not trojan or not trojan['password']:
                    return None
                
                return {
                    "type": "trojan",
                    "tag": f"trojan-{str(uuid.uuid4())[:8]}",
                    "server": trojan['address'],
                    "server_port": trojan['port'],
                    "password": trojan['password'],
                    "tls": {
                        "enabled": True,
                        "server_name": trojan['sni'],
                        "alpn": trojan['alpn'].split(',') if trojan['alpn'] else [],
                        "insecure": not bool(trojan['sni'])
                    }
                }
            
            # Hysteria2
            elif config.startswith(('hysteria2://', 'hy2://')):
                hy2 = self.parse_hysteria2(config)
                if not hy2 or not hy2['auth']:
                    return None
                
                return {
                    "type": "hysteria2",
                    "tag": f"hy2-{str(uuid.uuid4())[:8]}",
                    "server": hy2['address'],
                    "server_port": hy2['port'],
                    "password": hy2['auth'],
                    "tls": {
                        "enabled": True,
                        "server_name": hy2['sni'],
                        "insecure": not bool(hy2['sni'])
                    },
                    "obfs": {
                        "type": "salamander",
                        "password": hy2['obfs']
                    } if hy2['obfs'] else None
                }
            
            # Shadowsocks
            elif config.startswith('ss://'):
                ss = self.parse_shadowsocks(config)
                if not ss:
                    return None
                
                return {
                    "type": "shadowsocks",
                    "tag": f"ss-{str(uuid.uuid4())[:8]}",
                    "server": ss['address'],
                    "server_port": ss['port'],
                    "method": ss['method'],
                    "password": ss['password'],
                    "udp_over_tcp": False
                }
            
            return None
        
        except Exception as e:
            print(f"Conversion error: {str(e)}")
            return None

    def process_configs(self):
        try:
            with open('configs/proxy_configs.txt', 'r') as f:
                configs = [c.strip() for c in f.readlines() if c.strip() and not c.startswith('//')]

            valid_configs = []
            for config in configs:
                converted = self.convert_to_singbox(config)
                if converted:
                    # Validate required fields
                    if not converted.get("server") or not converted.get("server_port"):
                        continue
                    if converted["type"] in ["vless", "trojan"] and not converted.get("password") and not converted.get("uuid"):
                        continue
                    valid_configs.append(converted)

            singbox_json = {
                "outbounds": valid_configs
            }

            with open(self.output_file, 'w') as f:
                json.dump(singbox_json, f, indent=2, ensure_ascii=False)
            
            print(f"Converted {len(valid_configs)} valid configs")
        
        except Exception as e:
            print(f"Critical error: {str(e)}")

def main():
    converter = ConfigToSingbox()
    converter.process_configs()

if __name__ == '__main__':
    main()