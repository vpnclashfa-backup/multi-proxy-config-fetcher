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
            encoded = config[8:].split('#')[0].split('?')[0]
            padding = '=' * (4 - (len(encoded) % 4))
            decoded = base64.b64decode(encoded + padding).decode('utf-8')
            return json.loads(decoded)
        except:
            return None

    def parse_vless(self, config: str) -> Optional[Dict]:
        try:
            url = urlparse(config)
            netloc = url.netloc.split('@')
            if len(netloc) != 2:
                return None
            
            uuid_part, server_part = netloc
            server, port = server_part.split(':') if ':' in server_part else (server_part, '443')
            
            params = parse_qs(url.query)
            return {
                'uuid': uuid_part,
                'address': server,
                'port': int(port),
                'flow': params.get('flow', [''])[0],
                'encryption': params.get('encryption', ['none'])[0],
                'security': params.get('security', ['tls'])[0],
                'sni': params.get('sni', [''])[0],
                'fp': params.get('fp', [''])[0],
                'alpn': params.get('alpn', [''])[0].split(',')
            }
        except:
            return None

    def parse_trojan(self, config: str) -> Optional[Dict]:
        try:
            url = urlparse(config)
            password = url.username
            server = url.hostname
            port = url.port or 443
            
            params = parse_qs(url.query)
            return {
                'password': unquote(password),
                'address': server,
                'port': port,
                'sni': params.get('sni', [''])[0],
                'alpn': params.get('alpn', [''])[0].split(','),
                'fp': params.get('fp', [''])[0]
            }
        except:
            return None

    def parse_hysteria2(self, config: str) -> Optional[Dict]:
        try:
            url = urlparse(config)
            auth = url.username
            server = url.hostname
            port = url.port or 443
            
            params = parse_qs(url.query)
            return {
                'auth': unquote(auth),
                'address': server,
                'port': port,
                'sni': params.get('sni', [''])[0],
                'alpn': params.get('alpn', [''])[0].split(','),
                'obfs': params.get('obfs', [''])[0],
                'obfs-password': params.get('obfs-password', [''])[0]
            }
        except:
            return None

    def parse_shadowsocks(self, config: str) -> Optional[Dict]:
        try:
            url = urlparse(config)
            userinfo = base64.b64decode(url.username).decode('utf-8')
            method, password = userinfo.split(':', 1)
            
            return {
                'method': method,
                'password': password,
                'address': url.hostname,
                'port': url.port or 8388,
                'plugin': url.fragment if url.fragment else ''
            }
        except:
            return None

    def convert_to_singbox(self, config: str) -> Optional[Dict]:
        try:
            # VMess
            if config.startswith('vmess://'):
                vmess_data = self.decode_vmess(config)
                if not vmess_data or 'add' not in vmess_data:
                    return None
                
                tls = {
                    "enabled": vmess_data.get('tls') == 'tls',
                    "server_name": vmess_data.get('sni') or vmess_data.get('host', ''),
                    "alpn": vmess_data.get('alpn', '').split(',') if vmess_data.get('alpn') else []
                }
                
                transport = {
                    "type": "tcp",
                    "host": [vmess_data.get('host', '')],
                    "path": vmess_data.get('path', '')
                }
                
                if vmess_data.get('net') == 'ws':
                    transport["type"] = "ws"
                    transport["path"] = vmess_data.get('path', '')
                    transport["headers"] = {
                        "Host": vmess_data.get('host', '')
                    }
                
                return {
                    "type": "vmess",
                    "tag": f"vmess-{uuid.uuid4().hex[:6]}",
                    "server": vmess_data['add'],
                    "server_port": int(vmess_data['port']),
                    "uuid": vmess_data['id'],
                    "security": vmess_data.get('scy', 'auto'),
                    "alterId": int(vmess_data.get('aid', 0)),
                    "transport": transport,
                    "tls": tls if tls["enabled"] else None
                }
            
            # VLESS
            elif config.startswith('vless://'):
                vless_data = self.parse_vless(config)
                if not vless_data or not vless_data['uuid']:
                    return None
                
                tls = {
                    "enabled": vless_data['security'] == 'tls',
                    "server_name": vless_data['sni'],
                    "alpn": vless_data['alpn'],
                    "fingerprint": vless_data['fp']
                } if vless_data['security'] == 'tls' else None
                
                return {
                    "type": "vless",
                    "tag": f"vless-{uuid.uuid4().hex[:6]}",
                    "server": vless_data['address'],
                    "server_port": vless_data['port'],
                    "uuid": vless_data['uuid'],
                    "flow": vless_data['flow'],
                    "encryption": vless_data['encryption'],
                    "transport": {"type": "tcp"},
                    "tls": tls
                }
            
            # Trojan
            elif config.startswith('trojan://'):
                trojan_data = self.parse_trojan(config)
                if not trojan_data or not trojan_data['password']:
                    return None
                
                tls = {
                    "enabled": True,
                    "server_name": trojan_data['sni'],
                    "alpn": trojan_data['alpn'],
                    "fingerprint": trojan_data['fp']
                }
                
                return {
                    "type": "trojan",
                    "tag": f"trojan-{uuid.uuid4().hex[:6]}",
                    "server": trojan_data['address'],
                    "server_port": trojan_data['port'],
                    "password": trojan_data['password'],
                    "tls": tls,
                    "transport": {"type": "tcp"}
                }
            
            # Hysteria2
            elif config.startswith(('hysteria2://', 'hy2://')):
                hy2_data = self.parse_hysteria2(config)
                if not hy2_data or not hy2_data['auth']:
                    return None
                
                obfs = {
                    "type": "salamander",
                    "password": hy2_data['obfs-password']
                } if hy2_data['obfs'] else None
                
                return {
                    "type": "hysteria2",
                    "tag": f"hy2-{uuid.uuid4().hex[:6]}",
                    "server": hy2_data['address'],
                    "server_port": hy2_data['port'],
                    "password": hy2_data['auth'],
                    "obfs": obfs,
                    "tls": {
                        "enabled": True,
                        "server_name": hy2_data['sni'],
                        "alpn": hy2_data['alpn']
                    }
                }
            
            # Shadowsocks
            elif config.startswith('ss://'):
                ss_data = self.parse_shadowsocks(config)
                if not ss_data or not ss_data['method']:
                    return None
                
                plugin = {
                    "type": ss_data['plugin'].split('-')[0],
                    "host": ss_data['plugin'].split('=')[1]
                } if 'plugin' in ss_data and ss_data['plugin'] else None
                
                return {
                    "type": "shadowsocks",
                    "tag": f"ss-{uuid.uuid4().hex[:6]}",
                    "server": ss_data['address'],
                    "server_port": ss_data['port'],
                    "method": ss_data['method'],
                    "password": ss_data['password'],
                    "plugin": plugin
                }
            
            return None
        
        except Exception as e:
            print(f"Conversion error: {str(e)}")
            return None

    def process_configs(self):
        try:
            with open('configs/proxy_configs.txt', 'r') as f:
                configs = [c.strip() for c in f.read().splitlines() if c.strip() and not c.startswith('//')]

            singbox_configs = []
            for config in configs:
                converted = self.convert_to_singbox(config)
                if converted:
                    # حذف فیلدهای خالی
                    converted = {k: v for k, v in converted.items() if v not in (None, '', [])}
                    singbox_configs.append(converted)

            # ساختار اصلی Sing-box
            final_config = {
                "outbounds": singbox_configs,
                "route": {
                    "rules": [
                        {
                            "geosite": ["category-ads-all"],
                            "outbound": "block"
                        }
                    ]
                }
            }

            with open(self.output_file, 'w') as f:
                json.dump(final_config, f, indent=2, ensure_ascii=False)
            
            print(f"Converted {len(singbox_configs)} configs successfully")
            
        except Exception as e:
            print(f"Error processing configs: {str(e)}")

def main():
    converter = ConfigToSingbox()
    converter.process_configs()

if __name__ == '__main__':
    main()