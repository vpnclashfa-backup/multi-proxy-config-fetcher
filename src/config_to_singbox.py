import json
import base64
import uuid
from urllib.parse import urlparse, parse_qs

class ConfigToSingbox:
    def __init__(self):
        self.output_file = 'configs/singbox_configs.json'
    
    def decode_vmess(self, config: str):
        try:
            encoded = config.replace('vmess://', '')
            decoded = base64.b64decode(encoded).decode('utf-8')
            return json.loads(decoded)
        except Exception:
            return None

    def parse_vless(self, config: str):
        try:
            url = urlparse(config)
            if url.scheme.lower() != 'vless' or not url.hostname:
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
        except Exception:
            return None

    def parse_trojan(self, config: str):
        try:
            url = urlparse(config)
            if url.scheme.lower() != 'trojan' or not url.hostname:
                return None
            port = url.port or 443
            params = parse_qs(url.query)
            return {
                'password': url.username,
                'address': url.hostname,
                'port': port,
                'sni': params.get('sni', [url.hostname])[0],
                'alpn': params.get('alpn', [''])[0].split(','),
                'type': params.get('type', ['tcp'])[0],
                'path': params.get('path', [''])[0]
            }
        except Exception:
            return None

    def parse_hysteria2(self, config: str):
        try:
            url = urlparse(config)
            if url.scheme.lower() not in ['hysteria2', 'hy2'] or not url.hostname or not url.port:
                return None
            query = dict(pair.split('=') for pair in url.query.split('&')) if url.query else {}
            return {
                'address': url.hostname,
                'port': url.port,
                'password': url.username or query.get('password', ''),
                'sni': query.get('sni', url.hostname),
                'obfs': query.get('obfs', '')
            }
        except Exception:
            return None

    def parse_shadowsocks(self, config: str):
        try:
            parts = config.replace('ss://', '').split('@')
            if len(parts) != 2:
                return None
            method_pass = base64.b64decode(parts[0] + '==').decode('utf-8')
            method, password = method_pass.split(':', 1)
            server_parts = parts[1].split('#')[0]
            host, port = server_parts.split(':')
            return {
                'method': method,
                'password': password,
                'address': host,
                'port': int(port)
            }
        except Exception:
            return None

    def convert_to_singbox(self, config: str):
        try:
            config_lower = config.lower()
            if config_lower.startswith('vmess://'):
                vmess_data = self.decode_vmess(config)
                if not vmess_data or not vmess_data.get('add') or not vmess_data.get('port') or not vmess_data.get('id'):
                    return None
                transport = {}
                if vmess_data.get('net') in ['ws', 'http']:
                    transport.update({
                        "type": vmess_data['net'],
                        "path": vmess_data.get('path', ''),
                        "headers": {"Host": vmess_data.get('host', '')} if vmess_data.get('host') else {}
                    })
                return {
                    "type": "vmess",
                    "tag": f"vmess-{str(uuid.uuid4())[:8]}",
                    "server": vmess_data['add'],
                    "server_port": vmess_data['port'],
                    "uuid": vmess_data['id'],
                    "security": vmess_data.get('scy', 'auto'),
                    "transport": transport,
                    "tls": {
                        "enabled": vmess_data.get('tls') == 'tls',
                        "server_name": vmess_data.get('sni', vmess_data['add'])
                    }
                }

            elif config_lower.startswith('vless://'):
                vless_data = self.parse_vless(config)
                if not vless_data:
                    return None
                transport = {}
                if vless_data['type'] == 'ws':
                    transport = {
                        "type": "ws",
                        "path": vless_data.get('path', ''),
                        "headers": {"Host": vless_data.get('host', '')} if vless_data.get('host') else {}
                    }
                return {
                    "type": "vless",
                    "tag": f"vless-{str(uuid.uuid4())[:8]}",
                    "server": vless_data['address'],
                    "server_port": vless_data['port'],
                    "uuid": vless_data['uuid'],
                    "flow": vless_data['flow'],
                    "tls": {
                        "enabled": True,
                        "server_name": vless_data['sni']
                    },
                    "transport": transport
                }

            elif config_lower.startswith('trojan://'):
                trojan_data = self.parse_trojan(config)
                if not trojan_data:
                    return None
                transport = {}
                if trojan_data['type'] != 'tcp':
                    transport = {
                        "type": trojan_data['type'],
                        "path": trojan_data.get('path', ''),
                        "headers": {"Host": trojan_data.get('host', '')} if trojan_data.get('host') else {}
                    }
                return {
                    "type": "trojan",
                    "tag": f"trojan-{str(uuid.uuid4())[:8]}",
                    "server": trojan_data['address'],
                    "server_port": trojan_data['port'],
                    "password": trojan_data['password'],
                    "tls": {
                        "enabled": True,
                        "server_name": trojan_data['sni'],
                        "alpn": trojan_data['alpn']
                    },
                    "transport": transport
                }

            elif config_lower.startswith(('hysteria2://', 'hy2://')):
                hy2_data = self.parse_hysteria2(config)
                if not hy2_data:
                    return None
                return {
                    "type": "hysteria2",
                    "tag": f"hy2-{str(uuid.uuid4())[:8]}",
                    "server": hy2_data['address'],
                    "server_port": hy2_data['port'],
                    "password": hy2_data['password'],
                    "obfs": {
                        "type": "salamander",
                        "password": hy2_data['obfs']
                    } if hy2_data['obfs'] else None,
                    "tls": {
                        "enabled": True,
                        "server_name": hy2_data['sni']
                    }
                }

            elif config_lower.startswith('ss://'):
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
        except Exception:
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

            rule_set_config = {
                "route": {
                    "rules": [
                        {
                            "geosite": ["category-ads-all"],
                            "outbound": "block"
                        }
                    ],
                    "auto_detect_interface": True,
                    "final": "proxy"
                },
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
                        "url": "https://www.gstatic.com/generate_204",
                        "interval": "10m"
                    },
                    {"type": "direct", "tag": "direct"},
                    {"type": "block", "tag": "block"}
                ] + outbounds,
                "dns": {
                    "servers": [
                        {"tag": "remote", "address": "tls://8.8.8.8", "detour": "proxy"},
                        {"tag": "local", "address": "local", "detour": "direct"}
                    ],
                    "rules": [
                        {"outbound": "direct", "server": "local"},
                        {"geosite": ["category-ads-all"], "server": "block"}
                    ]
                }
            }

            with open(self.output_file, 'w') as f:
                json.dump(rule_set_config, f, indent=2, ensure_ascii=False)

        except Exception as e:
            print(f"Error: {str(e)}")

def main():
    ConfigToSingbox().process_configs()

if __name__ == '__main__':
    main()