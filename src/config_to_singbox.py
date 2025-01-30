import json
import base64
import uuid
import re
from urllib.parse import urlparse, parse_qs, unquote

class ConfigToSingbox:
    def __init__(self):
        self.output_file = 'configs/singbox_configs.json'

    def decode_vmess(self, config: str) -> dict:
        try:
            decoded = base64.b64decode(config[8:] + '===').decode('utf-8')
            return json.loads(decoded)
        except:
            return {}

    def parse_vless(self, config: str) -> dict:
        try:
            url = urlparse(config)
            netloc = url.netloc.split('@', 1)
            if len(netloc) != 2:
                return {}
            
            uuid_part, server_part = netloc
            server, _, port = server_part.partition(':')
            params = parse_qs(url.query)
            
            return {
                'uuid': uuid_part,
                'address': server,
                'port': int(port),
                'flow': params.get('flow', [''])[0],
                'security': params.get('security', ['tls'])[0],
                'sni': params.get('sni', [server])[0],
                'fp': params.get('fp', [''])[0],
                'type': params.get('type', [''])[0],
                'path': params.get('path', [''])[0],
                'host': params.get('host', [''])[0]
            }
        except:
            return {}

    def parse_trojan(self, config: str) -> dict:
        try:
            url = urlparse(config)
            server_part = url.netloc.split('@')[-1]
            server, _, port = server_part.partition(':')
            params = parse_qs(url.query)
            
            return {
                'password': unquote(url.username),
                'address': server,
                'port': int(port),
                'sni': params.get('sni', [server])[0],
                'fp': params.get('fp', [''])[0],
                'type': params.get('type', [''])[0],
                'path': params.get('path', [''])[0],
                'host': params.get('host', [''])[0]
            }
        except:
            return {}

    def parse_hysteria2(self, config: str) -> dict:
        try:
            config = config.replace('hysteria2://', 'hy2://')
            url = urlparse(config)
            auth, _, server = url.netloc.rpartition('@')
            server, _, port = server.partition(':')
            params = parse_qs(url.query)
            
            return {
                'password': auth or params.get('auth', [''])[0],
                'address': server,
                'port': int(port),
                'sni': params.get('sni', [server])[0],
                'obfs': params.get('obfs', [''])[0],
                'obfs-password': params.get('obfs-password', [''])[0],
                'alpn': params.get('alpn', [''])[0].split(','),
                'insecure': '1' if params.get('insecure', [''])[0] else '0'
            }
        except:
            return {}

    def parse_shadowsocks(self, config: str) -> dict:
        try:
            parts = config[5:].split('#', 1)
            decoded = base64.b64decode(parts[0].split('@')[0] + '===').decode()
            method, password = decoded.split(':', 1)
            server, port = parts[0].split('@')[1].split(':')
            
            return {
                'method': method,
                'password': password,
                'address': server,
                'port': int(port)
            }
        except:
            return {}

    def convert_to_singbox(self, config: str) -> dict:
        if config.startswith('vmess://'):
            data = self.decode_vmess(config)
            if not data.get('add') or not data.get('port'):
                return {}
            
            return {
                "type": "vmess",
                "tag": f"vmess-{uuid.uuid4().hex[:6]}",
                "server": data['add'],
                "server_port": int(data['port']),
                "uuid": data['id'],
                "security": data.get('scy', 'auto'),
                "alter_id": int(data.get('aid', 0)),
                "transport": {
                    "type": data.get('net', 'tcp'),
                    "path": data.get('path', ''),
                    "host": data.get('host', ''),
                    "headers": {
                        "Host": data.get('host', '')
                    } if data.get('host') else {}
                },
                "tls": {
                    "enabled": data.get('tls') == 'tls',
                    "server_name": data.get('sni', data['add']),
                    "insecure": False
                }
            }

        elif config.startswith('vless://'):
            data = self.parse_vless(config)
            if not data.get('address'):
                return {}
            
            transport = {}
            if data['type'] == 'ws':
                transport = {
                    "type": "ws",
                    "path": data['path'],
                    "headers": {"Host": data['host']} if data['host'] else {}
                }
            elif data['type'] == 'grpc':
                transport = {
                    "type": "grpc",
                    "service_name": data['path'].lstrip('/')
                }
            
            return {
                "type": "vless",
                "tag": f"vless-{uuid.uuid4().hex[:6]}",
                "server": data['address'],
                "server_port": data['port'],
                "uuid": data['uuid'],
                "flow": data['flow'],
                "packet_encoding": "xudp",
                "transport": transport,
                "tls": {
                    "enabled": data['security'] == 'tls',
                    "server_name": data['sni'],
                    "insecure": False,
                    "alpn": ["h2", "http/1.1"]
                }
            }

        elif config.startswith('trojan://'):
            data = self.parse_trojan(config)
            if not data.get('address'):
                return {}
            
            transport = {}
            if data['type'] == 'ws':
                transport = {
                    "type": "ws",
                    "path": data['path'],
                    "headers": {"Host": data['host']} if data['host'] else {}
                }
            elif data['type'] == 'grpc':
                transport = {
                    "type": "grpc",
                    "service_name": data['path'].lstrip('/')
                }
            
            return {
                "type": "trojan",
                "tag": f"trojan-{uuid.uuid4().hex[:6]}",
                "server": data['address'],
                "server_port": data['port'],
                "password": data['password'],
                "transport": transport,
                "tls": {
                    "enabled": True,
                    "server_name": data['sni'],
                    "alpn": ["h2", "http/1.1"],
                    "insecure": False
                }
            }

        elif config.startswith(('hy2://', 'hysteria2://')):
            data = self.parse_hysteria2(config)
            if not data.get('address'):
                return {}
            
            return {
                "type": "hysteria2",
                "tag": f"hy2-{uuid.uuid4().hex[:6]}",
                "server": data['address'],
                "server_port": data['port'],
                "password": data['password'],
                "obfs": {
                    "type": "salamander",
                    "password": data['obfs-password']
                } if data['obfs'] else None,
                "tls": {
                    "enabled": True,
                    "server_name": data['sni'],
                    "insecure": data['insecure'] == '1',
                    "alpn": data['alpn']
                }
            }

        elif config.startswith('ss://'):
            data = self.parse_shadowsocks(config)
            if not data.get('address'):
                return {}
            
            return {
                "type": "shadowsocks",
                "tag": f"ss-{uuid.uuid4().hex[:6]}",
                "server": data['address'],
                "server_port": data['port'],
                "method": data['method'],
                "password": data['password']
            }

        return {}

    def process_configs(self):
        try:
            with open('configs/proxy_configs.txt') as f:
                configs = [c.strip() for c in f if c.strip() and not c.startswith('//')]

            outbounds = []
            for config in configs:
                if converted := self.convert_to_singbox(config):
                    outbounds.append(converted)

            if not outbounds:
                return

            singbox_config = {
                "dns": {
                    "servers": [
                        {"tag": "local", "address": "local"},
                        {"tag": "block", "address": "rcode://success"}
                    ]
                },
                "inbounds": [
                    {
                        "type": "tun",
                        "tag": "tun-in",
                        "inet4_address": "172.19.0.1/30",
                        "mtu": 9000,
                        "auto_route": True,
                        "strict_route": False,
                        "sniff": True
                    }
                ],
                "outbounds": [
                    {
                        "type": "selector",
                        "tag": "proxy",
                        "outbounds": ["auto"] + [o["tag"] for o in outbounds]
                    },
                    {
                        "type": "urltest",
                        "tag": "auto",
                        "outbounds": [o["tag"] for o in outbounds],
                        "url": "https://www.gstatic.com/generate_204",
                        "interval": "5m"
                    },
                    *outbounds,
                    {"type": "direct", "tag": "direct"},
                    {"type": "block", "tag": "block"}
                ]
            }

            with open(self.output_file, 'w') as f:
                json.dump(singbox_config, f, indent=2, ensure_ascii=False)

        except Exception as e:
            print(f"Error: {e}")

def main():
    ConfigToSingbox().process_configs()

if __name__ == '__main__':
    main()