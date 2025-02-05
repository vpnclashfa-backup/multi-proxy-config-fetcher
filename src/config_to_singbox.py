import json
import base64
import uuid
import re
from typing import Dict, Optional, List, Union
from urllib.parse import urlparse, parse_qs, unquote

class ConfigToSingbox:
    def __init__(self):
        self.output_file = 'configs/singbox_configs.json'

    def safe_base64_decode(self, encoded_str: str) -> Optional[str]:
        try:
            padding = 4 - (len(encoded_str) % 4)
            if padding != 4:
                encoded_str += '=' * padding
            return base64.b64decode(encoded_str.encode()).decode('utf-8')
        except:
            try:
                return base64.b64decode(encoded_str + '=' * (-len(encoded_str) % 4)).decode('utf-8')
            except:
                return None

    def clean_url(self, url: str) -> str:
        return re.sub(r'[\x00-\x1F\x7F-\x9F]', '', url)

    def decode_vmess(self, config: str) -> Optional[Dict]:
        try:
            encoded = config.replace('vmess://', '').strip()
            if '{' not in encoded:
                decoded = self.safe_base64_decode(encoded)
                if not decoded:
                    return None
                return json.loads(decoded)
            return json.loads(encoded)
        except:
            try:
                parts = encoded.split('@')
                if len(parts) == 2:
                    server_parts = parts[1].split('?')[0].split(':')
                    if len(server_parts) == 2:
                        return {
                            'add': server_parts[0],
                            'port': server_parts[1],
                            'id': parts[0],
                            'net': 'tcp'
                        }
            except:
                pass
            return None

    def parse_vless(self, config: str) -> Optional[Dict]:
        try:
            cleaned_config = self.clean_url(config)
            url = urlparse(cleaned_config)
            if url.scheme.lower() != 'vless':
                return None

            netloc = url.netloc.split('@')[-1]
            address = netloc.split(':')[0] if ':' in netloc else netloc
            port = int(netloc.split(':')[1]) if ':' in netloc else 443

            params = parse_qs(url.query, keep_blank_values=True)
            return {
                'uuid': unquote(url.username or ''),
                'address': address,
                'port': port,
                'flow': params.get('flow', [''])[0],
                'sni': params.get('sni', [params.get('host', [address])[0]])[0],
                'type': params.get('type', ['tcp'])[0],
                'path': unquote(params.get('path', [''])[0]),
                'host': params.get('host', [''])[0]
            }
        except:
            return None

    def parse_trojan(self, config: str) -> Optional[Dict]:
        try:
            cleaned_config = self.clean_url(config)
            url = urlparse(cleaned_config)
            if url.scheme.lower() != 'trojan':
                return None

            netloc = url.netloc.split('@')[-1]
            port = int(netloc.split(':')[1]) if ':' in netloc else 443
            params = parse_qs(url.query, keep_blank_values=True)

            return {
                'password': unquote(url.username or ''),
                'address': url.hostname or netloc.split(':')[0],
                'port': port,
                'sni': params.get('sni', [url.hostname])[0],
                'alpn': params.get('alpn', [''])[0],
                'type': params.get('type', ['tcp'])[0],
                'path': unquote(params.get('path', [''])[0])
            }
        except:
            return None

    def parse_hysteria2(self, config: str) -> Optional[Dict]:
        try:
            cleaned_config = self.clean_url(config)
            url = urlparse(cleaned_config)
            if url.scheme.lower() not in ['hysteria2', 'hy2']:
                return None

            netloc = url.netloc.split('@')[-1]
            port = url.port or int(netloc.split(':')[1]) if ':' in netloc else 443
            query = dict(param.split('=', 1) for param in url.query.split('&') if '=' in param) if url.query else {}

            return {
                'address': url.hostname or netloc.split(':')[0],
                'port': port,
                'password': unquote(url.username or query.get('password', '')),
                'sni': query.get('sni', url.hostname or netloc.split(':')[0])
            }
        except:
            return None

    def parse_shadowsocks(self, config: str) -> Optional[Dict]:
        try:
            if '#' in config:
                config = config.split('#')[0]

            ss_parts = config.replace('ss://', '').split('@')
            if len(ss_parts) == 2:
                decoded_parts = self.safe_base64_decode(ss_parts[0])
                if decoded_parts and ':' in decoded_parts:
                    method, password = decoded_parts.split(':', 1)
                    server_parts = ss_parts[1].split(':')
                    if len(server_parts) == 2:
                        return {
                            'method': method,
                            'password': password,
                            'address': server_parts[0],
                            'port': int(server_parts[1])
                        }
            elif len(ss_parts) == 1:
                decoded = self.safe_base64_decode(ss_parts[0])
                if decoded and '@' in decoded:
                    method_pass, server = decoded.split('@')
                    method, password = method_pass.split(':')
                    host, port = server.split(':')
                    return {
                        'method': method,
                        'password': password,
                        'address': host,
                        'port': int(port)
                    }
            return None
        except:
            return None

    def convert_to_singbox(self, config: str) -> Optional[Dict]:
        try:
            config = config.strip()
            config_lower = config.lower()

            if config_lower.startswith('vmess://'):
                vmess_data = self.decode_vmess(config)
                if not vmess_data:
                    return None

                transport = {}
                if vmess_data.get('net') in ['ws', 'h2', 'http', 'grpc']:
                    transport["type"] = vmess_data.get('net')
                    if vmess_data.get('path'):
                        transport["path"] = vmess_data.get('path')
                    if vmess_data.get('host'):
                        transport["headers"] = {"Host": vmess_data.get('host')}

                return {
                    "type": "vmess",
                    "tag": f"vmess-{str(uuid.uuid4())[:8]}",
                    "server": vmess_data.get('add'),
                    "server_port": int(vmess_data.get('port', 443)),
                    "uuid": vmess_data.get('id'),
                    "security": vmess_data.get('scy', 'auto'),
                    "alter_id": int(vmess_data.get('aid', 0)),
                    "transport": transport,
                    "tls": {
                        "enabled": vmess_data.get('tls') == 'tls',
                        "insecure": True,
                        "server_name": vmess_data.get('sni') or vmess_data.get('host') or vmess_data.get('add')
                    }
                }

            elif config_lower.startswith('vless://'):
                vless_data = self.parse_vless(config)
                if not vless_data:
                    return None

                transport = {}
                if vless_data['type'] != 'tcp':
                    transport["type"] = vless_data['type']
                    if vless_data.get('path'):
                        transport["path"] = vless_data['path']
                    if vless_data.get('host'):
                        transport["headers"] = {"Host": vless_data['host']}

                return {
                    "type": "vless",
                    "tag": f"vless-{str(uuid.uuid4())[:8]}",
                    "server": vless_data['address'],
                    "server_port": vless_data['port'],
                    "uuid": vless_data['uuid'],
                    "flow": vless_data['flow'],
                    "tls": {
                        "enabled": True,
                        "server_name": vless_data['sni'],
                        "insecure": True
                    },
                    "transport": transport
                }

            elif config_lower.startswith('trojan://'):
                trojan_data = self.parse_trojan(config)
                if not trojan_data:
                    return None

                transport = {}
                if trojan_data['type'] != 'tcp':
                    transport["type"] = trojan_data['type']
                    if trojan_data.get('path'):
                        transport["path"] = trojan_data['path']

                return {
                    "type": "trojan",
                    "tag": f"trojan-{str(uuid.uuid4())[:8]}",
                    "server": trojan_data['address'],
                    "server_port": trojan_data['port'],
                    "password": trojan_data['password'],
                    "tls": {
                        "enabled": True,
                        "server_name": trojan_data['sni'],
                        "alpn": [x for x in trojan_data['alpn'].split(',') if x],
                        "insecure": True
                    },
                    "transport": transport
                }

            elif config_lower.startswith(('hysteria2://', 'hy2://')):
                hy2_data = self.parse_hysteria2(config)
                if not hy2_data:
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
        except:
            return None

    def process_configs(self):
        try:
            with open('configs/proxy_configs.txt', 'r', encoding='utf-8') as f:
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

            dns_config = {
                "dns": {
                    "final": "local-dns",
                    "rules": [
                        {"clash_mode": "Global", "server": "proxy-dns", "source_ip_cidr": ["172.19.0.0/30"]},
                        {"server": "proxy-dns", "source_ip_cidr": ["172.19.0.0/30"]},
                        {"clash_mode": "Direct", "server": "direct-dns"}
                    ],
                    "servers": [
                        {"address": "tls://208.67.222.123", "address_resolver": "local-dns", "detour": "proxy", "tag": "proxy-dns"},
                        {"address": "local", "detour": "direct", "tag": "local-dns"},
                        {"address": "rcode://success", "tag": "block"},
                        {"address": "local", "detour": "direct", "tag": "direct-dns"}
                    ],
                    "strategy": "prefer_ipv4"
                }
            }

            inbounds_config = [
                {"address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"], "auto_route": True, "endpoint_independent_nat": False, "mtu": 9000, "platform": {"http_proxy": {"enabled": True, "server": "127.0.0.1", "server_port": 2080}}, "sniff": True, "stack": "system", "strict_route": False, "type": "tun"},
                {"listen": "127.0.0.1", "listen_port": 2080, "sniff": True, "type": "mixed", "users": []}
            ]

            outbounds_config = [
                {"tag": "proxy", "type": "selector", "outbounds": ["auto"] + valid_tags + ["direct"]},
                {"tag": "auto", "type": "urltest", "outbounds": valid_tags, "url": "http://www.gstatic.com/generate_204", "interval": "10m", "tolerance": 50},
                {"tag": "direct", "type": "direct"}
            ] + outbounds

            route_config = {
                "auto_detect_interface": True,
                "final": "proxy",
                "rules": [
                    {"clash_mode": "Direct", "outbound": "direct"},
                    {"clash_mode": "Global", "outbound": "proxy"},
                    {"protocol": "dns", "action": "hijack-dns"}
                ]
            }

            singbox_config = {**dns_config, "inbounds": inbounds_config, "outbounds": outbounds_config, "route": route_config}

            with open(self.output_file, 'w', encoding='utf-8') as f:
                json.dump(singbox_config, f, indent=2, ensure_ascii=False)

        except Exception as e:
            print(f"Error processing configs: {str(e)}")

def main():
    converter = ConfigToSingbox()
    converter.process_configs()

if __name__ == '__main__':
    main()