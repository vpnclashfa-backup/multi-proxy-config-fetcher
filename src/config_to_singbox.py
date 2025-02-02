import json
import base64
import uuid
from urllib.parse import urlparse, parse_qs
from typing import Dict, Optional

class ConfigToSingbox:
    def __init__(self):
        self.output_file = 'configs/singbox_configs.json'
    
    def decode_vmess(self, config: str) -> Optional[Dict]:
        try:
            encoded = config.replace('vmess://', '')
            decoded = base64.b64decode(encoded + '==').decode('utf-8')
            return json.loads(decoded)
        except Exception:
            return None
    
    def parse_vless(self, config: str) -> Optional[Dict]:
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
                'host': params.get('host', [''])[0],
                'security': params.get('security', ['tls'])[0],
                'fp': params.get('fp', [''])[0]
            }
        except Exception:
            return None
    
    def parse_trojan(self, config: str) -> Optional[Dict]:
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
                'alpn': params.get('alpn', [''])[0],
                'type': params.get('type', ['tcp'])[0],
                'path': params.get('path', [''])[0],
                'security': params.get('security', ['tls'])[0],
                'fp': params.get('fp', [''])[0]
            }
        except Exception:
            return None
    
    def parse_hysteria2(self, config: str) -> Optional[Dict]:
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
                'obfs': query.get('obfs', ''),
                'obfs-password': query.get('obfs-password', '')
            }
        except Exception:
            return None
    
    def parse_shadowsocks(self, config: str) -> Optional[Dict]:
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
                'port': int(port),
                'plugin': ''
            }
        except Exception:
            return None
    
    def parse_wireguard(self, config: str) -> Optional[Dict]:
        try:
            url = urlparse(config)
            if url.scheme.lower() != 'wireguard' or not url.hostname:
                return None
            params = parse_qs(url.query)
            return {
                'private_key': url.username,
                'address': url.hostname,
                'port': url.port or 51820,
                'public_key': params.get('public_key', [''])[0],
                'preshared_key': params.get('preshared_key', [''])[0],
                'mtu': int(params.get('mtu', [1420])[0]),
                'ip': params.get('ip', [''])[0].split(',')
            }
        except Exception:
            return None
    
    def convert_to_singbox(self, config: str) -> Optional[Dict]:
        try:
            config_lower = config.lower()
            if config_lower.startswith('vmess://'):
                vmess_data = self.decode_vmess(config)
                if not vmess_data:
                    return None
                transport = {}
                if vmess_data.get('net') == 'ws':
                    transport.update({
                        "type": "ws",
                        "path": vmess_data.get('path', ''),
                        "headers": {"Host": vmess_data.get('host', '')} if vmess_data.get('host') else {}
                    })
                elif vmess_data.get('net') == 'h2':
                    transport.update({
                        "type": "http",
                        "host": [vmess_data.get('host', '')],
                        "path": vmess_data.get('path', '')
                    })
                tls = {}
                if vmess_data.get('tls') == 'tls':
                    tls = {
                        "enabled": True,
                        "server_name": vmess_data.get('sni', vmess_data['add']),
                        "utls": {
                            "enabled": True,
                            "fingerprint": vmess_data.get('fp', 'chrome')
                        }
                    }
                return {
                    "type": "vmess",
                    "tag": f"vmess-{uuid.uuid4().hex[:6]}",
                    "server": vmess_data['add'],
                    "server_port": int(vmess_data['port']),
                    "uuid": vmess_data['id'],
                    "security": vmess_data.get('scy', 'auto'),
                    "alter_id": int(vmess_data.get('aid', 0)),
                    "transport": transport,
                    "tls": tls
                }
            elif config_lower.startswith('vless://'):
                vless_data = self.parse_vless(config)
                if not vless_data:
                    return None
                transport = {}
                if vless_data['type'] == 'ws':
                    transport.update({
                        "type": "ws",
                        "path": vless_data['path'],
                        "headers": {"Host": vless_data['host']} if vless_data['host'] else {}
                    })
                tls = {}
                if vless_data['security'] == 'tls':
                    tls = {
                        "enabled": True,
                        "server_name": vless_data['sni'],
                        "utls": {
                            "enabled": True,
                            "fingerprint": vless_data.get('fp', 'chrome')
                        }
                    }
                elif vless_data['security'] == 'reality':
                    tls = {
                        "enabled": True,
                        "server_name": vless_data['sni'],
                        "reality": {
                            "enabled": True,
                            "public_key": vless_data.get('pbk', ''),
                            "short_id": vless_data.get('sid', '')
                        }
                    }
                return {
                    "type": "vless",
                    "tag": f"vless-{uuid.uuid4().hex[:6]}",
                    "server": vless_data['address'],
                    "server_port": vless_data['port'],
                    "uuid": vless_data['uuid'],
                    "flow": vless_data['flow'],
                    "packet_encoding": "xudp",
                    "transport": transport,
                    "tls": tls
                }
            elif config_lower.startswith('trojan://'):
                trojan_data = self.parse_trojan(config)
                if not trojan_data:
                    return None
                transport = {}
                if trojan_data['type'] == 'ws':
                    transport.update({
                        "type": "ws",
                        "path": trojan_data['path'],
                        "headers": {"Host": trojan_data.get('host', '')}
                    })
                tls = {
                    "enabled": True,
                    "server_name": trojan_data['sni'],
                    "utls": {
                        "enabled": True,
                        "fingerprint": trojan_data.get('fp', 'chrome')
                    }
                }
                return {
                    "type": "trojan",
                    "tag": f"trojan-{uuid.uuid4().hex[:6]}",
                    "server": trojan_data['address'],
                    "server_port": trojan_data['port'],
                    "password": trojan_data['password'],
                    "transport": transport,
                    "tls": tls
                }
            elif config_lower.startswith(('hysteria2://', 'hy2://')):
                hy2_data = self.parse_hysteria2(config)
                if not hy2_data:
                    return None
                obfs = {}
                if hy2_data['obfs']:
                    obfs = {
                        "type": hy2_data['obfs'],
                        "password": hy2_data['obfs-password']
                    }
                return {
                    "type": "hysteria2",
                    "tag": f"hy2-{uuid.uuid4().hex[:6]}",
                    "server": hy2_data['address'],
                    "server_port": hy2_data['port'],
                    "password": hy2_data['password'],
                    "obfs": obfs,
                    "tls": {
                        "enabled": True,
                        "server_name": hy2_data['sni'],
                        "utls": {
                            "enabled": True,
                            "fingerprint": "chrome"
                        }
                    }
                }
            elif config_lower.startswith('ss://'):
                ss_data = self.parse_shadowsocks(config)
                if not ss_data:
                    return None
                plugin = {}
                if ss_data['plugin']:
                    plugin = {
                        "type": ss_data['plugin'].split('-')[0],
                        "host": ss_data['plugin'].split(';')[1].split('=')[1]
                    }
                return {
                    "type": "shadowsocks",
                    "tag": f"ss-{uuid.uuid4().hex[:6]}",
                    "server": ss_data['address'],
                    "server_port": ss_data['port'],
                    "method": ss_data['method'],
                    "password": ss_data['password'],
                    "plugin": plugin
                }
            elif config_lower.startswith('wireguard://'):
                wg_data = self.parse_wireguard(config)
                if not wg_data:
                    return None
                return {
                    "type": "wireguard",
                    "tag": f"wg-{uuid.uuid4().hex[:6]}",
                    "server": wg_data['address'],
                    "server_port": wg_data['port'],
                    "local_address": wg_data['ip'],
                    "private_key": wg_data['private_key'],
                    "peer_public_key": wg_data['public_key'],
                    "pre_shared_key": wg_data['preshared_key'],
                    "mtu": wg_data['mtu']
                }
            return None
        except Exception:
            return None
    
    def process_configs(self):
        try:
            with open('configs/proxy_configs.txt', 'r') as f:
                configs = f.read().splitlines()
            
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
            
            final_config = {
                "dns": {
                    "servers": [
                        {"tag": "system", "address": "local", "detour": "direct"}
                    ],
                    "rules": [
                        {"geosite": "cn", "server": "system"}
                    ]
                },
                "inbounds": [
                    {
                        "type": "tun",
                        "tag": "tun-in",
                        "interface_name": "SingBox",
                        "mtu": 9000,
                        "inet4_address": "172.19.0.1/30",
                        "inet6_address": "fdfe:dcba:9876::1/126",
                        "auto_route": True,
                        "strict_route": False,
                        "sniff": True
                    }
                ],
                "outbounds": [
                    {
                        "type": "selector",
                        "tag": "proxy",
                        "outbounds": ["auto"] + valid_tags,
                        "default": "auto"
                    },
                    {
                        "type": "urltest",
                        "tag": "auto",
                        "outbounds": valid_tags,
                        "interval": "10m",
                        "tolerance": 50
                    },
                    {
                        "type": "direct",
                        "tag": "direct"
                    },
                    {
                        "type": "dns",
                        "tag": "dns-out"
                    }
                ] + outbounds,
                "route": {
                    "geoip": {
                        "download_url": "https://testingcf.jsdelivr.net/gh/SagerNet/sing-geoip@release/geoip.db",
                        "download_detour": "direct"
                    },
                    "geosite": {
                        "download_url": "https://testingcf.jsdelivr.net/gh/SagerNet/sing-geosite@release/geosite.db",
                        "download_detour": "direct"
                    },
                    "rules": [
                        {"protocol": "dns", "outbound": "dns-out"},
                        {"geosite": "cn", "geoip": "cn", "outbound": "direct"}
                    ]
                }
            }
            
            with open(self.output_file, 'w') as f:
                json.dump(final_config, f, indent=2, ensure_ascii=False)
        
        except Exception as e:
            print(f"Error processing configs: {str(e)}")

def main():
    converter = ConfigToSingbox()
    converter.process_configs()

if __name__ == '__main__':
    main()