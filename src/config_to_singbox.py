import json
import base64
import uuid
from typing import Dict, Optional
from urllib.parse import urlparse, parse_qs

class ConfigToSingbox:
    def __init__(self):
        self.output_file = 'configs/singbox_configs.json'

    def decode_vmess(self, config: str) -> Optional[Dict]:
        try:
            encoded = config.replace('vmess://', '')
            decoded = base64.b64decode(encoded).decode('utf-8')
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
                'encryption': params.get('encryption', ['none'])[0],
                'sni': params.get('sni', [address])[0],
                'fp': params.get('fp', [''])[0],
                'type': params.get('type', ['tcp'])[0],
                'path': params.get('path', [''])[0],
                'host': params.get('host', [''])[0],
                'fragment': params.get('fragment', [''])[0]
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
                'fp': params.get('fp', [''])[0],
                'type': params.get('type', ['tcp'])[0],
                'path': params.get('path', [''])[0],
                'fragment': params.get('fragment', [''])[0]
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
                'insecure': query.get('insecure', '0') == '1',
                'hop_ports': query.get('hop', '').split(',') if query.get('hop') else []
            }
        except Exception:
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
        except Exception:
            return None

    def parse_wireguard(self, config: str) -> Optional[Dict]:
        try:
            lines = config.strip().split('\n')
            if not lines[0].strip() == '[Interface]':
                return None
            
            wg_config = {'peers': []}
            current_section = None
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                    
                if line.startswith('['):
                    current_section = line[1:-1]
                    if current_section == 'Peer':
                        wg_config['peers'].append({})
                    continue
                    
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()
                
                if current_section == 'Interface':
                    wg_config[key.lower()] = value
                elif current_section == 'Peer':
                    wg_config['peers'][-1][key.lower()] = value
                    
            return wg_config
        except Exception:
            return None

    def convert_to_singbox(self, config: str) -> Optional[Dict]:
        try:
            config_lower = config.lower()
            if config_lower.startswith('vmess://'):
                vmess_data = self.decode_vmess(config)
                if not vmess_data or not vmess_data.get('add') or not vmess_data.get('port') or not vmess_data.get('id'):
                    return None
                    
                transport = {}
                if vmess_data.get('net') in ['ws', 'h2', 'grpc']:
                    transport["type"] = vmess_data.get('net')
                    if vmess_data.get('path'):
                        transport["path"] = vmess_data.get('path')
                    if vmess_data.get('host'):
                        transport["headers"] = {"Host": vmess_data.get('host')}
                    
                return {
                    "type": "vmess",
                    "tag": f"vmess-{str(uuid.uuid4())[:8]}",
                    "server": vmess_data['add'],
                    "server_port": int(vmess_data['port']),
                    "uuid": vmess_data['id'],
                    "security": vmess_data.get('scy', 'auto'),
                    "alter_id": int(vmess_data.get('aid', 0)),
                    "transport": transport,
                    "tls": {
                        "enabled": vmess_data.get('tls') == 'tls',
                        "insecure": True,
                        "server_name": vmess_data.get('sni', vmess_data['add']),
                        "utls": {
                            "enabled": True,
                            "fingerprint": vmess_data.get('fp', 'chrome')
                        }
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
                    "encryption": vless_data['encryption'],
                    "transport": transport,
                    "tls": {
                        "enabled": True,
                        "server_name": vless_data['sni'],
                        "insecure": True,
                        "utls": {
                            "enabled": True,
                            "fingerprint": vless_data['fp'] or "chrome"
                        }
                    },
                    "packet_encoding": "xudp",
                    "multiplex": {
                        "enabled": True,
                        "protocol": "smux",
                        "max_streams": 32
                    }
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
                    "transport": transport,
                    "tls": {
                        "enabled": True,
                        "server_name": trojan_data['sni'],
                        "alpn": trojan_data['alpn'].split(',') if trojan_data['alpn'] else ["h2", "http/1.1"],
                        "insecure": True,
                        "utls": {
                            "enabled": True,
                            "fingerprint": trojan_data['fp'] or "chrome"
                        }
                    },
                    "multiplex": {
                        "enabled": True,
                        "protocol": "smux",
                        "max_streams": 32
                    }
                }
                
            elif config_lower.startswith('hysteria2://') or config_lower.startswith('hy2://'):
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
                        "server_name": hy2_data['sni'],
                        "insecure": hy2_data['insecure']
                    },
                    "hop_ports": hy2_data['hop_ports']
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
                    "password": ss_data['password'],
                    "multiplex": {
                        "enabled": True,
                        "protocol": "smux",
                        "max_streams": 32
                    }
                }
                
            elif config.startswith('[Interface]'):
                wg_data = self.parse_wireguard(config)
                if not wg_data or not wg_data.get('privatekey') or not wg_data.get('peers'):
                    return None
                    
                peer = wg_data['peers'][0]
                endpoint = peer.get('endpoint', '').split(':')
                if len(endpoint) != 2:
                    return None
                    
                return {
                    "type": "wireguard",
                    "tag": f"wireguard-{str(uuid.uuid4())[:8]}",
                    "server": endpoint[0],
                    "server_port": int(endpoint[1]),
                    "private_key": wg_data['privatekey'],
                    "peer_public_key": peer.get('publickey', ''),
                    "pre_shared_key": peer.get('presharedkey', ''),
                    "reserved": peer.get('reserved', '').split(',') if peer.get('reserved') else [],
                    "mtu": int(wg_data.get('mtu', 1420))
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
                
            dns_config = {
                "dns": {
                    "servers": [
                        {
                            "tag": "google",
                            "address": "tls://8.8.8.8",
                            "address_resolver": "local",
                            "strategy": "prefer_ipv4"
                        },
                        {
                            "tag": "local",
                            "address": "local",
                            "detour": "direct"
                        }
                    ],
                    "rules": [
                        {
                            "domain_suffix": [".ir"],
                            "server": "local"
                        }
                    ],
                    "final": "google",
                    "strategy": "prefer_ipv4",
                    "independent_cache": true
                }
            }

            inbounds_config = [
                {
                    "type": "mixed",
                    "tag": "mixed-in",
                    "listen": "127.0.0.1",
                    "listen_port": 2080,
                    "sniff": True,
                    "sniff_override_destination": True,
                    "domain_strategy": "prefer_ipv4"
                },
                {
                    "type": "tun",
                    "tag": "tun-in",
                    "interface_name": "tun0",
                    "stack": "system",
                    "auto_route": True,
                    "strict_route": True,
                    "sniff": True,
                    "sniff_override_destination": True,
                    "domain_strategy": "prefer_ipv4",
                    "mtu": 9000,
                    "inet4_address": "172.19.0.1/30",
                    "inet6_address": "fdfe:dcba:9876::1/126",
                    "auto_route": True,
                    "strict_route": True
                }
            ]

            outbounds_config = [
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
                    "url": "http://www.gstatic.com/generate_204",
                    "interval": "10m",
                    "tolerance": 50,
                    "interrupt_exist_connections": False
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
            ] + outbounds

            route_config = {
                "rules": [
                    {
                        "protocol": "dns",
                        "outbound": "dns-out"
                    },
                    {
                        "geosite": "category-ads-all",
                        "outbound": "block"
                    },
                    {
                        "geosite": "ir",
                        "geoip": "ir",
                        "outbound": "direct"
                    }
                ],
                "auto_detect_interface": True,
                "override_android_vpn": True,
                "default_interface": "en0",
                "final": "proxy"
            }

            experimental_config = {
                "cache_file": {
                    "enabled": True,
                    "path": "cache.db"
                },
                "clash_api": {
                    "external_controller": "127.0.0.1:9090",
                    "external_ui": "ui",
                    "external_ui_download_url": "",
                    "external_ui_download_detour": "direct",
                    "secret": "",
                    "default_mode": "rule"
                }
            }

            ntp_config = {
                "enabled": True,
                "server": "time.apple.com",
                "server_port": 123,
                "interval": "30m",
                "detour": "direct"
            }

            singbox_config = {
                "log": {
                    "level": "info",
                    "timestamp": True
                },
                **dns_config,
                "inbounds": inbounds_config,
                "outbounds": outbounds_config,
                "route": route_config,
                "experimental": experimental_config,
                "ntp": ntp_config
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