import json
import base64
import uuid
import re
from typing import Dict, Optional, List
from urllib.parse import urlparse, parse_qs, unquote

class ConfigToSingbox:
    def __init__(self):
        self.output_file = 'configs/singbox_configs.json'

    def safe_base64_decode(self, data: str) -> Optional[str]:
        try:
            padding = 4 - (len(data) % 4)
            if padding != 4:
                data += '=' * padding
            return base64.urlsafe_b64decode(data).decode('utf-8')
        except:
            try:
                return base64.b64decode(data).decode('utf-8')
            except:
                return None

    def decode_vmess(self, config: str) -> Optional[Dict]:
        try:
            encoded = config.replace('vmess://', '').strip()
            decoded = self.safe_base64_decode(encoded)
            if not decoded:
                return None
            
            if decoded.startswith('{'):
                vmess_data = json.loads(decoded)
            else:
                parts = decoded.split('@')
                if len(parts) != 2:
                    return None
                host_port = parts[1].split(':')
                vmess_data = {
                    'id': parts[0],
                    'add': host_port[0],
                    'port': host_port[1],
                    'aid': '0',
                    'net': 'tcp',
                    'tls': ''
                }
            return vmess_data
        except:
            return None

    def parse_vless(self, config: str) -> Optional[Dict]:
        try:
            if '@' not in config:
                return None
            
            uuid_part = re.search(r'vless://(.*?)@', config)
            if not uuid_part:
                return None
                
            url = urlparse(config)
            netloc = url.netloc.split('@')[-1]
            address, port = netloc.split(':') if ':' in netloc else (netloc, '443')
            params = {k: v[0] for k, v in parse_qs(url.query).items()}
            
            return {
                'uuid': uuid_part.group(1),
                'address': address.strip(),
                'port': int(port),
                'flow': params.get('flow', ''),
                'sni': params.get('sni', params.get('serverName', address.strip())),
                'type': params.get('type', params.get('security', 'tcp')),
                'path': unquote(params.get('path', '')),
                'host': params.get('host', '')
            }
        except:
            return None

    def parse_trojan(self, config: str) -> Optional[Dict]:
        try:
            if '@' not in config:
                return None
                
            password_part = re.search(r'trojan://(.*?)@', config)
            if not password_part:
                return None
                
            url = urlparse(config)
            port = url.port or 443
            params = {k: v[0] for k, v in parse_qs(url.query).items()}
            
            return {
                'password': unquote(password_part.group(1)),
                'address': url.hostname,
                'port': port,
                'sni': params.get('sni', params.get('peer', url.hostname)),
                'alpn': params.get('alpn', ''),
                'type': params.get('type', params.get('security', 'tcp')),
                'path': unquote(params.get('path', ''))
            }
        except:
            return None

    def parse_hysteria2(self, config: str) -> Optional[Dict]:
        try:
            url = urlparse(config)
            if not url.hostname or not url.port:
                return None
                
            query = {k: v[0] for k, v in parse_qs(url.query).items()}
            password = url.username or query.get('password', '')
            
            if not password:
                auth_part = re.search(r'auth=(.*?)(&|$)', config)
                if auth_part:
                    password = auth_part.group(1)
                    
            return {
                'address': url.hostname,
                'port': url.port,
                'password': unquote(password),
                'sni': query.get('sni', query.get('peer', url.hostname))
            }
        except:
            return None

    def parse_shadowsocks(self, config: str) -> Optional[Dict]:
        try:
            config = config.replace('ss://', '')
            if '@' in config:
                method_pass, server_part = config.split('@')
                decoded = self.safe_base64_decode(method_pass) or method_pass
            else:
                decoded = self.safe_base64_decode(config.split('#')[0])
                if not decoded or '@' not in decoded:
                    return None
                method_pass, server_part = decoded.split('@')
            
            method, password = method_pass.split(':')
            host, port = server_part.split('#')[0].split(':')
            
            return {
                'method': method.lower(),
                'password': password,
                'address': host.strip(),
                'port': int(port)
            }
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
                    "server": vmess_data.get('add', '').strip(),
                    "server_port": int(vmess_data.get('port', 0)),
                    "uuid": vmess_data.get('id', ''),
                    "security": vmess_data.get('scy', 'auto'),
                    "alter_id": int(vmess_data.get('aid', 0)),
                    "transport": transport,
                    "tls": {
                        "enabled": vmess_data.get('tls', '').lower() == 'tls',
                        "insecure": True,
                        "server_name": vmess_data.get('sni', vmess_data.get('host', vmess_data.get('add', '')))
                    }
                }
                
            elif config_lower.startswith('vless://'):
                vless_data = self.parse_vless(config)
                if not vless_data:
                    return None
                    
                transport = {}
                if vless_data['type'] in ['ws', 'h2', 'http', 'grpc']:
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
                if trojan_data['type'] in ['ws', 'h2', 'http', 'grpc']:
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
                
            outbounds: List[Dict] = []
            valid_tags: List[str] = []
            
            for config in configs:
                config = config.strip()
                if not config or config.startswith('//'):
                    continue
                    
                converted = self.convert_to_singbox(config)
                if converted and all(converted.get(key) for key in ['server', 'server_port', 'tag']):
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