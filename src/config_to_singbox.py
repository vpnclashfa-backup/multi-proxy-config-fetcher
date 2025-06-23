import json
import base64
import uuid
import time
import socket
import requests
from typing import Dict, Optional, Tuple, List
from urllib.parse import urlparse, parse_qs, unquote

class ConfigToSingbox:
    def __init__(self):
        self.output_file = 'configs/singbox_configs.json'
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        # Cache for IP locations to avoid repeated API calls
        self.ip_location_cache: Dict[str, Tuple[str, str]] = {}

    def get_location_from_ip_api(self, ip: str) -> Tuple[str, str]:
        try:
            response = requests.get(f'http://ip-api.com/json/{ip}', headers=self.headers, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success' and data.get('countryCode'):
                    return data['countryCode'].lower(), data['country']
        except Exception:
            pass
        return '', ''

    # Other get_location helpers can be placed here...

    def get_location(self, address: str) -> tuple:
        if not address or address.lower() == "auto":
            return "🏳️", "Unknown"
        
        if address in self.ip_location_cache:
            return self.ip_location_cache[address]
        
        try:
            ip = socket.gethostbyname(address)
            if ip in self.ip_location_cache:
                return self.ip_location_cache[ip]

            flag, country = self.get_location_from_ip_api(ip)
            if country:
                country_code = country.lower()
                flag_emoji = ''.join(chr(ord('🇦') + ord(c.upper()) - ord('A')) for c in country_code)
                result = (flag_emoji, country)
                self.ip_location_cache[address] = result
                self.ip_location_cache[ip] = result
                return result
            
        except Exception:
            pass
        
        result = ("🏳️", "Unknown")
        self.ip_location_cache[address] = result
        return result

    def _decode_base64_safe(self, s: str) -> str:
        s = s.replace('-', '+').replace('_', '/')
        padding = -len(s) % 4
        if padding:
            s += '=' * padding
        try:
            return base64.b64decode(s).decode('utf-8')
        except Exception:
            return ""

    def _parse_query_params(self, url: str) -> Dict[str, str]:
        params = {}
        try:
            parsed_url = urlparse(url)
            query = parse_qs(parsed_url.query)
            for key, value in query.items():
                if value:
                    params[key.lower()] = value[0]
        except:
            pass
        return params

    def _build_transport(self, params: Dict) -> Dict:
        transport = {}
        net_type = params.get('type', 'tcp')
        
        if net_type == 'ws':
            transport['type'] = 'ws'
            transport['path'] = params.get('path', '/')
            transport['headers'] = {'Host': params.get('host', '')}
        elif net_type == 'grpc':
            transport['type'] = 'grpc'
            transport['service_name'] = params.get('servicename', '')
        
        return transport

    def _build_tls(self, params: Dict, host: str) -> Dict:
        security = params.get('security', 'none')
        if security not in ['tls', 'reality', 'xtls']:
            return None

        tls_obj = {"enabled": True, "server_name": params.get('sni', host)}
        
        if security == 'reality':
            tls_obj['reality'] = {
                "enabled": True,
                "public_key": params.get('pbk'),
                "short_id": params.get('sid', '')
            }
        else:
            tls_obj['insecure'] = params.get('allowinsecure', '1') == '1'
            tls_obj['alpn'] = [p.strip() for p in params.get('alpn', '').split(',')] if params.get('alpn') else None
        
        return {k: v for k, v in tls_obj.items() if v is not None}

    def convert_to_singbox(self, config: str) -> Optional[Dict]:
        try:
            config_lower = config.lower()
            outbound = {}

            if config_lower.startswith(('vless://', 'trojan://')):
                is_vless = config_lower.startswith('vless://')
                parsed = urlparse(config)
                params = self._parse_query_params(config)
                
                userinfo, hostinfo = parsed.netloc.split('@', 1)
                host, port_str = hostinfo.rsplit(':', 1)

                outbound = {
                    "type": "vless" if is_vless else "trojan",
                    "server": host,
                    "server_port": int(port_str),
                    "uuid": userinfo if is_vless else None,
                    "password": userinfo if not is_vless else None,
                    "flow": params.get('flow', None) if is_vless else None,
                    "tls": self._build_tls(params, host),
                    "transport": self._build_transport(params)
                }

            elif config_lower.startswith('vmess://'):
                vmess_data = json.loads(self._decode_base64_safe(config[8:]))
                host = vmess_data.get('add', '')
                port = int(vmess_data.get('port', 0))
                params = {k.lower(): v for k, v in vmess_data.items()}

                outbound = {
                    "type": "vmess",
                    "server": host,
                    "server_port": port,
                    "uuid": vmess_data.get('id'),
                    "alter_id": int(vmess_data.get('aid', 0)),
                    "security": vmess_data.get('scy', 'auto'),
                    "tls": self._build_tls(params, host),
                    "transport": self._build_transport(params)
                }

            elif config_lower.startswith('ss://'):
                parsed = urlparse(config)
                params = self._parse_query_params(config)
                if '@' in parsed.netloc:
                    method_pass, host_port = parsed.netloc.split('@', 1)
                    method, password = unquote(method_pass).split(':', 1)
                    host, port = host_port.split(':')
                else:
                    decoded = self._decode_base64_safe(config[5:].split('#')[0])
                    match = re.match(r'(.+?):(.+?)@(.+?):(\d+)', decoded)
                    method, password, host, port = match.groups()

                outbound = {
                    "type": "shadowsocks",
                    "server": host,
                    "server_port": int(port),
                    "method": method,
                    "password": password
                }
                if params.get('plugin') == 'shadow-tls':
                    outbound['plugin'] = 'shadow-tls'
                    outbound['plugin_opts'] = f"host={params.get('host', host)}"
            
            elif config_lower.startswith('ssr://'):
                decoded_str = self._decode_base64_safe(config[6:])
                parts = decoded_str.split(':')
                server, port, protocol, method, obfs, password_b64 = parts
                password = self._decode_base64_safe(password_b64.split('/?')[0])
                params = self._parse_query_params(decoded_str)

                outbound = {
                    "type": "shadowsocksr",
                    "server": server,
                    "server_port": int(port),
                    "method": method,
                    "password": password,
                    "obfs": obfs,
                    "obfs_param": self._decode_base64_safe(params.get('obfsparam', '')),
                    "protocol": protocol,
                    "protocol_param": self._decode_base64_safe(params.get('protoparam', ''))
                }

            elif config_lower.startswith(('hysteria://', 'hysteria2://', 'hy2://')):
                is_hy2 = not config_lower.startswith('hysteria://')
                parsed = urlparse(config)
                params = self._parse_query_params(config)
                host, port = parsed.netloc.split('@')[1].rsplit(':', 1)

                outbound = {
                    "type": "hysteria2" if is_hy2 else "hysteria",
                    "server": host,
                    "server_port": int(port),
                    "password": parsed.username,
                    "tls": {
                        "enabled": True,
                        "insecure": True,
                        "server_name": params.get('sni', host)
                    }
                }
                if not is_hy2: # Hysteria v1 specific params
                    outbound["up_mbps"] = int(params.get("up", 50))
                    outbound["down_mbps"] = int(params.get("down", 100))

            elif config_lower.startswith('snell://'):
                parsed = urlparse(config)
                params = self._parse_query_params(config)
                host, port = parsed.netloc.split('@')[0].rsplit(':', 1)
                
                outbound = {
                    "type": "snell",
                    "server": host,
                    "server_port": int(port),
                    "psk": parsed.username,
                    "version": params.get('version', '3')
                }

            elif config_lower.startswith('ssh://'):
                parsed = urlparse(config)
                params = self._parse_query_params(config)
                outbound = {
                    "type": "ssh",
                    "server": parsed.hostname,
                    "server_port": parsed.port or 22,
                    "user": parsed.username,
                    "password": unquote(parsed.password) if parsed.password else None,
                    "private_key": params.get('pk').replace(" ", "\n") if params.get('pk') else None
                }
            
            else: # Protocol is not supported or recognized
                return None

            # Finalize outbound object
            if outbound.get("server"):
                flag, country = self.get_location(outbound["server"])
                protocol_name = outbound["type"]
                outbound["tag"] = f"{flag} {protocol_name}-{str(uuid.uuid4())[:6]} ({country})"
                return {k: v for k, v in outbound.items() if v is not None}

            return None

        except Exception:
            return None

    def process_configs(self):
        try:
            with open('configs/proxy_configs.txt', 'r', encoding='utf-8') as f:
                configs = f.read().strip().split('\n')
            
            outbounds = []
            valid_tags = []

            for config in configs:
                config = config.strip()
                if not config or config.startswith(('#', '//')):
                    continue
                
                converted = self.convert_to_singbox(config)
                if converted:
                    outbounds.append(converted)
                    if 'tag' in converted and converted['tag']:
                        valid_tags.append(converted['tag'])

            if not outbounds:
                print("No valid outbounds generated.")
                return

            dns_config = {"dns": {"servers": [{"tag": "local", "address": "local"}], "final": "local"}}
            inbounds_config = [{"listen": "127.0.0.1", "listen_port": 2080, "sniff": True, "type": "mixed"}]
            route_config = {"final": "proxy", "rules": []}
            
            selector_outbounds = ["auto-urltest"] + valid_tags + ["direct"]
            final_outbounds = [
                {"tag": "proxy", "type": "selector", "outbounds": selector_outbounds},
                {"tag": "auto-urltest", "type": "urltest", "outbounds": valid_tags, "url": "http://www.gstatic.com/generate_204"},
                {"tag": "direct", "type": "direct"},
            ] + outbounds

            singbox_config = {**dns_config, "inbounds": inbounds_config, "outbounds": final_outbounds, "route": route_config}

            with open(self.output_file, 'w', encoding='utf-8') as f:
                json.dump(singbox_config, f, indent=2, ensure_ascii=False)

        except Exception as e:
            print(f"Error processing configs: {str(e)}")

def main():
    converter = ConfigToSingbox()
    converter.process_configs()

if __name__ == '__main__':
    main()
