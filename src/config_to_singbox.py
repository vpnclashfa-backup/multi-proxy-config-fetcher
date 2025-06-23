import json
import base64
import uuid
import time
import socket
import requests
import os
import re
from typing import Dict, Optional, Tuple, List
from urllib.parse import urlparse, parse_qs, unquote

class ConfigToSingbox:
    def __init__(self):
        self.output_dir = 'configs'
        self.output_file = os.path.join(self.output_dir, 'singbox_configs.json')
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        self.ip_location_cache: Dict[str, Tuple[str, str]] = {}

    # ... (All helper methods like get_location, _decode_base64_safe, parsers, etc. from the previous step remain unchanged) ...
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
            
            else: 
                return None

            if outbound.get("server"):
                flag, country = self.get_location(outbound["server"])
                protocol_name = outbound["type"]
                outbound["tag"] = f"{flag} {protocol_name}-{str(uuid.uuid4())[:6]} ({country})"
                return {k: v for k, v in outbound.items() if v is not None}

            return None

        except Exception:
            return None

    def process_configs(self):
        """
        MODIFIED: Now categorizes outbounds and saves separate JSON files for each protocol.
        """
        try:
            input_file = os.path.join(self.output_dir, 'proxy_configs.txt')
            with open(input_file, 'r', encoding='utf-8') as f:
                # Read all configs from the main text file
                configs = f.read().strip().split('\n')
            
            all_outbounds = []
            for config in configs:
                config = config.strip()
                if not config or config.startswith(('#', '//')):
                    continue
                
                converted = self.convert_to_singbox(config)
                if converted:
                    all_outbounds.append(converted)

            if not all_outbounds:
                print("No valid outbounds were generated.")
                return

            # --- Categorize outbounds by protocol type ---
            categorized_outbounds: Dict[str, List[Dict]] = {}
            for outbound in all_outbounds:
                proto_type = outbound.get('type')
                if proto_type:
                    if proto_type not in categorized_outbounds:
                        categorized_outbounds[proto_type] = []
                    categorized_outbounds[proto_type].append(outbound)

            # --- Define boilerplate for sing-box configs ---
            def create_singbox_structure(outbounds: List[Dict]) -> Dict:
                tags = [o['tag'] for o in outbounds if 'tag' in o]
                selector_outbounds = ["auto-urltest"] + tags + ["direct"]
                final_outbounds = [
                    {"tag": "proxy", "type": "selector", "outbounds": selector_outbounds},
                    {"tag": "auto-urltest", "type": "urltest", "outbounds": tags, "url": "http://www.gstatic.com/generate_204"},
                    {"tag": "direct", "type": "direct"},
                ] + outbounds
                
                return {
                    "dns": {"servers": [{"tag": "local", "address": "local"}], "final": "local"},
                    "inbounds": [{"listen": "127.0.0.1", "listen_port": 2080, "sniff": True, "type": "mixed"}],
                    "outbounds": final_outbounds,
                    "route": {"final": "proxy", "rules": []}
                }

            # --- Save the main combined JSON file ---
            main_config_structure = create_singbox_structure(all_outbounds)
            with open(self.output_file, 'w', encoding='utf-8') as f:
                json.dump(main_config_structure, f, indent=2, ensure_ascii=False)
            print(f"Successfully saved combined sing-box config to {self.output_file}")

            # --- Save per-protocol JSON files ---
            for proto_type, outbounds_list in categorized_outbounds.items():
                protocol_config_structure = create_singbox_structure(outbounds_list)
                protocol_filename = os.path.join(self.output_dir, f"singbox_{proto_type}.json")
                with open(protocol_filename, 'w', encoding='utf-8') as f:
                    json.dump(protocol_config_structure, f, indent=2, ensure_ascii=False)
                print(f"Successfully saved {proto_type}-only sing-box config to {protocol_filename}")


        except Exception as e:
            print(f"Error processing configs: {str(e)}")

def main():
    converter = ConfigToSingbox()
    converter.process_configs()

if __name__ == '__main__':
    main()
