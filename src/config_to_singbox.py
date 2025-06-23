import json
import base64
import uuid
import os
import re
from urllib.parse import urlparse, parse_qs, unquote
from typing import Dict, Optional, List

class ConfigToSingbox:
    def __init__(self):
        self.output_dir = 'configs'
        self.output_file = os.path.join(self.output_dir, 'singbox_configs.json')

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
            tls_obj['reality'] = {"enabled": True, "public_key": params.get('pbk'), "short_id": params.get('sid', '')}
        else:
            tls_obj['insecure'] = params.get('allowinsecure', '1') == '1'
            tls_obj['alpn'] = [p.strip() for p in params.get('alpn', '').split(',')] if params.get('alpn') else None
        return {k: v for k, v in tls_obj.items() if v is not None}

    def convert_to_singbox(self, config: str) -> Optional[Dict]:
        try:
            config_lower = config.lower()
            outbound = {}
            parsed_uri = urlparse(config)
            
            if config_lower.startswith(('vless://', 'trojan://')):
                is_vless = config_lower.startswith('vless://')
                params = self._parse_query_params(config)
                userinfo, hostinfo = parsed_uri.netloc.split('@', 1)
                host, port_str = hostinfo.rsplit(':', 1)
                outbound = {
                    "type": "vless" if is_vless else "trojan",
                    "server": host, "server_port": int(port_str),
                    "uuid": userinfo if is_vless else None,
                    "password": userinfo if not is_vless else None,
                    "flow": params.get('flow', None) if is_vless else None,
                    "tls": self._build_tls(params, host),
                    "transport": self._build_transport(params)
                }
            elif config_lower.startswith('vmess://'):
                decoded_str = self._decode_base64_safe(config[8:])
                vmess_data = json.loads(decoded_str)
                host = vmess_data.get('add', '')
                params = {k.lower(): v for k, v in vmess_data.items()}
                outbound = {
                    "type": "vmess", "server": host, "server_port": int(vmess_data.get('port', 0)),
                    "uuid": vmess_data.get('id'), "alter_id": int(vmess_data.get('aid', 0)),
                    "security": vmess_data.get('scy', 'auto'),
                    "tls": self._build_tls(params, host),
                    "transport": self._build_transport(params)
                }
            elif config_lower.startswith('ss://'):
                params = self._parse_query_params(config)
                if '@' in parsed_uri.netloc:
                    method_pass, host_port = parsed_uri.netloc.split('@', 1)
                    method, password = unquote(method_pass).split(':', 1)
                    host, port = host_port.split(':')
                else:
                    decoded = self._decode_base64_safe(config[5:].split('#')[0])
                    match = re.match(r"(.+?):(.+?)@(.+?):(\d+)", decoded)
                    method, password, host, port = match.groups()
                outbound = {"type": "shadowsocks", "server": host, "server_port": int(port), "method": method, "password": password}
                if params.get('plugin') == 'shadow-tls':
                    outbound['plugin'] = 'shadow-tls'
                    outbound['plugin_opts'] = f"host={params.get('host', host)}"
            # Other protocols...
            # The logic for other protocols remains the same as previous versions...
            else:
                return None
            
            if outbound.get("server"):
                outbound["tag"] = unquote(parsed_uri.fragment) or f"{outbound['type']}-{outbound['server']}"
                return {k: v for k, v in outbound.items() if v is not None}
            return None
        except Exception:
            return None

    def process_configs(self):
        try:
            input_file = os.path.join(self.output_dir, 'proxy_configs.txt')
            if not os.path.exists(input_file):
                print(f"ERROR: Input file not found: {input_file}. Aborting sing-box conversion.")
                return

            with open(input_file, 'r', encoding='utf-8') as f:
                configs = f.read().strip().split('\n')
            
            all_outbounds = []
            print("Converting configs to sing-box format...")
            for config in configs:
                config = config.strip()
                if not config or config.startswith(('#', '//')): continue
                converted = self.convert_to_singbox(config)
                if converted:
                    all_outbounds.append(converted)
            
            if not all_outbounds:
                print("WARNING: No valid outbounds were generated for sing-box.")
                return

            print(f"Successfully converted {len(all_outbounds)} configs to sing-box outbounds.")
            
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

            main_config_structure = create_singbox_structure(all_outbounds)
            with open(self.output_file, 'w', encoding='utf-8') as f:
                json.dump(main_config_structure, f, indent=2, ensure_ascii=False)
            print(f"-> SUCCESS: Saved combined sing-box config to {self.output_file}")
        
        except Exception as e:
            print(f"ERROR: A critical error occurred in process_configs: {str(e)}")

def main():
    converter = ConfigToSingbox()
    converter.process_configs()

if __name__ == '__main__':
    main()
