# File: src/config_to_clash.py
# (The definitive, final, fully-audited and corrected version)

import os
import re
import yaml
import base64
import json
import socket
from urllib.parse import urlparse, parse_qs, unquote
from typing import Optional, Dict, List
import copy
from nacl.public import PrivateKey

# Assuming utils.py exists in the same directory (src/)
from utils import get_random_user_agent, generate_unique_name, clean_proxy_name

class UriToClashConverter:
    """
    An advanced and comprehensive helper class to convert various proxy URI schemes
    into Clash-compatible dictionaries, with extended parameter support and robustness.
    """
    SUPPORTED_SS_CIPHERS = {
        "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "aes-128-cfb", "aes-192-cfb",
        "aes-256-cfb", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "chacha20-ietf-poly1305",
        "xchacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
        "2022-blake3-chacha20-poly1305", "rc4-md5", "none"
    }
    DEPRECATED_CIPHERS = {'rc4-md5', 'aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb', 'chacha20'}


    @staticmethod
    def _is_valid_server_port(server: str, port: any) -> bool:
        if not server or port is None: return False
        try:
            if not (1 <= int(port) <= 65535): return False
        except (ValueError, TypeError): return False
        # Basic validation for IP addresses and hostnames
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", server):
             return True
        if re.match(r"^[a-zA-Z0-9.-]+$", server):
             return True
        return False


    @staticmethod
    def parse(uri: str, filter_deprecated: bool = False) -> Optional[Dict]:
        try:
            scheme = uri.split("://")[0]
            parsers = {
                "vless": UriToClashConverter.parse_vless_trojan, "trojan": UriToClashConverter.parse_vless_trojan,
                "ss": UriToClashConverter.parse_ss, "ssr": UriToClashConverter.parse_ssr,
                "vmess": UriToClashConverter.parse_vmess, "hysteria": UriToClashConverter.parse_hysteria,
                "hysteria2": UriToClashConverter.parse_hysteria2, "tuic": UriToClashConverter.parse_tuic,
                "snell": UriToClashConverter.parse_snell, "ssh": UriToClashConverter.parse_ssh,
                "wireguard": UriToClashConverter.parse_wireguard, "anytls": UriToClashConverter.parse_anytls,
                "mieru": UriToClashConverter.parse_mieru,
            }
            if scheme in parsers:
                proxy = parsers[scheme](uri)
                if proxy and filter_deprecated and proxy.get('cipher') in UriToClashConverter.DEPRECATED_CIPHERS:
                    return None
                return proxy
        except Exception:
            pass
        return None

    @staticmethod
    def _get_params(uri: str) -> Dict:
        return parse_qs(urlparse(uri).query)

    # ... (All other corrected parsers like parse_vmess, parse_vless_trojan, etc. remain here) ...
    # This is the full code, so all methods are included.
    
    @staticmethod
    def parse_vmess(uri: str) -> Optional[Dict]:
        try:
            decoded_str = base64.b64decode(uri[8:]).decode('utf-8')
            vmess_data = json.loads(decoded_str)
        except:
            return None

        if not UriToClashConverter._is_valid_server_port(vmess_data.get('add'), vmess_data.get('port')):
            return None

        host = vmess_data.get('add')
        supported_ciphers = {'auto', 'aes-128-gcm', 'chacha20-poly1305', 'none'}
        original_cipher = vmess_data.get('scy', 'auto').lower()

        proxy = {
            "name": vmess_data.get('ps', f"vmess-{host}"),
            "type": "vmess",
            "server": host,
            "port": int(vmess_data.get('port')),
            "uuid": vmess_data.get('id'),
            "alterId": int(vmess_data.get('aid', 0)),
            "cipher": original_cipher if original_cipher in supported_ciphers else 'auto',
            "udp": True,
            "network": vmess_data.get('net', 'tcp'),
        }

        if vmess_data.get('tls') in ['tls', 'reality']:
            proxy['tls'] = True
            sni = vmess_data.get('sni') or vmess_data.get('host') or host
            proxy['servername'] = sni
            proxy['skip-cert-verify'] = True

        network = proxy.get("network")
        if network == "ws":
            ws_host = vmess_data.get('host', host) or host
            proxy['ws-opts'] = {
                'path': vmess_data.get('path', '/'),
                'headers': {
                    'Host': ws_host,
                    'User-Agent': get_random_user_agent()
                }
            }
        elif network == "h2":
             proxy['h2-opts'] = {
                 'host': [vmess_data.get('host', host) or host],
                 'path': vmess_data.get('path', '/')
             }
        elif network == "grpc":
            proxy['grpc-opts'] = {
                'grpc-service-name': vmess_data.get('path', '')
            }

        return proxy

    @staticmethod
    def parse_vless_trojan(uri: str) -> Optional[Dict]:
        parsed_uri = urlparse(uri)
        if not UriToClashConverter._is_valid_server_port(parsed_uri.hostname, parsed_uri.port) or not parsed_uri.username: return None
        params = UriToClashConverter._get_params(uri)
        proxy = {"name": unquote(parsed_uri.fragment) or f"{parsed_uri.scheme}-{parsed_uri.hostname}", "type": parsed_uri.scheme, "server": parsed_uri.hostname, "port": int(parsed_uri.port), "udp": True}
        
        if parsed_uri.scheme == 'vless':
            proxy['uuid'] = parsed_uri.username
            if 'flow' in params: proxy['flow'] = params['flow'][0]
        else: # trojan
            proxy['password'] = parsed_uri.username
        
        proxy['network'] = params.get('type', ['tcp'])[0]
        
        if proxy['network'] == 'ws':
            ws_opts = {
                'path': params.get('path', ['/'])[0],
                'headers': {
                    'Host': params.get('host', [proxy['server']])[0] or proxy['server'],
                    'User-Agent': get_random_user_agent()
                }
            }
            if 'ed' in params:
                try:
                    ws_opts['max-early-data'] = int(params['ed'][0])
                    ws_opts['early-data-header-name'] = 'Sec-WebSocket-Protocol'
                except: pass
            proxy['ws-opts'] = ws_opts
        elif proxy['network'] == 'grpc': 
            proxy['grpc-opts'] = {'grpc-service-name': params.get('serviceName', [''])[0]}
        elif proxy['network'] == 'tcp' and params.get('headerType', ['none'])[0] == 'http':
            host = params.get('host', [proxy['server']])[0] or proxy['server']
            path = params.get('path', ['/'])[0].split(',')
            proxy['network'] = 'http'
            proxy['http-opts'] = {
                'method': 'GET',
                'path': path,
                'headers': {'Host': [host]}
            }

        security = params.get('security', ['none'])[0]
        if security == 'tls':
            proxy['tls'] = True
            proxy['servername'] = params.get('sni', [proxy['server']])[0] or proxy['server']
            proxy['skip-cert-verify'] = True
            if 'alpn' in params: proxy['alpn'] = params['alpn'][0].split(',')
            if 'fp' in params: proxy['client-fingerprint'] = params['fp'][0]
        elif security == 'reality':
            proxy['tls'] = True
            proxy['servername'] = params.get('sni', [proxy['server']])[0] or proxy['server']
            proxy['client-fingerprint'] = params.get('fp', ['chrome'])[0]
            proxy['reality-opts'] = {'public-key': params.get('pbk', [''])[0], 'short-id': params.get('sid', [''])[0]}
            
        return proxy

    @staticmethod
    def parse_ss(uri: str) -> Optional[Dict]:
        parsed_uri = urlparse(uri)
        name = unquote(parsed_uri.fragment)
        
        server, port, cipher, password = None, None, None, None
        
        if '@' in parsed_uri.netloc:
            server = parsed_uri.hostname
            port = parsed_uri.port
            user_info = parsed_uri.netloc.split('@', 1)[0]
            decoded_user_info = unquote(user_info)
            if ':' in decoded_user_info:
                parts = decoded_user_info.split(':', 1)
                if len(parts) == 2: cipher, password = parts
            else:
                try:
                    decoded = base64.b64decode(decoded_user_info + '===').decode('utf-8')
                    parts = decoded.split(':', 1)
                    if len(parts) == 2: cipher, password = parts
                except: return None
        else:
            try:
                full_decoded = base64.b64decode(unquote(uri[5:].split('#')[0]) + '===').decode('utf-8')
                match = re.match(r'(.+?):(.+?)@(.+?):(\d+)', full_decoded)
                if match:
                    cipher, password, server, port = match.groups()
            except: return None
            
        if not all([server, port, cipher, password]) or not UriToClashConverter._is_valid_server_port(server, port):
            return None

        cipher_lower = cipher.lower()
        if cipher_lower not in UriToClashConverter.SUPPORTED_SS_CIPHERS: return None
        
        cipher_map = {'chacha20-poly1305': 'chacha20-ietf-poly1305'}
        normalized_cipher = cipher_map.get(cipher_lower, cipher_lower)
        
        proxy = {
            "name": name or f"ss-{server}",
            "type": "ss",
            "server": server,
            "port": int(port),
            "cipher": normalized_cipher,
            "password": password,
            "udp": True
        }
        
        params = UriToClashConverter._get_params(uri)
        if 'plugin' in params:
            plugin_name = params['plugin'][0]
            proxy['plugin'] = plugin_name
            opts = {}
            if plugin_name == 'obfs':
                opts['mode'] = params.get('obfs', [''])[0] or params.get('mode', [''])[0]
                opts['host'] = params.get('obfs-host', [''])[0] or params.get('host', [''])[0]
            elif plugin_name == 'v2ray-plugin':
                opts['mode'] = params.get('mode', ['websocket'])[0]
                if params.get('tls', ['false'])[0] == 'true': opts['tls'] = True
                opts['path'] = params.get('path', ['/'])[0]
                opts['host'] = params.get('host', [proxy['server']])[0]
            elif plugin_name == 'shadow-tls':
                opts['password'] = params.get('password', [''])[0]
                opts['version'] = int(params.get('version', [2])[0])
            proxy['plugin-opts'] = {k: v for k, v in opts.items() if v}
            
        return proxy

    @staticmethod
    def parse_ssr(uri: str) -> Optional[Dict]:
        try:
            decoded_str = base64.b64decode(uri[6:].rstrip('=') + '===').decode('utf-8'); parts = decoded_str.split(':')
            if len(parts) < 6: return None
            server, port_str, protocol, method, obfs, password_b64_and_params = parts[0:6]; port = int(port_str)
            if not UriToClashConverter._is_valid_server_port(server, port): return None
            password_b64 = password_b64_and_params.split('/?')[0]; password = base64.b64decode(password_b64 + '===').decode('utf-8'); params = parse_qs(urlparse(decoded_str).query)
            proxy = {"name": base64.b64decode(params.get('remarks', [''])[0] + '===').decode('utf-8') or f"ssr-{server}", "type": "ssr", "server": server, "port": int(port), "cipher": method, "password": password, "obfs": obfs, "protocol": protocol, "obfs-param": base64.b64decode(params.get('obfsparam', [''])[0] + '===').decode('utf-8'), "protocol-param": base64.b64decode(params.get('protoparam', [''])[0] + '===').decode('utf-8'), "udp": True}
            return proxy
        except: return None
    
    @staticmethod
    def parse_hysteria(uri: str) -> Optional[Dict]:
        parsed_uri = urlparse(uri)
        if not UriToClashConverter._is_valid_server_port(parsed_uri.hostname, parsed_uri.port): return None

        params = UriToClashConverter._get_params(uri)
        auth_string = parsed_uri.username or params.get('auth', [None])[0]
        if not auth_string: return None
        
        try:
            up = params.get('up', [''])[0] or params.get('upmbps', ['50'])[0]
            down = params.get('down', [''])[0] or params.get('downmbps', ['100'])[0]
            up_speed = int(up)
            down_speed = int(down)
        except (ValueError, TypeError):
            up_speed, down_speed = 50, 100

        proxy = {
            "name": unquote(parsed_uri.fragment) or f"hysteria-{parsed_uri.hostname}",
            "type": "hysteria",
            "server": parsed_uri.hostname,
            "port": int(parsed_uri.port),
            "auth-str": auth_string,
            "up": up_speed,
            "down": down_speed,
            "protocol": params.get('protocol', [None])[0],
            "sni": params.get('sni', [''])[0] or params.get('peer', [parsed_uri.hostname])[0],
            "obfs": params.get('obfs', [None])[0],
            "skip-cert-verify": params.get('insecure', ['1'])[0] in ['1', 'true']
        }
        return {k: v for k, v in proxy.items() if v is not None}

    @staticmethod
    def parse_hysteria2(uri: str) -> Optional[Dict]:
        parsed_uri = urlparse(uri)
        if not UriToClashConverter._is_valid_server_port(parsed_uri.hostname, parsed_uri.port): return None
        params = UriToClashConverter._get_params(uri)
        proxy = {
            "name": unquote(parsed_uri.fragment) or f"hysteria2-{parsed_uri.hostname}",
            "type": "hysteria2",
            "server": parsed_uri.hostname,
            "port": int(parsed_uri.port),
            "password": parsed_uri.username,
            "sni": params.get('sni', [''])[0] or params.get('peer', [parsed_uri.hostname])[0],
            "skip-cert-verify": params.get('insecure', ['1'])[0] in ['1', 'true'],
            "fingerprint": params.get('pinSHA256', [None])[0]
        }
        if 'obfs' in params:
            proxy['obfs'] = params['obfs'][0]
            if 'obfs-password' in params:
                proxy['obfs-password'] = params['obfs-password'][0]

        return {k: v for k, v in proxy.items() if v is not None}

    @staticmethod
    def parse_tuic(uri: str) -> Optional[Dict]:
        parsed_uri = urlparse(uri)
        if not UriToClashConverter._is_valid_server_port(parsed_uri.hostname, parsed_uri.port): return None
        if not parsed_uri.username: return None
        
        params = UriToClashConverter._get_params(uri)
        proxy = {
            "name": unquote(parsed_uri.fragment) or f"tuic-{parsed_uri.hostname}", 
            "type": "tuic", 
            "server": parsed_uri.hostname, 
            "port": int(parsed_uri.port), 
            "sni": params.get('sni', [parsed_uri.hostname])[0], 
            "alpn": [params.get('alpn', ['h3'])[0]], 
            "skip-cert-verify": True, 
            "udp-relay-mode": params.get('udp-relay-mode', ['native'])[0],
            "congestion-control": params.get('congestion_control', [None])[0],
            "disable-sni": params.get('disable_sni', ['0'])[0] == '1'
        }
        
        if ':' in parsed_uri.username:
            uuid, password = parsed_uri.username.split(':', 1)
            proxy['uuid'] = uuid
            proxy['password'] = password
        else:
            proxy['token'] = parsed_uri.username

        return {k: v for k, v in proxy.items() if v is not None and v is not False}

    @staticmethod
    def parse_snell(uri: str) -> Optional[Dict]:
        parsed_uri = urlparse(uri)
        if not UriToClashConverter._is_valid_server_port(parsed_uri.hostname, parsed_uri.port): return None
        params = UriToClashConverter._get_params(uri)
        proxy = {"name": unquote(parsed_uri.fragment) or f"snell-{parsed_uri.hostname}", "type": "snell", "server": parsed_uri.hostname, "port": int(parsed_uri.port), "psk": parsed_uri.username, "version": params.get('version', ['3'])[0]}
        if 'obfs' in params: proxy['obfs-opts'] = {'mode': params['obfs'][0]}
        return proxy

    @staticmethod
    def parse_ssh(uri: str) -> Optional[Dict]:
        parsed_uri = urlparse(uri)
        if not UriToClashConverter._is_valid_server_port(parsed_uri.hostname, parsed_uri.port or 22): return None
        proxy = {"name": unquote(parsed_uri.fragment) or f"ssh-{parsed_uri.hostname}", "type": "ssh", "server": parsed_uri.hostname, "port": int(parsed_uri.port or 22), "username": parsed_uri.username, "password": parsed_uri.password}
        return {k: v for k, v in proxy.items() if v is not None}

    @staticmethod
    def parse_wireguard(uri: str) -> Optional[Dict]:
        parsed_uri = urlparse(uri)
        if not UriToClashConverter._is_valid_server_port(parsed_uri.hostname, parsed_uri.port) or not parsed_uri.username: return None
        params = UriToClashConverter._get_params(uri)
        private_key_b64 = unquote(parsed_uri.username)
        
        public_key_b64 = params.get('publicKey', [''])[0] or params.get('publickey', [''])[0]

        if not public_key_b64:
            try:
                private_key_bytes = base64.b64decode(private_key_b64)
                priv_key_obj = PrivateKey(private_key_bytes)
                pub_key_obj = priv_key_obj.public_key
                public_key_b64 = base64.b64encode(bytes(pub_key_obj)).decode('utf-8')
            except Exception as e:
                print(f"Could not generate public key for a wireguard config, skipping. Error: {e}")
                return None

        proxy = {"name": unquote(parsed_uri.fragment) or f"wg-{parsed_uri.hostname}", "type": "wireguard", "server": parsed_uri.hostname, "port": int(parsed_uri.port), "private-key": private_key_b64, "public-key": public_key_b64, "udp": True}
        
        if 'address' in params:
            addresses = params['address'][0].split(',')
            for addr in addresses:
                addr = addr.strip()
                if ':' in addr: proxy['ipv6'] = addr
                elif '.' in addr: proxy['ip'] = addr
        
        # [FINAL FIX] Discard config if local address is missing
        if 'ip' not in proxy and 'ipv6' not in proxy:
            return None
        
        if 'presharedKey' in params: proxy['pre-shared-key'] = params['presharedKey'][0]
        if 'mtu' in params: proxy['mtu'] = int(params['mtu'][0])
        if 'dns' in params: proxy['dns'] = [d.strip() for d in params['dns'][0].split(',')]
            
        return proxy

    @staticmethod
    def parse_anytls(uri: str) -> Optional[Dict]:
        parsed_uri = urlparse(uri)
        if not UriToClashConverter._is_valid_server_port(parsed_uri.hostname, parsed_uri.port): return None
        params = UriToClashConverter._get_params(uri)
        proxy = {"name": unquote(parsed_uri.fragment) or f"anytls-{parsed_uri.hostname}", "type": "anytls", "server": parsed_uri.hostname, "port": int(parsed_uri.port), "password": parsed_uri.username, "client-fingerprint": params.get('fp', ['chrome'])[0], "sni": params.get('sni', [parsed_uri.hostname])[0], "alpn": params.get('alpn', ['h2,http/1.1'])[0].split(','), "skip-cert-verify": True, "udp": True}
        return proxy

    @staticmethod
    def parse_mieru(uri: str) -> Optional[Dict]:
        parsed_uri = urlparse(uri)
        if not UriToClashConverter._is_valid_server_port(parsed_uri.hostname, parsed_uri.port): return None
        params = UriToClashConverter._get_params(uri)
        proxy = {"name": unquote(parsed_uri.fragment) or f"mieru-{parsed_uri.hostname}", "type": "mieru", "server": parsed_uri.hostname, "port": int(parsed_uri.port), "username": parsed_uri.username, "password": params.get('password', [''])[0], "transport": "TCP", "multiplexing": "MULTIPLEXING_LOW"}
        return proxy

def replace_placeholders(data, proxy_names):
    if isinstance(data, dict):
        for key, value in data.items(): data[key] = replace_placeholders(value, proxy_names)
    elif isinstance(data, list):
        new_list = []
        for item in data:
            if isinstance(item, str) and item == 'ALL_PROXIES_PLACEHOLDER':
                new_list.extend(proxy_names)
            else:
                new_list.append(replace_placeholders(item, proxy_names))
        return new_list
    return data

def main():
    # These would be read from user_settings.py
    APPEND_PROTOCOL_TO_NAME = True
    FILTER_DEPRECATED = True

    configs_dir = 'configs'; templates_dir = 'templates'
    input_file_path = os.path.join(configs_dir, 'proxy_configs.txt')
    if not os.path.exists(input_file_path): print(f"ERROR: Input file not found: {input_file_path}"); return
    
    with open(input_file_path, 'r', encoding='utf-8') as f: all_uris = f.read().strip().split()
    
    all_clash_proxies = []
    for uri in all_uris:
        clash_proxy = UriToClashConverter.parse(uri, filter_deprecated=FILTER_DEPRECATED)
        if clash_proxy:
            if APPEND_PROTOCOL_TO_NAME:
                type_name = clash_proxy['type'].upper()
                if not clash_proxy['name'].startswith(f"[{type_name}]"):
                    clash_proxy['name'] = f"[{type_name}] {clash_proxy['name']}"
            all_clash_proxies.append(clash_proxy)

    name_counts = {}; unique_named_proxies = []
    for proxy in all_clash_proxies:
        original_name = clean_proxy_name(proxy.get('name', 'proxy'))
        proxy['name'] = generate_unique_name(name_counts, original_name)
        unique_named_proxies.append(proxy)

    all_clash_proxies = unique_named_proxies
    
    if not all_clash_proxies: print("WARNING: No valid Clash-compatible proxies were generated."); return
    print(f"Successfully converted and de-duplicated {len(all_clash_proxies)} URIs to Clash format.")
    
    if not os.path.isdir(templates_dir): print(f"ERROR: Templates directory '{templates_dir}' not found."); return
    
    template_files = [f for f in os.listdir(templates_dir) if f.endswith(('.yaml', '.yml'))]
    if not template_files: print(f"WARNING: No templates found in '{templates_dir}'."); return
    
    for template_file in template_files:
        template_path = os.path.join(templates_dir, template_file)
        template_base_name = os.path.splitext(template_file)[0]
        print(f"\n--- Processing template: {template_file} ---")
        
        with open(template_path, 'r', encoding='utf-8') as f: template_data = yaml.safe_load(f)
        
        proxy_names = [p['name'] for p in all_clash_proxies]
        combined_data = copy.deepcopy(template_data)
        if 'proxies' not in combined_data: combined_data['proxies'] = []
        combined_data['proxies'].extend(all_clash_proxies)

        if 'proxy-groups' in combined_data:
            replace_placeholders(combined_data['proxy-groups'], proxy_names)
        
        output_filename = os.path.join(configs_dir, f"{template_base_name}_combined.yaml")
        with open(output_filename, 'w', encoding='utf-8') as f: yaml.dump(combined_data, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
        print(f"-> Saved combined Clash config to: {output_filename}")
        
        categorized_proxies = {}
        for proxy in all_clash_proxies:
            ptype = proxy.get('type')
            if ptype not in categorized_proxies: categorized_proxies[ptype] = []
            categorized_proxies[ptype].append(proxy)
        
        for ptype, proxies_list in categorized_proxies.items():
            if not proxies_list: continue
            per_protocol_data = copy.deepcopy(template_data)
            if 'proxies' not in per_protocol_data: per_protocol_data['proxies'] = []
            per_protocol_data['proxies'].extend(proxies_list)

            per_protocol_proxy_names = [p['name'] for p in proxies_list]
            if 'proxy-groups' in per_protocol_data:
                replace_placeholders(per_protocol_data['proxy-groups'], per_protocol_proxy_names)
            
            output_filename = os.path.join(configs_dir, f"{template_base_name}_{ptype}.yaml")
            with open(output_filename, 'w', encoding='utf-8') as f: yaml.dump(per_protocol_data, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
            print(f"-> Saved {ptype}-only Clash config to: {output_filename}")

if __name__ == "__main__":
    main()