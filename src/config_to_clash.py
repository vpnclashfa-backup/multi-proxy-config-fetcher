import os
import re
import yaml
import base64
import json
import socket
from urllib.parse import urlparse, parse_qs, unquote
from typing import Optional, Dict, List
import copy

class UriToClashConverter:
    """
    A comprehensive helper class to convert various proxy URI schemes 
    into Clash-compatible dictionaries, with per-protocol validation and normalization.
    """
    @staticmethod
    def _is_valid_server_port(server: str, port: int) -> bool:
        if not server or not port: return False
        try:
            if not (1 <= int(port) <= 65535): return False
        except (ValueError, TypeError): return False
        try:
            socket.inet_pton(socket.AF_INET6, server)
            return True
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET, server)
                return True
            except socket.error:
                if re.match(r"^(?!-)[A-Z\d-]{1,63}(?<!-)(\.[A-Z\d-]{1,63}(?<!-))*\.?$", server, re.IGNORECASE):
                    return True
        return False

    @staticmethod
    def parse(uri: str) -> Optional[Dict]:
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
                return parsers[scheme](uri)
        except Exception:
            pass
        return None

    @staticmethod
    def _get_params(uri: str) -> Dict:
        return parse_qs(urlparse(uri).query)

    @staticmethod
    def parse_ss(uri: str) -> Optional[Dict]:
        """
        MODIFIED: Added cipher name normalization.
        """
        parsed_uri = urlparse(uri)
        if not UriToClashConverter._is_valid_server_port(parsed_uri.hostname, parsed_uri.port):
            return None
            
        params = UriToClashConverter._get_params(uri)
        
        # --- Cipher and Password Extraction ---
        if '@' in parsed_uri.netloc:
            user_info, host_info = parsed_uri.netloc.split('@', 1)
            try:
                decoded_user_info = unquote(user_info)
                cipher, password = decoded_user_info.split(':', 1)
            except (ValueError, TypeError):
                decoded_user_info = base64.b64decode(unquote(user_info) + '===').decode('utf-8')
                cipher, password = decoded_user_info.split(':', 1)
        else:
            decoded_full = base64.b64decode(unquote(parsed_uri.netloc) + '===').decode('utf-8')
            match = re.match(r'(.+?):(.+)', decoded_full)
            cipher, password = match.groups()

        # --- NEW: Cipher Normalization ---
        cipher_map = {
            'chacha20-poly1305': 'chacha20-ietf-poly1305',
            'aes-256-gcm': 'aes-256-gcm', # It's already standard but good to have
            'aes-128-gcm': 'aes-128-gcm',
            # Add other common non-standard names here if needed
        }
        normalized_cipher = cipher_map.get(cipher.lower(), cipher)
        
        proxy = {
            "name": unquote(parsed_uri.fragment) or f"ss-{parsed_uri.hostname}",
            "type": "ss", "server": parsed_uri.hostname, "port": parsed_uri.port,
            "cipher": normalized_cipher, # Use the normalized cipher
            "password": password, "udp": True
        }
        
        if 'plugin' in params:
            proxy['plugin'] = params['plugin'][0]
            proxy['plugin-opts'] = {
                'mode': params.get('obfs', [''])[0] or params.get('mode', [''])[0],
                'host': params.get('obfs-host', [''])[0] or params.get('host', [''])[0]
            }
            if params.get('path'): proxy['plugin-opts']['path'] = params.get('path')[0]
            if params.get('tls', ['false'])[0] == 'true': proxy['plugin-opts']['tls'] = True
            
        return proxy

    # ... (The rest of the parsers and functions remain unchanged) ...
    @staticmethod
    def parse_vless_trojan(uri: str) -> Optional[Dict]:
        parsed_uri = urlparse(uri);
        if not UriToClashConverter._is_valid_server_port(parsed_uri.hostname, parsed_uri.port) or not parsed_uri.username: return None
        params = UriToClashConverter._get_params(uri)
        proxy = {"name": unquote(parsed_uri.fragment) or f"{parsed_uri.scheme}-{parsed_uri.hostname}", "type": parsed_uri.scheme, "server": parsed_uri.hostname, "port": parsed_uri.port, "udp": True}
        if parsed_uri.scheme == 'vless':
            proxy['uuid'] = parsed_uri.username
            if params.get('flow'): proxy['flow'] = params['flow'][0]
        else: proxy['password'] = parsed_uri.username
        proxy['network'] = params.get('type', ['tcp'])[0]
        if proxy['network'] == 'ws': proxy['ws-opts'] = {'path': params.get('path', ['/'])[0], 'headers': {'Host': params.get('host', [proxy['server']])[0]}}
        elif proxy['network'] == 'grpc': proxy['grpc-opts'] = {'grpc-service-name': params.get('serviceName', [''])[0]}
        security = params.get('security', ['none'])[0]
        if security == 'tls':
            proxy['tls'] = True; proxy['servername'] = params.get('sni', [proxy['server']])[0]; proxy['skip-cert-verify'] = True
            if params.get('alpn'): proxy['alpn'] = params['alpn'][0].split(',')
            if params.get('fp'): proxy['client-fingerprint'] = params['fp'][0]
        elif security == 'reality':
            proxy['tls'] = True; proxy['servername'] = params.get('sni', [proxy['server']])[0]; proxy['client-fingerprint'] = params.get('fp', ['chrome'])[0]
            proxy['reality-opts'] = {'public-key': params.get('pbk', [''])[0], 'short-id': params.get('sid', [''])[0]}
        return proxy
    @staticmethod
    def parse_ssr(uri: str) -> Optional[Dict]:
        try:
            decoded_str = base64.b64decode(uri[6:].rstrip('=') + '===').decode('utf-8'); parts = decoded_str.split(':')
            if len(parts) < 6: return None
            server, port_str, protocol, method, obfs, password_b64_and_params = parts[0:6]; port = int(port_str)
            if not UriToClashConverter._is_valid_server_port(server, port): return None
            password_b64 = password_b64_and_params.split('/?')[0]; password = base64.b64decode(password_b64 + '===').decode('utf-8'); params = parse_qs(urlparse(decoded_str).query)
            proxy = {"name": base64.b64decode(params.get('remarks', [''])[0] + '===').decode('utf-8') or f"ssr-{server}", "type": "ssr", "server": server, "port": port, "cipher": method, "password": password, "obfs": obfs, "protocol": protocol, "obfs-param": base64.b64decode(params.get('obfsparam', [''])[0] + '===').decode('utf-8'), "protocol-param": base64.b64decode(params.get('protoparam', [''])[0] + '===').decode('utf-8'), "udp": True}
            return proxy
        except: return None
    @staticmethod
    def parse_vmess(uri: str) -> Optional[Dict]:
        decoded_str = base64.b64decode(uri[8:]).decode('utf-8'); vmess_data = json.loads(decoded_str)
        if not UriToClashConverter._is_valid_server_port(vmess_data.get('add'), vmess_data.get('port')): return None
        proxy = {"name": vmess_data.get('ps', f"vmess-{vmess_data.get('add')}"), "type": "vmess", "server": vmess_data.get('add'), "port": int(vmess_data.get('port')), "uuid": vmess_data.get('id'), "alterId": int(vmess_data.get('aid', 0)), "cipher": vmess_data.get('scy', 'auto'), "udp": True, "network": vmess_data.get('net', 'tcp'),}
        if vmess_data.get('tls') in ['tls', 'reality']: proxy['tls'] = True; proxy['servername'] = vmess_data.get('sni', vmess_data.get('add')); proxy['skip-cert-verify'] = True
        if vmess_data.get('net') == 'ws': proxy['ws-opts'] = {'path': vmess_data.get('path', '/'), 'headers': {'Host': vmess_data.get('host', vmess_data.get('add'))}}
        return proxy
    @staticmethod
    def parse_hysteria(uri: str) -> Optional[Dict]:
        parsed_uri = urlparse(uri)
        if not UriToClashConverter._is_valid_server_port(parsed_uri.hostname, parsed_uri.port): return None
        params = UriToClashConverter._get_params(uri)
        proxy = {"name": unquote(parsed_uri.fragment) or f"hysteria-{parsed_uri.hostname}", "type": "hysteria", "server": parsed_uri.hostname, "port": parsed_uri.port, "auth-str": parsed_uri.username, "up": params.get('up', ['50'])[0], "down": params.get('down', ['100'])[0], "protocol": params.get('protocol', [None])[0], "sni": params.get('sni', [parsed_uri.hostname])[0], "skip-cert-verify": True}
        return {k: v for k, v in proxy.items() if v is not None}
    @staticmethod
    def parse_hysteria2(uri: str) -> Optional[Dict]:
        parsed_uri = urlparse(uri)
        if not UriToClashConverter._is_valid_server_port(parsed_uri.hostname, parsed_uri.port): return None
        params = UriToClashConverter._get_params(uri)
        proxy = {"name": unquote(parsed_uri.fragment) or f"hysteria2-{parsed_uri.hostname}", "type": "hysteria2", "server": parsed_uri.hostname, "port": parsed_uri.port, "password": parsed_uri.username, "sni": params.get('sni', [parsed_uri.hostname])[0], "skip-cert-verify": True}
        return proxy
    @staticmethod
    def parse_tuic(uri: str) -> Optional[Dict]:
        parsed_uri = urlparse(uri)
        if not UriToClashConverter._is_valid_server_port(parsed_uri.hostname, parsed_uri.port): return None
        params = UriToClashConverter._get_params(uri); uuid, password = parsed_uri.username.split(':', 1)
        proxy = {"name": unquote(parsed_uri.fragment) or f"tuic-{parsed_uri.hostname}", "type": "tuic", "server": parsed_uri.hostname, "port": parsed_uri.port, "uuid": uuid, "password": password, "sni": params.get('sni', [parsed_uri.hostname])[0], "alpn": [params.get('alpn', ['h3'])[0]], "skip-cert-verify": True, "udp-relay-mode": params.get('udp-relay-mode', ['native'])[0]}
        return proxy
    @staticmethod
    def parse_snell(uri: str) -> Optional[Dict]:
        parsed_uri = urlparse(uri)
        if not UriToClashConverter._is_valid_server_port(parsed_uri.hostname, parsed_uri.port): return None
        params = UriToClashConverter._get_params(uri)
        proxy = {"name": unquote(parsed_uri.fragment) or f"snell-{parsed_uri.hostname}", "type": "snell", "server": parsed_uri.hostname, "port": parsed_uri.port, "psk": parsed_uri.username, "version": params.get('version', ['3'])[0],}
        if params.get('obfs'): proxy['obfs-opts'] = {'mode': params['obfs'][0]}
        return proxy
    @staticmethod
    def parse_ssh(uri: str) -> Optional[Dict]:
        parsed_uri = urlparse(uri)
        if not UriToClashConverter._is_valid_server_port(parsed_uri.hostname, parsed_uri.port or 22): return None
        proxy = {"name": unquote(parsed_uri.fragment) or f"ssh-{parsed_uri.hostname}", "type": "ssh", "server": parsed_uri.hostname, "port": parsed_uri.port or 22, "username": parsed_uri.username, "password": parsed_uri.password,}
        return {k: v for k, v in proxy.items() if v is not None}
    @staticmethod
    def parse_wireguard(uri: str) -> Optional[Dict]:
        parsed_uri = urlparse(uri)
        if not UriToClashConverter._is_valid_server_port(parsed_uri.hostname, parsed_uri.port) or not parsed_uri.username: return None
        params = UriToClashConverter._get_params(uri); private_key = unquote(parsed_uri.username)
        proxy = {"name": unquote(parsed_uri.fragment) or f"wg-{parsed_uri.hostname}", "type": "wireguard", "server": parsed_uri.hostname, "port": parsed_uri.port, "private-key": private_key, "public-key": params.get('publicKey', [''])[0], "udp": True}
        addresses = params.get('address', ['172.16.0.2/32'])[0].split(',')
        for addr in addresses:
            addr = addr.strip()
            if ':' in addr: proxy['ipv6'] = addr
            elif '.' in addr: proxy['ip'] = addr
        if params.get('presharedKey'): proxy['pre-shared-key'] = params['presharedKey'][0]
        proxy['mtu'] = int(params.get('mtu', [1280])[0])
        return proxy
    @staticmethod
    def parse_anytls(uri: str) -> Optional[Dict]:
        parsed_uri = urlparse(uri)
        if not UriToClashConverter._is_valid_server_port(parsed_uri.hostname, parsed_uri.port): return None
        params = UriToClashConverter._get_params(uri)
        proxy = {"name": unquote(parsed_uri.fragment) or f"anytls-{parsed_uri.hostname}", "type": "anytls", "server": parsed_uri.hostname, "port": parsed_uri.port, "password": parsed_uri.username, "client-fingerprint": params.get('fp', ['chrome'])[0], "sni": params.get('sni', [parsed_uri.hostname])[0], "alpn": params.get('alpn', ['h2,http/1.1'])[0].split(','), "skip-cert-verify": True, "udp": True}
        return proxy
    @staticmethod
    def parse_mieru(uri: str) -> Optional[Dict]:
        parsed_uri = urlparse(uri)
        if not UriToClashConverter._is_valid_server_port(parsed_uri.hostname, parsed_uri.port): return None
        params = UriToClashConverter._get_params(uri)
        proxy = {"name": unquote(parsed_uri.fragment) or f"mieru-{parsed_uri.hostname}", "type": "mieru", "server": parsed_uri.hostname, "port": parsed_uri.port, "username": parsed_uri.username, "password": params.get('password', [''])[0], "transport": "TCP", "multiplexing": "MULTIPLEXING_LOW"}
        return proxy

def replace_placeholders(data, proxy_names):
    if isinstance(data, dict):
        for key, value in data.items(): data[key] = replace_placeholders(value, proxy_names)
    elif isinstance(data, list):
        new_list = []
        for item in data:
            if item == 'ALL_PROXIES_PLACEHOLDER': new_list.extend(proxy_names)
            else: new_list.append(replace_placeholders(item, proxy_names))
        return new_list
    return data

def main():
    configs_dir = 'configs'; templates_dir = 'templates'
    input_file_path = os.path.join(configs_dir, 'proxy_configs.txt')
    if not os.path.exists(input_file_path): print(f"ERROR: Input file not found: {input_file_path}"); return
    with open(input_file_path, 'r', encoding='utf-8') as f: all_uris = f.read().strip().split()
    all_clash_proxies = []
    for uri in all_uris:
        clash_proxy = UriToClashConverter.parse(uri)
        if clash_proxy: all_clash_proxies.append(clash_proxy)
    name_counts = {}; unique_named_proxies = []
    for proxy in all_clash_proxies:
        name = proxy.get('name', 'proxy')
        if name in name_counts: name_counts[name] += 1; proxy['name'] = f"{name}-{name_counts[name]}"
        else: name_counts[name] = 1
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
        combined_data = copy.deepcopy(template_data); combined_data['proxies'] = all_clash_proxies
        replace_placeholders(combined_data.get('proxy-groups', []), proxy_names)
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
            per_protocol_data = copy.deepcopy(template_data); per_protocol_data['proxies'] = proxies_list
            per_protocol_proxy_names = [p['name'] for p in proxies_list]
            replace_placeholders(per_protocol_data.get('proxy-groups', []), per_protocol_proxy_names)
            output_filename = os.path.join(configs_dir, f"{template_base_name}_{ptype}.yaml")
            with open(output_filename, 'w', encoding='utf-8') as f: yaml.dump(per_protocol_data, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
            print(f"-> Saved {ptype}-only Clash config to: {output_filename}")

if __name__ == "__main__":
    main()