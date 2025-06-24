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

# Add logging for better debugging
import logging
logging.basicConfig(level=logging.WARNING, format='%(levelname)s: %(message)s') # Changed level to WARNING to show meaningful errors

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
        if not server or port is None:
            logging.debug(f"Invalid server or port: server='{server}', port='{port}' (None or empty)")
            return False
        try:
            int_port = int(port)
            if not (1 <= int_port <= 65535):
                logging.debug(f"Invalid port range: {int_port}")
                return False
        except (ValueError, TypeError):
            logging.debug(f"Port is not a valid integer: {port}")
            return False
        
        # Basic validation for IP addresses and hostnames
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", server):
             return True
        if re.match(r"^[a-zA-Z0-9.-]+$", server):
             return True
        # Allow IPv6 in brackets or without, simple check
        if server.startswith('[') and server.endswith(']'):
            server = server[1:-1] # Remove brackets for inner validation
        if ':' in server and re.match(r'^([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,7}:|[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4}){1,7}$|::([0-9a-fA-F]{1,4}:){1,6}[0-9a-fA-F]{1,4}|[0-9a-fA-F]{1,4}::([0-9a-fA-F]{1,4}:){1,5}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,2}::([0-9a-fA-F]{1,4}:){1,4}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,3}::([0-9a-fA-F]{1,4}:){1,3}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,4}::([0-9a-fA-F]{1,4}:){1,2}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}::[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,6}::[0-9a-fA-F]{1,4}$', server):
            return True
        
        logging.debug(f"Invalid server format: {server}")
        return False


    @staticmethod
    def parse(uri: str, filter_deprecated: bool = False) -> Optional[Dict]:
        try:
            scheme_parts = uri.split("://")
            if len(scheme_parts) < 2:
                logging.warning(f"URI '{uri}' is malformed (missing '://'). Skipping.")
                return None
            scheme = scheme_parts[0]
            
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
                if proxy:
                    if filter_deprecated and proxy.get('cipher') in UriToClashConverter.DEPRECATED_CIPHERS:
                        logging.info(f"Filtered deprecated cipher for proxy: {proxy.get('name', 'N/A')}")
                        return None
                    return proxy
                else:
                    logging.warning(f"Parser for scheme '{scheme}' returned no proxy for URI: {uri}")
                    return None
            else:
                logging.warning(f"Unsupported scheme '{scheme}' for URI: {uri}")
                return None
        except Exception as e:
            logging.error(f"An unexpected error occurred while parsing URI '{uri}': {e}", exc_info=False) # exc_info=False to avoid full traceback in common logs
            return None

    @staticmethod
    def _get_params(uri: str) -> Dict:
        return parse_qs(urlparse(uri).query)

    @staticmethod
    def parse_vmess(uri: str) -> Optional[Dict]:
        try:
            decoded_str = base64.b64decode(uri[8:]).decode('utf-8')
            vmess_data = json.loads(decoded_str)
        except Exception as e:
            logging.warning(f"Error decoding or parsing VMess JSON for URI '{uri}': {e}. Skipping VMess proxy.")
            return None

        server_addr = vmess_data.get('add')
        server_port = vmess_data.get('port')
        if not UriToClashConverter._is_valid_server_port(server_addr, server_port):
            logging.warning(f"Invalid server '{server_addr}' or port '{server_port}' for VMess proxy '{vmess_data.get('ps', 'N/A')}' from URI: {uri}. Skipping.")
            return None
        
        uuid = vmess_data.get('id')
        if not re.match(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$', uuid or ''):
            logging.warning(f"Invalid UUID format '{uuid}' for VMess proxy '{vmess_data.get('ps', 'N/A')}' from URI: {uri}. Skipping.")
            return None

        supported_ciphers = {'auto', 'aes-128-gcm', 'chacha20-poly1305', 'none'}
        original_cipher = vmess_data.get('scy', 'auto').lower()

        proxy = {
            "name": vmess_data.get('ps', f"vmess-{server_addr}"),
            "type": "vmess",
            "server": server_addr,
            "port": int(server_port),
            "uuid": uuid,
            "alterId": int(vmess_data.get('aid', 0)),
            "cipher": original_cipher if original_cipher in supported_ciphers else 'auto',
            "udp": True,
        }

        network = vmess_data.get('net', 'tcp').lower()
        # No warning for 'xhttp' as per user request
        proxy['network'] = network

        if vmess_data.get('tls') in ['tls', 'reality']:
            proxy['tls'] = True
            sni = vmess_data.get('sni') or vmess_data.get('host') or server_addr
            proxy['servername'] = sni
            proxy['skip-cert-verify'] = True

        if proxy['network'] == "ws":
            ws_host = vmess_data.get('host', server_addr) or server_addr
            ws_path = vmess_data.get('path', '/')
            if ws_path is None: # Ensure path is a string, not null
                ws_path = '/'
                logging.info(f"VMess proxy '{proxy['name']}' had null ws-opts path in URI. Defaulting to '/'.")

            proxy['ws-opts'] = {
                'path': ws_path,
                'headers': {
                    'Host': ws_host,
                    'User-Agent': get_random_user_agent()
                }
            }
        elif proxy['network'] == "h2":
             proxy['h2-opts'] = {
                 'host': [vmess_data.get('host', server_addr) or server_addr],
                 'path': vmess_data.get('path', '/')
             }
        elif proxy['network'] == "grpc":
            proxy['grpc-opts'] = {
                'grpc-service-name': vmess_data.get('path', '')
            }

        return proxy

    @staticmethod
    def parse_vless_trojan(uri: str) -> Optional[Dict]:
        parsed_uri = urlparse(uri)
        if not UriToClashConverter._is_valid_server_port(parsed_uri.hostname, parsed_uri.port):
            logging.warning(f"Invalid server '{parsed_uri.hostname}' or port '{parsed_uri.port}' for VLESS/Trojan proxy from URI: {uri}. Skipping.")
            return None
        if not parsed_uri.username:
            logging.warning(f"Missing UUID/password for VLESS/Trojan proxy from URI: {uri}. Skipping.")
            return None
        
        params = UriToClashConverter._get_params(uri)
        proxy_name = unquote(parsed_uri.fragment) or f"{parsed_uri.scheme}-{parsed_uri.hostname}"
        proxy = {
            "name": proxy_name,
            "type": parsed_uri.scheme,
            "server": parsed_uri.hostname,
            "port": int(parsed_uri.port),
            "udp": True
        }

        if parsed_uri.scheme == 'vless':
            uuid = parsed_uri.username
            if not re.match(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$', uuid):
                logging.warning(f"Invalid UUID format '{uuid}' for VLESS proxy '{proxy_name}' from URI: {uri}. Skipping.")
                return None
            proxy['uuid'] = uuid
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
                except (ValueError, TypeError):
                    logging.warning(f"Invalid 'ed' parameter for VLESS/Trojan WS proxy '{proxy_name}' from URI: {uri}. Skipping 'max-early-data'.")
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
            
            public_key_reality = params.get('pbk', [''])[0]
            short_id_reality = params.get('sid', [''])[0]
            if not public_key_reality:
                logging.warning(f"Reality proxy '{proxy_name}' missing public-key (pbk) from URI: {uri}. Skipping.")
                return None
            if not short_id_reality:
                logging.warning(f"Reality proxy '{proxy_name}' missing short-id (sid) from URI: {uri}. Skipping.")
                return None

            proxy['reality-opts'] = {'public-key': public_key_reality, 'short-id': short_id_reality}

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
                    logging.warning(f"Invalid user info format for SS proxy '{name or 'N/A'}': {decoded_user_info} in {uri}. Skipping.")
                    return None
            else: # Attempt base64 decode if not plain text
                try:
                    decoded = base64.b64decode(decoded_user_info + '===').decode('utf-8')
                    parts = decoded.split(':', 1)
                    if len(parts) == 2: cipher, password = parts
                    else:
                        logging.warning(f"Invalid base64 decoded user info for SS proxy '{name or 'N/A'}': {decoded} in {uri}. Skipping.")
                        return None
                except Exception as e:
                    logging.warning(f"Could not base64 decode SS user info for URI '{uri}': {e}. Skipping.")
                    return None
        else: # Entire netloc is base64 encoded
            try:
                full_decoded = base64.b64decode(unquote(uri[5:].split('#')[0]) + '===').decode('utf-8')
                match = re.match(r'(.+?):(.+?)@(.+?):(\d+)', full_decoded)
                if match:
                    cipher, password, server, port = match.groups()
                else:
                    logging.warning(f"No match for full SS decoded URI: {full_decoded} in {uri}. Skipping.")
                    return None
            except Exception as e:
                logging.warning(f"Could not base64 decode full SS URI '{uri}': {e}. Skipping.")
                return None

        if not all([server, port, cipher, password]) or not UriToClashConverter._is_valid_server_port(server, port):
            logging.warning(f"Missing essential SS parameters (server, port, cipher, password) or invalid server/port for URI: {uri}. Skipping.")
            return None

        cipher_lower = cipher.lower()
        if cipher_lower not in UriToClashConverter.SUPPORTED_SS_CIPHERS:
            logging.warning(f"Unsupported SS cipher '{cipher_lower}' for proxy '{name or server}'. Skipping.")
            return None

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
                if params.get('tls', ['false'])[0].lower() == 'true': opts['tls'] = True
                opts['path'] = params.get('path', ['/'])[0]
                opts['host'] = params.get('host', [proxy['server']])[0]
            elif plugin_name == 'shadow-tls':
                opts['password'] = params.get('password', [''])[0]
                try:
                    opts['version'] = int(params.get('version', [2])[0])
                except (ValueError, TypeError):
                    logging.warning(f"Invalid 'version' for shadow-tls plugin in {uri}. Defaulting to 2.")
                    opts['version'] = 2
            proxy['plugin-opts'] = {k: v for k, v in opts.items() if v}

        return proxy

    @staticmethod
    def parse_ssr(uri: str) -> Optional[Dict]:
        try:
            decoded_str = base64.b64decode(uri[6:].rstrip('=') + '===').decode('utf-8')
            parts = decoded_str.split(':')
            if len(parts) < 6:
                logging.warning(f"SSR URI has too few parts after decoding: '{decoded_str}' in '{uri}'. Skipping.")
                return None
            
            server, port_str, protocol, method, obfs, password_b64_and_params = parts[0:6]
            
            try:
                port = int(port_str)
            except (ValueError, TypeError):
                logging.warning(f"Invalid port '{port_str}' for SSR proxy from URI: {uri}. Skipping.")
                return None

            if not UriToClashConverter._is_valid_server_port(server, port):
                logging.warning(f"Invalid server '{server}' or port '{port}' for SSR proxy from URI: {uri}. Skipping.")
                return None
            
            password_b64 = password_b64_and_params.split('/?')[0]
            try:
                password = base64.b64decode(password_b64 + '===').decode('utf-8')
            except Exception as e:
                logging.warning(f"Could not decode SSR password for URI '{uri}': {e}. Setting password to empty string.")
                password = "" # Set to empty string if decoding fails

            params = parse_qs(urlparse(decoded_str).query)
            
            remarks = base64.b64decode(params.get('remarks', [''])[0] + '===').decode('utf-8')
            obfs_param = base64.b64decode(params.get('obfsparam', [''])[0] + '===').decode('utf-8')
            protocol_param = base64.b64decode(params.get('protoparam', [''])[0] + '===').decode('utf-8')

            proxy = {
                "name": remarks or f"ssr-{server}",
                "type": "ssr",
                "server": server,
                "port": port,
                "cipher": method,
                "password": password,
                "obfs": obfs,
                "protocol": protocol,
                "obfs-param": obfs_param,
                "protocol-param": protocol_param,
                "udp": True
            }
            return proxy
        except Exception as e:
            logging.warning(f"Error parsing SSR URI '{uri}': {e}. Skipping SSR proxy.")
            return None

    @staticmethod
    def parse_hysteria(uri: str) -> Optional[Dict]:
        parsed_uri = urlparse(uri)
        if not UriToClashConverter._is_valid_server_port(parsed_uri.hostname, parsed_uri.port):
            logging.warning(f"Invalid server '{parsed_uri.hostname}' or port '{parsed_uri.port}' for Hysteria proxy from URI: {uri}. Skipping.")
            return None

        params = UriToClashConverter._get_params(uri)
        auth_string = parsed_uri.username or params.get('auth', [None])[0]
        if not auth_string:
            logging.warning(f"Hysteria proxy '{parsed_uri.hostname}' missing auth-str from URI: {uri}. Skipping.")
            return None

        try:
            up = params.get('up', [''])[0] or params.get('upmbps', ['50'])[0]
            down = params.get('down', [''])[0] or params.get('downmbps', ['100'])[0]
            up_speed = int(up)
            down_speed = int(down)
        except (ValueError, TypeError):
            logging.warning(f"Invalid up/down speed '{up}'/'{down}' for Hysteria proxy '{parsed_uri.hostname}' from URI: {uri}. Defaulting to 50/100.")
            up_speed, down_speed = 50, 100

        skip_cert_verify = False
        insecure_param = params.get('insecure', ['0'])[0].lower()
        if insecure_param in ['1', 'true']:
            skip_cert_verify = True
        elif insecure_param in ['0', 'false']:
            skip_cert_verify = False
        else:
            logging.warning(f"Unrecognized 'insecure' value '{insecure_param}' for Hysteria proxy '{parsed_uri.hostname}' from URI: {uri}. Defaulting to false.")

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
            "skip-cert-verify": skip_cert_verify
        }
        return {k: v for k, v in proxy.items() if v is not None}

    @staticmethod
    def parse_hysteria2(uri: str) -> Optional[Dict]:
        parsed_uri = urlparse(uri)
        if not UriToClashConverter._is_valid_server_port(parsed_uri.hostname, parsed_uri.port):
            logging.warning(f"Invalid server '{parsed_uri.hostname}' or port '{parsed_uri.port}' for Hysteria2 proxy from URI: {uri}. Skipping.")
            return None
        
        params = UriToClashConverter._get_params(uri)
        
        skip_cert_verify = False
        insecure_param = params.get('insecure', ['0'])[0].lower()
        if insecure_param in ['1', 'true']:
            skip_cert_verify = True
        elif insecure_param in ['0', 'false']:
            skip_cert_verify = False
        else:
            logging.warning(f"Unrecognized 'insecure' value '{insecure_param}' for Hysteria2 proxy '{parsed_uri.hostname}' from URI: {uri}. Defaulting to false.")


        proxy = {
            "name": unquote(parsed_uri.fragment) or f"hysteria2-{parsed_uri.hostname}",
            "type": "hysteria2",
            "server": parsed_uri.hostname,
            "port": int(parsed_uri.port),
            "password": parsed_uri.username,
            "sni": params.get('sni', [''])[0] or params.get('peer', [parsed_uri.hostname])[0],
            "skip-cert-verify": skip_cert_verify,
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
        if not UriToClashConverter._is_valid_server_port(parsed_uri.hostname, parsed_uri.port):
            logging.warning(f"Invalid server '{parsed_uri.hostname}' or port '{parsed_uri.port}' for TUIC proxy from URI: {uri}. Skipping.")
            return None
        if not parsed_uri.username:
            logging.warning(f"TUIC proxy '{parsed_uri.hostname}' missing UUID/token from URI: {uri}. Skipping.")
            return None

        params = UriToClashConverter._get_params(uri)
        
        skip_cert_verify = False
        insecure_param = params.get('insecure', ['0'])[0].lower()
        if insecure_param in ['1', 'true']:
            skip_cert_verify = True
        elif insecure_param in ['0', 'false']:
            skip_cert_verify = False
        else:
            logging.warning(f"Unrecognized 'insecure' value '{insecure_param}' for TUIC proxy '{parsed_uri.hostname}' from URI: {uri}. Defaulting to false.")

        proxy = {
            "name": unquote(parsed_uri.fragment) or f"tuic-{parsed_uri.hostname}", 
            "type": "tuic", 
            "server": parsed_uri.hostname, 
            "port": int(parsed_uri.port), 
            "sni": params.get('sni', [parsed_uri.hostname])[0], 
            "alpn": [params.get('alpn', ['h3'])[0]], 
            "skip-cert-verify": skip_cert_verify, 
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
        
        return {k: v for k, v in proxy.items() if v is not None and (v is not False or k == 'disable-sni')}


    @staticmethod
    def parse_snell(uri: str) -> Optional[Dict]:
        parsed_uri = urlparse(uri)
        if not UriToClashConverter._is_valid_server_port(parsed_uri.hostname, parsed_uri.port):
            logging.warning(f"Invalid server '{parsed_uri.hostname}' or port '{parsed_uri.port}' for Snell proxy from URI: {uri}. Skipping.")
            return None
        if not parsed_uri.username:
            logging.warning(f"Snell proxy '{parsed_uri.hostname}' missing PSK from URI: {uri}. Skipping.")
            return None

        params = UriToClashConverter._get_params(uri)
        proxy = {
            "name": unquote(parsed_uri.fragment) or f"snell-{parsed_uri.hostname}",
            "type": "snell",
            "server": parsed_uri.hostname,
            "port": int(parsed_uri.port),
            "psk": parsed_uri.username,
            "version": params.get('version', ['3'])[0]
        }
        if 'obfs' in params: proxy['obfs-opts'] = {'mode': params['obfs'][0]}
        return proxy

    @staticmethod
    def parse_ssh(uri: str) -> Optional[Dict]:
        parsed_uri = urlparse(uri)
        port = parsed_uri.port if parsed_uri.port is not None else 22
        if not UriToClashConverter._is_valid_server_port(parsed_uri.hostname, port):
            logging.warning(f"Invalid server '{parsed_uri.hostname}' or port '{port}' for SSH proxy from URI: {uri}. Skipping.")
            return None
        if not parsed_uri.username:
            logging.warning(f"SSH proxy '{parsed_uri.hostname}' missing username from URI: {uri}. Skipping.")
            return None

        proxy = {
            "name": unquote(parsed_uri.fragment) or f"ssh-{parsed_uri.hostname}",
            "type": "ssh",
            "server": parsed_uri.hostname,
            "port": int(port),
            "username": parsed_uri.username,
        }
        if parsed_uri.password: # Password is optional for SSH
            proxy["password"] = parsed_uri.password

        return {k: v for k, v in proxy.items() if v is not None}

    @staticmethod
    def parse_wireguard(uri: str) -> Optional[Dict]:
        parsed_uri = urlparse(uri)
        if not UriToClashConverter._is_valid_server_port(parsed_uri.hostname, parsed_uri.port):
            logging.warning(f"Invalid server '{parsed_uri.hostname}' or port '{parsed_uri.port}' for WireGuard proxy from URI: {uri}. Skipping.")
            return None
        if not parsed_uri.username: # private-key is in username
            logging.warning(f"WireGuard proxy '{parsed_uri.hostname}' missing private key from URI: {uri}. Skipping.")
            return None

        params = UriToClashConverter._get_params(uri)
        private_key_b64 = unquote(parsed_uri.username)

        public_key_b64 = params.get('publicKey', [''])[0] or params.get('publickey', [''])[0]
        if not public_key_b64:
            try:
                private_key_bytes = base64.b64decode(private_key_b64)
                priv_key_obj = PrivateKey(private_key_bytes)
                pub_key_obj = priv_key_obj.public_key
                public_key_b64 = base64.b64encode(bytes(pub_key_obj)).decode('utf-8')
                logging.info(f"Generated public key for WireGuard proxy: {unquote(parsed_uri.fragment) or parsed_uri.hostname}")
            except Exception as e:
                logging.error(f"Could not generate public key for WireGuard config from URI '{uri}': {e}. Skipping WireGuard proxy.")
                return None

        proxy = {
            "name": unquote(parsed_uri.fragment) or f"wg-{parsed_uri.hostname}",
            "type": "wireguard",
            "server": parsed_uri.hostname,
            "port": int(parsed_uri.port),
            "private-key": private_key_b64,
            "public-key": public_key_b64,
            "udp": True
        }

        if 'address' in params:
            addresses = params['address'][0].split(',')
            for addr in addresses:
                addr = addr.strip()
                if ':' in addr:
                    proxy['ipv6'] = addr
                elif '.' in addr:
                    proxy['ip'] = addr
        
        if 'pre-shared-key' in params:
            proxy['pre-shared-key'] = params['pre-shared-key'][0]
        elif 'presharedKey' in params:
            proxy['pre-shared-key'] = params['presharedKey'][0]
        
        if 'reserved' in params:
            reserved_value = params['reserved'][0]
            try:
                if re.match(r"^\d+(,\d+)*$", reserved_value):
                    proxy['reserved'] = [int(x) for x in reserved_value.split(',')]
                else:
                    proxy['reserved'] = reserved_value
            except (ValueError, TypeError):
                proxy['reserved'] = reserved_value
                logging.warning(f"Invalid 'reserved' format '{reserved_value}' for WireGuard proxy '{proxy['name']}' from URI: {uri}. Keeping as string.")

        if 'mtu' in params:
            try:
                proxy['mtu'] = int(params['mtu'][0])
            except (ValueError, TypeError):
                logging.warning(f"Invalid MTU value '{params['mtu'][0]}' for WireGuard proxy '{proxy['name']}' from URI: {uri}. Skipping MTU.")
        
        if 'remote-dns-resolve' in params:
            remote_dns_resolve_val = params['remote-dns-resolve'][0].lower()
            if remote_dns_resolve_val in ['true', '1']:
                proxy['remote-dns-resolve'] = True
            elif remote_dns_resolve_val in ['false', '0']:
                proxy['remote-dns-resolve'] = False
            else:
                logging.warning(f"Unrecognized 'remote-dns-resolve' value '{remote_dns_resolve_val}' for WireGuard proxy '{proxy['name']}' from URI: {uri}. Skipping.")

        if 'dns' in params:
            proxy['dns'] = [d.strip() for d in params['dns'][0].split(',')]

        if 'allowed-ips' in params:
            proxy['allowed-ips'] = [ip.strip() for ip in params['allowed-ips'][0].split(',')]
        else:
            proxy['allowed-ips'] = ["0.0.0.0/0", "::/0"]

        if 'dialer-proxy' in params:
            proxy['dialer-proxy'] = params['dialer-proxy'][0]

        amnezia_wg_params = {}
        for key_prefix in ['jc', 'jmin', 'jmax', 's1', 's2', 'h1', 'h2', 'h3', 'h4']:
            if key_prefix in params:
                try:
                    amnezia_wg_params[key_prefix] = int(params[key_prefix][0])
                except (ValueError, TypeError):
                    logging.warning(f"Invalid integer value for amnezia-wg-option '{key_prefix}' for proxy '{proxy['name']}' from URI: {uri}. Skipping.")
        
        if amnezia_wg_params:
            proxy['amnezia-wg-option'] = amnezia_wg_params

        if 'ip' not in proxy and 'ipv6' not in proxy:
            logging.warning(f"WireGuard proxy '{proxy['name']}' missing local IP/IPv6 address from URI: {uri}. Skipping config.")
            return None

        known_wireguard_params_list = [
            'address', 'private-key', 'public-key', 'publicKey', 'pre-shared-key',
            'presharedKey', 'reserved', 'mtu', 'remote-dns-resolve', 'dns',
            'allowed-ips', 'dialer-proxy', 'keepalive' # 'keepalive' is still in this list to avoid 'unknown parameter' warning from source URI
        ]
        known_wireguard_params_list.extend(['jc', 'jmin', 'jmax', 's1', 's2', 'h1', 'h2', 'h3', 'h4'])

        for key, value in params.items():
            if key not in known_wireguard_params_list:
                 logging.warning(f"Unknown or unsupported WireGuard parameter '{key}' for proxy '{proxy['name']}' with value '{value}' from URI: {uri}. Skipping this parameter.")

        return {k: v for k, v in proxy.items() if v is not None and v != ''}

    @staticmethod
    def parse_anytls(uri: str) -> Optional[Dict]:
        parsed_uri = urlparse(uri)
        if not UriToClashConverter._is_valid_server_port(parsed_uri.hostname, parsed_uri.port):
            logging.warning(f"Invalid server '{parsed_uri.hostname}' or port '{parsed_uri.port}' for AnyTLS proxy from URI: {uri}. Skipping.")
            return None
        if not parsed_uri.username:
            logging.warning(f"AnyTLS proxy '{parsed_uri.hostname}' missing password from URI: {uri}. Skipping.")
            return None

        params = UriToClashConverter._get_params(uri)
        
        skip_cert_verify = False
        insecure_param = params.get('insecure', ['0'])[0].lower()
        if insecure_param in ['1', 'true']:
            skip_cert_verify = True
        elif insecure_param in ['0', 'false']:
            skip_cert_verify = False
        else:
            logging.warning(f"Unrecognized 'insecure' value '{insecure_param}' for AnyTLS proxy '{parsed_uri.hostname}' from URI: {uri}. Defaulting to false.")

        proxy = {
            "name": unquote(parsed_uri.fragment) or f"anytls-{parsed_uri.hostname}",
            "type": "anytls",
            "server": parsed_uri.hostname,
            "port": int(parsed_uri.port),
            "password": parsed_uri.username,
            "client-fingerprint": params.get('fp', ['chrome'])[0],
            "sni": params.get('sni', [parsed_uri.hostname])[0],
            "alpn": params.get('alpn', ['h2,http/1.1'])[0].split(','),
            "skip-cert-verify": skip_cert_verify,
            "udp": True
        }
        return proxy

    @staticmethod
    def parse_mieru(uri: str) -> Optional[Dict]:
        parsed_uri = urlparse(uri)
        if not UriToClashConverter._is_valid_server_port(parsed_uri.hostname, parsed_uri.port):
            logging.warning(f"Invalid server '{parsed_uri.hostname}' or port '{parsed_uri.port}' for Mieru proxy from URI: {uri}. Skipping.")
            return None
        if not parsed_uri.username:
            logging.warning(f"Mieru proxy '{parsed_uri.hostname}' missing username from URI: {uri}. Skipping.")
            return None

        params = UriToClashConverter._get_params(uri)
        proxy = {
            "name": unquote(parsed_uri.fragment) or f"mieru-{parsed_uri.hostname}",
            "type": "mieru",
            "server": parsed_uri.hostname,
            "port": int(parsed_uri.port),
            "username": parsed_uri.username,
            "password": params.get('password', [''])[0],
            "transport": "TCP",
            "multiplexing": "MULTIPLEXING_LOW"
        }
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
    # Changed APPEND_PROTOCOL_TO_NAME to False as per user request
    APPEND_PROTOCOL_TO_NAME = False
    FILTER_DEPRECATED = True

    configs_dir = 'configs'
    templates_dir = 'templates'
    input_file_path = os.path.join(configs_dir, 'proxy_configs.txt')
    if not os.path.exists(input_file_path):
        logging.error(f"ERROR: Input file not found: {input_file_path}")
        return

    with open(input_file_path, 'r', encoding='utf-8') as f:
        all_uris = f.read().strip().split()

    all_clash_proxies = []
    for uri in all_uris:
        clash_proxy = UriToClashConverter.parse(uri, filter_deprecated=FILTER_DEPRECATED)
        if clash_proxy:
            # Removed the logic to append protocol to name here as per user request.
            # The clean_proxy_name function in utils.py should handle general cleaning.
            all_clash_proxies.append(clash_proxy)

    name_counts = {}; unique_named_proxies = []
    for proxy in all_clash_proxies:
        original_name = clean_proxy_name(proxy.get('name', 'proxy'))
        proxy['name'] = generate_unique_name(name_counts, original_name)
        unique_named_proxies.append(proxy)

    all_clash_proxies = unique_named_proxies

    if not all_clash_proxies:
        logging.warning("WARNING: No valid Clash-compatible proxies were generated from provided URIs.")
        return
    logging.info(f"Successfully converted and de-duplicated {len(all_clash_proxies)} URIs to Clash format.")

    if not os.path.isdir(templates_dir):
        logging.error(f"ERROR: Templates directory '{templates_dir}' not found. Please ensure it exists.")
        return

    template_files = [f for f in os.listdir(templates_dir) if f.endswith(('.yaml', '.yml'))]
    if not template_files:
        logging.warning(f"WARNING: No templates found in '{templates_dir}'. Please add at least one YAML template.")
        return

    for template_file in template_files:
        template_path = os.path.join(templates_dir, template_file)
        template_base_name = os.path.splitext(template_file)[0]
        logging.info(f"\n--- Processing template: {template_file} ---")

        try:
            with open(template_path, 'r', encoding='utf-8') as f:
                template_data = yaml.safe_load(f)
            if not isinstance(template_data, dict):
                logging.error(f"Template file '{template_file}' is not a valid YAML dictionary. Skipping.")
                continue
        except yaml.YAMLError as e:
            logging.error(f"Error parsing YAML template '{template_file}': {e}. Skipping.")
            continue
        except Exception as e:
            logging.error(f"Error reading template file '{template_file}': {e}. Skipping.")
            continue


        proxy_names = [p['name'] for p in all_clash_proxies]
        combined_data = copy.deepcopy(template_data)
        if 'proxies' not in combined_data: combined_data['proxies'] = []
        combined_data['proxies'].extend(all_clash_proxies)

        if 'proxy-groups' in combined_data:
            replace_placeholders(combined_data['proxy-groups'], proxy_names)

        output_filename = os.path.join(configs_dir, f"{template_base_name}_combined.yaml")
        try:
            with open(output_filename, 'w', encoding='utf-8') as f:
                yaml.dump(combined_data, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
            logging.info(f"-> Saved combined Clash config to: {output_filename}")
        except Exception as e:
            logging.error(f"Error writing combined config to '{output_filename}': {e}")


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
            try:
                with open(output_filename, 'w', encoding='utf-8') as f:
                    yaml.dump(per_protocol_data, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
                logging.info(f"-> Saved {ptype}-only Clash config to: {output_filename}")
            except Exception as e:
                logging.error(f"Error writing {ptype}-only config to '{output_filename}': {e}")

if __name__ == "__main__":
    main()

