import re
import base64
import json
import logging
from typing import Optional, Tuple, List
from urllib.parse import unquote, urlparse

# Configure logging for better debugging and information
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ConfigValidator:
    """
    کلاس ابزاری برای اعتبارسنجی، پاکسازی و تقسیم‌بندی پیکربندی‌های پروکسی.
    این کلاس انواع طرحواره‌های URI و محتوای Base64 رمزگذاری شده را مدیریت می‌کند.
    """

    @staticmethod
    def is_base64(s: str) -> bool:
        """
        بررسی می‌کند که آیا یک رشته داده شده یک رشته Base64 معتبر (یا URL-safe Base64) است یا خیر.
        این تابع تنها مجموعه کاراکترها و ساختار اولیه را بررسی می‌کند و تلاشی برای رمزگشایی نمی‌کند.

        Args:
            s (str): رشته مورد بررسی.

        Returns:
            bool: True اگر رشته به نظر Base64 باشد، در غیر این صورت False.
        """
        if not isinstance(s, str):
            logger.debug(f"Input for is_base64 is not a string: {type(s)}")
            return False
        # حذف کاراکترهای پدینگ برای اعتبارسنجی
        s = s.rstrip('=')
        # بررسی اینکه رشته فقط شامل کاراکترهای Base64 معتبر (A-Z, a-z, 0-9, +, /, -, _) باشد
        return bool(re.fullmatch(r'[A-Za-z0-9+/_-]*', s))

    @staticmethod
    def decode_base64_url(s: str) -> Optional[bytes]:
        """
        یک رشته URL-safe Base64 را رمزگشایی می‌کند. پدینگ‌های گمشده را مدیریت می‌کند.

        Args:
            s (str): رشته رمزگذاری شده URL-safe Base64.

        Returns:
            Optional[bytes]: بایت‌های رمزگشایی شده در صورت موفقیت، در غیر این صورت None.
        """
        if not isinstance(s, str):
            logger.debug(f"Input for decode_base64_url is not a string: {type(s)}")
            return None
        try:
            # جایگزینی کاراکترهای URL-safe با کاراکترهای استاندارد Base64
            s = s.replace('-', '+').replace('_', '/')
            # اضافه کردن پدینگ در صورت لزوم
            padding = -len(s) % 4
            if padding != 0 and padding != 4: # پدینگ می‌تواند 0، 1، 2، 3 باشد. اگر 0، پدینگ لازم نیست. اگر 4، یعنی طول % 4 == 0 است، پس پدینگ لازم نیست.
                s += '=' * padding
            return base64.b64decode(s)
        except Exception as e:
            logger.debug(f"Failed to decode URL-safe Base64 '{s[:50]}...': {e}")
            return None

    @staticmethod
    def decode_base64_text(text: str) -> Optional[str]:
        """
        یک رشته Base64 (که می‌تواند URL-safe باشد) را رمزگشایی کرده و آن را به عنوان یک رشته UTF-8 برمی‌گرداند.
        این تابع ابتدا بررسی می‌کند که آیا ورودی خود به نظر Base64 می‌رسد یا خیر.

        Args:
            text (str): رشته رمزگذاری شده Base64.

        Returns:
            Optional[str]: رشته رمزگشایی شده در صورت موفقیت، در غیر این صورت None.
        """
        if not isinstance(text, str):
            logger.debug(f"Input for decode_base64_text is not a string: {type(text)}")
            return None
        try:
            if ConfigValidator.is_base64(text):
                decoded_bytes = ConfigValidator.decode_base64_url(text)
                if decoded_bytes:
                    return decoded_bytes.decode('utf-8')
            return None
        except Exception as e:
            logger.debug(f"Failed to decode Base64 text '{text[:50]}...': {e}")
            return None

    @staticmethod
    def clean_vmess_config(config: str) -> str:
        """
        یک URI Vmess را با حذف هر گونه کاراکتر اضافی پس از بخش Base64،
        که ممکن است به دلیل منابع بدفرم موجود باشد، پاکسازی می‌کند.

        Args:
            config (str): URI Vmess.

        Returns:
            str: URI Vmess پاکسازی شده.
        """
        if not isinstance(config, str) or "vmess://" not in config.lower():
            return config
        
        try:
            # پیدا کردن نقطه شروع Base64 پس از "vmess://"
            base64_start_index = config.lower().find("vmess://") + 8
            base64_part = config[base64_start_index:]
            # فقط کاراکترهای Base64 معتبر (A-Za-z0-9+/=_-) را مجاز می‌داند
            base64_clean = re.split(r'[^A-Za-z0-9+/=_-]', base64_part)[0]
            return f"vmess://{base64_clean}"
        except Exception as e:
            logger.warning(f"Failed to clean Vmess config '{config[:80]}...': {e}")
            return config


    @staticmethod
    def normalize_hysteria2_protocol(config: str) -> str:
        """
        طرحواره 'hy2://' را به 'hysteria2://' برای یکپارچگی عادی‌سازی می‌کند.

        Args:
            config (str): URI پروکسی.

        Returns:
            str: URI عادی‌سازی شده.
        """
        if not isinstance(config, str):
            return config
        if config.lower().startswith('hy2://'):
            return config.replace('hy2://', 'hysteria2://', 1)
        return config

    @staticmethod
    def check_base64_content(text: str) -> Optional[str]:
        """
        بررسی می‌کند که آیا متن داده شده Base64 رمزگذاری شده است و در صورت رمزگشایی،
        شامل هر یک از طرحواره‌های پروتکل پروکسی شناخته شده است یا خیر.
        این به شناسایی لینک‌های اشتراک Base64 رمزگذاری شده کمک می‌کند.

        Args:
            text (str): متن مورد بررسی.

        Returns:
            Optional[str]: محتوای رمزگشایی شده اگر شامل یک پروتکل شناخته شده باشد، در غیر این صورت None.
        """
        if not isinstance(text, str):
            return None
        try:
            decoded_text = ConfigValidator.decode_base64_text(text)
            if decoded_text:
                # لیست پروتکل‌های شناخته شده
                protocols = [
                    'vmess://', 'vless://', 'ss://', 'trojan://', 'hysteria2://', 'hy2://',
                    'wireguard://', 'tuic://', 'ssconf://', 'ssr://', 'hysteria://', 'snell://',
                    'ssh://', 'mieru://', 'anytls://', 'warp://', 'juicity://'
                ]
                # بررسی وجود پروتکل به صورت غیرحساس به حروف
                decoded_text_lower = decoded_text.lower()
                for protocol in protocols:
                    if protocol in decoded_text_lower:
                        return decoded_text # محتوای رمزگشایی شده با حروف اصلی را برمی‌گرداند
            return None
        except Exception as e:
            logger.debug(f"Error checking Base64 content for protocols '{text[:50]}...': {e}")
            return None

    @staticmethod
    def split_configs(text: str) -> List[str]:
        """
        یک رشته حاوی چندین پیکربندی پروکسی (که با فضای خالی/خطوط جدید جدا شده‌اند)
        را به لیستی از پیکربندی‌های فردی، پاکسازی شده و احتمالا عادی‌سازی شده تقسیم می‌کند.
        این تابع همچنین لینک‌های اشتراک Base64 رمزگذاری شده را در متن مدیریت می‌کند.

        Args:
            text (str): یک رشته حاوی یک یا چند پیکربندی پروکسی.

        Returns:
            List[str]: لیستی از URIهای پیکربندی پروکسی پاکسازی شده و متمایز.
        """
        if not isinstance(text, str):
            logger.warning(f"Input for split_configs is not a string: {type(text)}")
            return []

        all_protocols = [
            'vmess://', 'vless://', 'ss://', 'trojan://', 'hysteria2://', 'hy2://',
            'wireguard://', 'tuic://', 'ssconf://', 'ssr://', 'hysteria://', 'snell://',
            'ssh://', 'mieru://', 'anytls://', 'warp://', 'juicity://'
        ]
        
        configs = []
        # تقسیم بر اساس هر کاراکتر فضای خالی، از جمله خطوط جدید
        potential_configs = re.split(r'[\s\n]+', text)
        
        for p_config in potential_configs:
            p_config = p_config.strip()
            if not p_config:
                continue

            # ابتدا، بررسی می‌کند که آیا پیکربندی احتمالی یک لینک اشتراک Base64 رمزگذاری شده است
            decoded_content = ConfigValidator.check_base64_content(p_config)
            if decoded_content:
                # اگر یک اشتراک Base64 است، محتوای آن را به صورت بازگشتی تقسیم می‌کند
                configs.extend(ConfigValidator.split_configs(decoded_content))
                continue # به پیکربندی احتمالی بعدی می‌رود

            # اگر یک اشتراک Base64 نیست، بررسی می‌کند که آیا با یک پروتکل شناخته شده شروع می‌شود یا خیر
            is_valid_protocol_start = False
            for protocol in all_protocols:
                if p_config.lower().startswith(protocol):
                    is_valid_protocol_start = True
                    break

            if is_valid_protocol_start:
                # اعمال عادی‌سازی (مثلاً hy2 به hysteria2)
                p_config = ConfigValidator.normalize_hysteria2_protocol(p_config)
                # اعمال پاکسازی خاص Vmess
                p_config = ConfigValidator.clean_vmess_config(p_config)
                # اعمال پاکسازی عمومی
                clean_conf = ConfigValidator.clean_config(p_config)
                configs.append(clean_conf)
            else:
                logger.debug(f"Skipping potential config (no known protocol or not Base64): {p_config[:80]}...")


        # حذف موارد تکراری ضمن حفظ ترتیب (در صورت لزوم، اگرچه ترتیب معمولاً در اینجا حیاتی نیست)
        seen = set()
        unique_configs = []
        for x in configs:
            if x not in seen:
                unique_configs.append(x)
                seen.add(x)
        return unique_configs

    @staticmethod
    def clean_config(config: str) -> str:
        """
        پاکسازی عمومی را بر روی یک رشته پیکربندی پروکسی انجام می‌دهد:
        - حذف ایموجی‌ها/شکلک‌ها (محدوده یونی‌کد U+1F300-U+1F9FF).
        - حذف کاراکترهای کنترلی (ASCII 0-8, 11-31, 127-159).
        - جایگزینی چندین کاراکتر فضای خالی (به جز خطوط جدید) با یک فضای خالی.
        - حذف فضای خالی ابتدایی/انتهایی.

        Args:
            config (str): رشته پیکربندی پروکسی خام.

        Returns:
            str: رشته پیکربندی پروکسی پاکسازی شده.
        """
        if not isinstance(config, str):
            return ""
        
        # حذف ایموجی‌ها/شکلک‌ها
        config = re.sub(r'[\U0001F300-\U0001F9FF]', '', config, flags=re.UNICODE)
        # حذف کاراکترهای کنترلی (شامل فواصل غیرشکننده، و غیره)
        config = re.sub(r'[\x00-\x08\x0B-\x1F\x7F-\x9F]', '', config)
        # جایگزینی چندین فضای خالی (به جز خطوط جدید) با یک فضای خالی
        config = re.sub(r'[^\S\r\n]+', ' ', config)
        return config.strip()

    @classmethod
    def validate_protocol_config(cls, config: str, protocol: str) -> bool:
        """
        یک رشته پیکربندی پروکسی را در برابر پروتکل مورد انتظار آن اعتبارسنجی می‌کند.
        این تابع برای انعطاف‌پذیری و استحکام بیشتر بازنویسی شده است.

        Args:
            config (str): رشته URI پروکسی.
            protocol (str): طرحواره پروتکل مورد انتظار (مثلاً 'vless://', 'ss://').

        Returns:
            bool: True اگر پیکربندی برای پروتکل داده شده معتبر باشد، در غیر این صورت False.
        """
        if not isinstance(config, str) or not isinstance(protocol, str):
            logger.debug(f"Invalid input type for validate_protocol_config: config={type(config)}, protocol={type(protocol)}")
            return False
        
        is_valid = False
        try:
            # عادی‌سازی پروتکل به حروف کوچک برای مقایسه یکپارچه
            protocol_lower = protocol.lower()
            config_lower = config.lower()

            # اطمینان از اینکه پیکربندی واقعاً با پروتکل داده شده شروع می‌شود
            if not config_lower.startswith(protocol_lower):
                logger.debug(f"Config does not start with expected protocol {protocol}: {config[:80]}...")
                return False

            # تجزیه URI
            parsed_uri = urlparse(config)

            # قاعده 1: پروتکل‌هایی که پس از طرحواره عمدتاً Base64 رمزگذاری شده‌اند
            if protocol_lower in ['vmess://', 'ssr://']:
                # قسمت پس از طرحواره باید Base64 باشد
                base64_payload = config[len(protocol_lower):]
                if not cls.is_base64(base64_payload):
                    logger.debug(f"Payload not Base64 for {protocol}: {base64_payload[:50]}...")
                    return False
                
                # برای VMess، تلاش برای رمزگشایی و تجزیه به عنوان JSON
                if protocol_lower == 'vmess://':
                    decoded_vmess_str = cls.decode_base64_text(base64_payload)
                    if not decoded_vmess_str:
                        logger.debug(f"Failed to decode VMess Base64: {base64_payload[:50]}...")
                        return False
                    try:
                        vmess_json = json.loads(decoded_vmess_str)
                        # حداقل بررسی VMess: باید 'add' (سرور) و 'port' را داشته باشد
                        if not vmess_json.get('add') or not vmess_json.get('port'):
                            logger.debug(f"VMess JSON missing 'add' or 'port': {decoded_vmess_str[:50]}...")
                            return False
                    except json.JSONDecodeError:
                        logger.debug(f"VMess Base64 content is not valid JSON: {decoded_vmess_str[:50]}...")
                        return False
                return True

            # قاعده 2: پروتکل‌هایی که معمولاً بر اساس URL هستند
            # یک طرحواره معتبر، نام میزبان و اختیاری پورت/اطلاعات کاربر یک شروع خوب است.
            # برخی طرحواره‌ها مانند 'ss://' نیز می‌توانند به صورت کلی به صورت Base64 رمزگذاری شوند.

            # بررسی اینکه آیا دارای یک مکان شبکه معتبر (نام میزبان/پورت یا userinfo@host:port) است
            # و یک طرحواره که با پروتکل مورد انتظار مطابقت دارد.
            # برای تجزیه مستقیم URL، parsed_uri.hostname یا parsed_uri.netloc باید وجود داشته باشد.
            if not parsed_uri.scheme or not parsed_uri.netloc:
                # اگر ساختار URL استانداردی ندارد، ممکن است یک URI SS Base64 رمزگذاری شده باشد
                if protocol_lower == 'ss://' and cls.is_base64(config[len(protocol_lower):]):
                    decoded_ss = cls.decode_base64_text(config[len(protocol_lower):])
                    if decoded_ss and '@' in decoded_ss: # حداقل بررسی برای 'method:password@server:port'
                        return True
                logger.debug(f"Invalid URI structure for {protocol}: {config[:80]}...")
                is_valid = False
            else:
                # بررسی اولیه برای حضور سرور و پورت برای پروتکل‌های URL-محور رایج
                # این پروتکل‌ها معمولاً میزبان و پورت را مستقیماً در مسیر URI یا netloc دارند
                if protocol_lower in ['vless://', 'trojan://', 'hysteria://', 'hysteria2://', 'tuic://', 'snell://', 'ssh://', 'wireguard://', 'anytls://', 'mieru://', 'juicity://']:
                    if not parsed_uri.hostname or not parsed_uri.port:
                        # برای SSH، پورت می‌تواند پیش‌فرض 22 باشد
                        if protocol_lower == 'ssh://' and parsed_uri.hostname:
                            is_valid = True # پورت می‌تواند برای SSH ضمنی باشد
                        else:
                            logger.debug(f"Missing hostname or port for {protocol}: {config[:80]}...")
                            is_valid = False
                    else:
                        is_valid = True
                else:
                    is_valid = True # فرض می‌کنیم معتبر است اگر به عنوان URL تجزیه شده و یک نوع Base64 خاص که در بالا مدیریت شده، نباشد.

        except Exception as e:
            logger.debug(f"Validation error for config '{config[:80]}' with protocol {protocol}: {e}")
            is_valid = False

        if not is_valid:
            logger.debug(f"[REJECTED] Config failed validation for protocol {protocol}: {config[:80]}...")

        return is_valid
