import os
import sys
import requests
import time
from urllib.parse import urlparse, quote_plus

# --- نام فایل‌ها و پوشه‌ها دقیقاً همان ساختار قبلی شماست ---
# TEMPLATE_FILE حذف شد، زیرا دیگر فایل‌های YAML تولید نمی‌کنیم.
SUBS_FILE = 'subscriptions.txt'
FORMAT_FILE = 'format.txt'
# OUTPUT_DIR حذف شد، زیرا دیگر فایل‌های YAML تولید نمی‌کنیم.
PROVIDERS_DIR = 'providers'
# README_FILE و هرگونه ارتباط با آن حذف شد.
GITHUB_REPO = os.environ.get('GITHUB_REPOSITORY')


def get_filename_from_url(url):
    """تابعی برای استخراج نام فایل از URL"""
    path = urlparse(url).path
    filename = os.path.basename(path)
    return os.path.splitext(filename)[0]


# تابع update_readme حذف شد.


def main():
    """
    تابع اصلی که فقط فایل‌های فراهم‌کننده (providers) را دانلود و ذخیره می‌کند.
    """
    print("Starting robust provider generation process with retry logic...")
    try:
        # template_content و خواندن TEMPLATE_FILE حذف شد.

        with open(FORMAT_FILE, 'r', encoding='utf-8') as f:
            format_string = f.read().strip()

        if "[URL]" not in format_string:
            print(f"Warning: Placeholder [URL] not found in {FORMAT_FILE}. Using default.")
            format_string = "[URL]"

    except FileNotFoundError as e:
        sys.exit(f"CRITICAL ERROR: A required file is missing: {e.filename}")

    # os.makedirs(OUTPUT_DIR, exist_ok=True) حذف شد.
    os.makedirs(PROVIDERS_DIR, exist_ok=True)

    try:
        with open(SUBS_FILE, 'r', encoding='utf-8') as f:
            subscriptions = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        sys.exit(f"CRITICAL ERROR: Subscription file '{SUBS_FILE}' not found.")

    # generated_files دیگر مورد نیاز نیست.

    for sub_line in subscriptions:
        custom_name = None
        if ',' in sub_line:
            original_url, custom_name = [part.strip() for part in sub_line.split(',', 1)]
        else:
            original_url = sub_line

        file_name_base = custom_name if custom_name else get_filename_from_url(original_url)
        if not file_name_base:
            print(f"Warning: Could not determine a filename for URL: {original_url}. Skipping.")
            continue

        wrapped_url = format_string.replace("[URL]", quote_plus(original_url))

        print(f"Processing: {original_url}")
        print(f"  -> Wrapped URL: {wrapped_url}")

        provider_filename = f"{file_name_base}.txt"
        provider_path = os.path.join(PROVIDERS_DIR, provider_filename)

        # --- منطق تلاش مجدد برای دانلود ---
        response = None
        max_retries = 3
        retry_delay = 5  # 5 ثانیه تأخیر بین هر تلاش

        for attempt in range(max_retries):
            try:
                response = requests.get(wrapped_url, timeout=45) # افزایش زمان انتظار
                response.raise_for_status() # بررسی خطاهای HTTP مثل 4xx/5xx
                print(f"  -> Successfully downloaded on attempt {attempt + 1}.")
                break  # اگر موفق بود، از حلقه خارج شو
            except requests.RequestException as e:
                print(f"  -> Attempt {attempt + 1}/{max_retries} failed: {e}")
                if attempt < max_retries - 1:
                    print(f"  -> Waiting for {retry_delay} seconds before retrying...")
                    time.sleep(retry_delay)
                else:
                    print(f"  -> All retries failed. Skipping this subscription.")

        # اگر بعد از تمام تلاش‌ها، دانلود ناموفق بود، به لینک بعدی برو
        if response is None or not response.ok:
            continue

        # ذخیره محتوای دانلود شده
        with open(provider_path, 'w', encoding='utf-8') as f:
            f.write(response.text)
        print(f"  -> Successfully saved content to {provider_path}\n")

        # تمام منطق مربوط به جایگزینی URL و PATH در template و ذخیره فایل YAML حذف شد.
        # if not GITHUB_REPO:
        #    continue
        # raw_provider_url = f"https://raw.githubusercontent.com/{GITHUB_REPO}/main/{provider_path}"
        # modified_content = template_content
        # modified_content = modified_content.replace("%%URL_PLACEHOLDER%%", raw_provider_url)
        # modified_content = modified_content.replace("%%PATH_PLACEHOLDER%%", f"./{provider_path}")
        # output_filename = f"{file_name_base}.yaml"
        # output_path = os.path.join(OUTPUT_DIR, output_filename)
        # with open(output_path, 'w', encoding='utf-8') as f:
        #    f.write(modified_content)
        # print(f"  -> Generated final config: {output_path}\n")

    # هیچ فراخوانی به update_readme وجود ندارد.

if __name__ == "__main__":
    main()

