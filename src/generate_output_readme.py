import os
from datetime import datetime, timezone, timedelta

# We need the repo URL to build correct links
try:
    from user_settings import GITHUB_REPO_URL
except ImportError:
    # Provide a fallback just in case the file is run standalone without the setting
    GITHUB_REPO_URL = "https://github.com/YOUR_USERNAME/YOUR_REPO"
    print("Warning: GITHUB_REPO_URL not found in user_settings.py. Using a placeholder.")

def generate_output_readme():
    """
    Scans the 'configs' directory and generates a beautiful Persian README.md
    with raw links to all subscription files.
    """
    configs_dir = 'configs'
    output_readme_path = os.path.join(configs_dir, 'README.md')
    branch_name = "main" # Assuming the default branch is 'main'

    if not os.path.isdir(configs_dir):
        print(f"Error: Directory '{configs_dir}' not found.")
        return

    # --- 1. Scan and categorize all subscription files ---
    all_files = sorted(os.listdir(configs_dir))
    
    # Define main subscription files
    main_files = [
        "proxy_configs.txt",
        "proxy_configs_base64.txt",
        "singbox_configs.json",
        "clash_default_combined.yaml" # Assuming this is your main clash config
    ]
    
    # Categorize files
    text_subs = [f for f in all_files if f.endswith('_configs.txt') and f not in main_files]
    base64_subs = [f for f in all_files if f.endswith('_configs_base64.txt') and f not in main_files]
    singbox_subs = [f for f in all_files if f.startswith('singbox_') and f.endswith('.json') and f not in main_files]
    clash_subs = [f for f in all_files if f.endswith(('.yaml', '.yml')) and f not in main_files]

    # --- 2. Build the Markdown content ---
    def create_table(title, file_list):
        if not file_list:
            return ""
        
        table_md = f"### {title}\n\n"
        table_md += "| نام فایل | لینک دانلود مستقیم |\n"
        table_md += "|:---|:---|\n"
        for filename in file_list:
            # Construct the raw URL for the link
            raw_url = f"{GITHUB_REPO_URL}/raw/{branch_name}/{configs_dir}/{filename}"
            table_md += f"| `{filename}` | [دانلود]({raw_url}) |\n"
        return table_md + "\n"

    # Set timezone to Iran Standard Time (UTC+03:30)
    now_utc = datetime.now(timezone.utc)
    iran_tz = timezone(timedelta(hours=3, minutes=30))
    now_iran = now_utc.astimezone(iran_tz)

    # --- Main README content in Persian ---
    readme_content = f"""
# لینک‌های اشتراک (Subscription Links)

اشتراک‌های زیر به صورت خودکار توسط این پروژه تولید و به‌روزرسانی شده‌اند.

**آخرین به‌روزرسانی (به وقت ایران):** `{now_iran.strftime('%Y-%m-%d %H:%M:%S %Z')} `

---

## اشتراک‌های کلی

این بخش شامل لینک‌های اصلی است که حاوی تمام پروتکل‌های جمع‌آوری شده می‌باشند.

| نوع اشتراک | لینک دانلود مستقیم |
|:---|:---|
| **اشتراک کلی (متنی)** | [دانلود]({GITHUB_REPO_URL}/raw/{branch_name}/{configs_dir}/proxy_configs.txt) |
| **اشتراک کلی (Base64)** | [دانلود]({GITHUB_REPO_URL}/raw/{branch_name}/{configs_dir}/proxy_configs_base64.txt) |
| **اشتراک کلی (Sing-Box)** | [دانلود]({GITHUB_REPO_URL}/raw/{branch_name}/{configs_dir}/singbox_configs.json) |
| **اشتراک کلی (Clash)** | [دانلود]({GITHUB_REPO_URL}/raw/{branch_name}/{configs_dir}/clash_default_combined.yaml) |

---

## اشتراک‌های تفکیک شده بر اساس پروتکل
"""

    readme_content += create_table("اشتراک‌های متنی (Plain Text)", text_subs)
    readme_content += create_table("اشتراک‌های Base64", base64_subs)
    readme_content += create_table("فایل‌های JSON مخصوص Sing-Box", singbox_subs)
    readme_content += create_table("فایل‌های YAML مخصوص Clash", clash_subs)

    # --- 3. Write the content to the README.md file ---
    try:
        with open(output_readme_path, 'w', encoding='utf-8') as f:
            f.write(readme_content)
        print(f"Successfully generated README.md in '{configs_dir}' directory.")
    except Exception as e:
        print(f"Error writing to {output_readme_path}: {e}")

if __name__ == '__main__':
    generate_output_readme()
