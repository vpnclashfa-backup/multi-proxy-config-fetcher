import os
from datetime import datetime, timezone

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
    
    main_subs = {
        "proxy_configs.txt": "اشتراک کلی (متنی)",
        "proxy_configs_base64.txt": "اشتراک کلی (Base64)",
        "singbox_configs.json": "اشتراک کلی (Sing-Box)",
    }
    
    text_subs = [f for f in all_files if f.endswith('_configs.txt') and f not in main_subs]
    base64_subs = [f for f in all_files if f.endswith('_configs_base64.txt') and f not in main_subs]
    singbox_subs = [f for f in all_files if f.startswith('singbox_') and f.endswith('.json') and f not in main_subs]

    # --- 2. Build the Markdown content ---
    # Helper function to create a table section
    def create_table(title, file_list):
        if not file_list:
            return ""
        
        table_md = f"### {title}\n\n"
        table_md += "| نام فایل | لینک دانلود مستقیم |\n"
        table_md += "|:---|:---|\n"
        for filename in file_list:
            raw_url = f"{GITHUB_REPO_URL}/raw/{branch_name}/{configs_dir}/{filename}"
            table_md += f"| `{filename}` | [دانلود]({raw_url}) |\n"
        return table_md + "\n"

    # Main README content
    now_utc = datetime.now(timezone.utc)
    # Assuming location is Germany (CEST is UTC+2)
    # In summer, Germany uses CEST (UTC+2)
    local_tz = timezone(timedelta(hours=2))
    now_local = now_utc.astimezone(local_tz)

    readme_content = f"""
# subscription links

اشتراک‌های زیر به صورت خودکار توسط این پروژه تولید و به‌روزرسانی شده‌اند.

**آخرین به‌روزرسانی (به وقت آلمان):** `{now_local.strftime('%Y-%m-%d %H:%M:%S %Z')} `

---

##  종합 구독

여기에 있는 모든 프로토콜을 포함하는 일반 구독 링크입니다.

| 파일 이름 | 직접 다운로드 링크 |
|:---|:---|
| `proxy_configs.txt` | [다운로드]({GITHUB_REPO_URL}/raw/{branch_name}/{configs_dir}/proxy_configs.txt) |
| `proxy_configs_base64.txt` | [다운로드]({GITHUB_REPO_URL}/raw/{branch_name}/{configs_dir}/proxy_configs_base64.txt) |
| `singbox_configs.json` | [다운로드]({GITHUB_REPO_URL}/raw/{branch_name}/{configs_dir}/singbox_configs.json) |

---
"""

    readme_content += create_table("پروتکل 별 일반 텍스트 구독", text_subs)
    readme_content += create_table("프로토콜별 Base64 구독", base64_subs)
    readme_content += create_table("프로토콜별 Sing-Box JSON 파일", singbox_subs)

    # --- 3. Write the content to the README.md file ---
    try:
        with open(output_readme_path, 'w', encoding='utf-8') as f:
            f.write(readme_content)
        print(f"Successfully generated README.md in '{configs_dir}' directory.")
    except Exception as e:
        print(f"Error writing to {output_readme_path}: {e}")


if __name__ == '__main__':
    generate_output_readme()
