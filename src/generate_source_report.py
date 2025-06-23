import json
import os
from datetime import datetime

def generate_source_report_html(stats_data):
    """Generates an HTML report from channel statistics, sorted by valid configs."""
    
    # Sort channels by the number of valid configs in descending order
    try:
        sorted_channels = sorted(
            [ch for ch in stats_data.get('channels', []) if ch['metrics']['valid_configs'] > 0],
            key=lambda c: c['metrics']['valid_configs'],
            reverse=True
        )
    except KeyError:
        # Handle cases where metrics might be missing
        return "<html><body><h1>Error: Invalid statistics data format.</h1></body></html>"

    # Get a unique, sorted list of all protocols found across all channels
    all_protocols = sorted(list(set(
        protocol
        for channel in sorted_channels
        for protocol in channel['metrics'].get('protocol_counts', {})
        if channel['metrics']['protocol_counts'][protocol] > 0
    )))
    
    # Start building the HTML string
    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Source Statistics Report</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 font-sans">
    <div class="container mx-auto px-4 py-8">
        <header class="text-center mb-8">
            <h1 class="text-4xl font-bold text-gray-800">Proxy Sources Report</h1>
            <p class="text-gray-600 mt-2">Last Updated: {stats_data.get('timestamp', 'N/A')}</p>
        </header>

        <div class="bg-white shadow-lg rounded-lg overflow-hidden">
            <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-200">
                    <thead class="bg-gray-50">
                        <tr>
                            <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider sticky left-0 bg-gray-50 z-10">Source URL</th>
                            <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Total Valid Proxies</th>
                            {''.join(f'<th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">{protocol.replace("://", "")}</th>' for protocol in all_protocols)}
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">
    '''

    # Populate the table with data from each channel
    for channel in sorted_channels:
        metrics = channel.get('metrics', {})
        protocol_counts = metrics.get('protocol_counts', {})
        
        # Shorten the URL for display
        display_url = channel.get('url', 'Unknown URL').split('/')[-1]
        if not display_url:
            display_url = channel.get('url').split('/')[-2]


        html += f'''
                        <tr>
                            <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900 sticky left-0 bg-white" title="{channel.get('url', '')}">{display_url}</td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-center font-bold text-gray-700">{metrics.get('valid_configs', 0)}</td>
                            {''.join(f'<td class="px-6 py-4 whitespace-nowrap text-sm text-center text-gray-500">{(protocol_counts.get(protocol, 0) or "-")}</td>' for protocol in all_protocols)}
                        </tr>
        '''

    html += '''
                    </tbody>
                </table>
            </div>
        </div>
        <footer class="text-center text-gray-500 mt-8">
            <p>Report generated automatically.</p>
        </footer>
    </div>
</body>
</html>
    '''
    return html

def main():
    stats_file_path = os.path.join('configs', 'channel_stats.json')
    output_file_path = os.path.join('assets', 'source_statistics_report.html')

    try:
        print(f"Reading statistics from {stats_file_path}...")
        with open(stats_file_path, 'r', encoding='utf-8') as f:
            stats_data = json.load(f)
        
        print("Generating HTML report...")
        html_content = generate_source_report_html(stats_data)
        
        # Ensure the output directory exists
        os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
        
        with open(output_file_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"Successfully generated source statistics report at {output_file_path}")

    except FileNotFoundError:
        print(f"Error: Statistics file not found at {stats_file_path}. Please run the fetcher script first.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == '__main__':
    main()

