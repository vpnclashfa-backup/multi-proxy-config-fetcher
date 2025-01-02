import json
import os
from datetime import datetime

def generate_basic_svg(stats_data):
    width = 800
    height = len(stats_data['channels']) * 50 + 100
    
    svg = f'''<?xml version="1.0" encoding="UTF-8"?>
    <svg width="{width}" height="{height}" version="1.1" xmlns="http://www.w3.org/2000/svg">
    <style>
        .row {{ font: 14px Arial; }}
        .score {{ font: bold 14px Arial; }}
    </style>
    <text x="400" y="40" text-anchor="middle" font-size="20px" font-weight="bold">Channel Performance Overview</text>'''
    
    for idx, channel in enumerate(stats_data['channels']):
        y = 80 + (idx * 50)
        name = channel['url'].split('/')[-1]
        score = channel['metrics']['overall_score']
        success = (channel['metrics']['success_count'] / 
                  max(1, channel['metrics']['success_count'] + channel['metrics']['fail_count'])) * 100
        
        # Background bar
        svg += f'<rect x="150" y="{y}" width="500" height="30" fill="#eee" rx="5"/>'
        
        # Score bar
        width = min(500, 5 * score)
        color = '#22c55e' if score >= 70 else '#eab308' if score >= 50 else '#ef4444'
        svg += f'<rect x="150" y="{y}" width="{width}" height="30" fill="{color}" rx="5"/>'
        
        # Text
        svg += f'''
        <text x="140" y="{y+20}" text-anchor="end" class="row">{name}</text>
        <text x="660" y="{y+20}" text-anchor="start" class="score">{score:.1f}% (S:{success:.0f}%)</text>'''
    
    svg += '</svg>'
    return svg

def generate_html_report(stats_data):
    html = f'''<!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <script src="https://cdn.tailwindcss.com"></script>
        <title>Channel Performance Report</title>
    </head>
    <body class="bg-gray-50 p-8">
        <div class="max-w-6xl mx-auto">
            <h1 class="text-3xl font-bold text-gray-900 mb-8 text-center">Channel Performance Dashboard</h1>
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">'''
    
    for channel in stats_data['channels']:
        score = channel['metrics']['overall_score']
        name = channel['url'].split('/')[-1]
        success_rate = (channel['metrics']['success_count'] / 
                       max(1, channel['metrics']['success_count'] + channel['metrics']['fail_count'])) * 100
        
        color = 'green' if score >= 70 else 'yellow' if score >= 50 else 'red'
        
        html += f'''
            <div class="bg-white rounded-lg shadow p-6">
                <h2 class="text-xl font-semibold mb-4">{name}</h2>
                <div class="space-y-3">
                    <div class="flex justify-between">
                        <span>Overall Score:</span>
                        <span class="font-bold text-{color}-600">{score:.1f}%</span>
                    </div>
                    <div class="flex justify-between">
                        <span>Success Rate:</span>
                        <span>{success_rate:.1f}%</span>
                    </div>
                    <div class="flex justify-between">
                        <span>Valid/Total:</span>
                        <span>{channel['metrics']['valid_configs']}/{channel['metrics']['total_configs']}</span>
                    </div>
                    <div class="flex justify-between">
                        <span>Response Time:</span>
                        <span>{channel['metrics']['avg_response_time']:.1f}s</span>
                    </div>
                </div>
            </div>'''
    
    html += f'''
            </div>
            <div class="text-center text-gray-500 text-sm mt-8">
                Last updated: {stats_data['timestamp']}
            </div>
        </div>
    </body>
    </html>'''
    
    return html

def main():
    try:
        with open('configs/channel_stats.json', 'r') as f:
            stats_data = json.load(f)
        
        os.makedirs('assets', exist_ok=True)
        
        # Generate and save SVG
        svg_content = generate_basic_svg(stats_data)
        with open('assets/channel_stats_chart.svg', 'w', encoding='utf-8') as f:
            f.write(svg_content)
        
        # Generate and save HTML
        html_content = generate_html_report(stats_data)
        with open('assets/performance_report.html', 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print("Successfully generated chart and report!")
        
    except Exception as e:
        print(f"Error generating outputs: {str(e)}")

if __name__ == '__main__':
    main()