import json
import os
from datetime import datetime

def get_gauge_path(cx, cy, radius, value, start_angle=-180, end_angle=0):
    max_angle = end_angle - start_angle
    angle = start_angle + (max_angle * value / 100)
    x1 = cx + radius * -1
    y1 = cy + 0
    x2 = cx + radius * -1 * (angle / -180)
    y2 = cy + radius * (angle / -180)
    large_arc = 1 if (angle - start_angle) > 180 else 0
    path = f"M {cx} {cy} L {x1} {y1} A {radius} {radius} 0 {large_arc} 1 {x2} {y2} Z"
    return path

def generate_chart_svg(stats_data):
    channels = stats_data['channels']
    width = 800
    height = 400
    margin = 40
    gauge_size = 100
    gauges_per_row = 5
    row_height = gauge_size + 60
    
    svg = f'''<?xml version="1.0" encoding="UTF-8" standalone="no"?>
    <svg viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg">
    <defs>
        <linearGradient id="score-gradient" x1="0%" y1="0%" x2="100%" y1="0%">
            <stop offset="0%" style="stop-color:#ef4444"/>
            <stop offset="100%" style="stop-color:#22c55e"/>
        </linearGradient>
    </defs>'''
    
    y_offset = 60
    for idx, channel in enumerate(channels):
        row = idx // gauges_per_row
        col = idx % gauges_per_row
        
        cx = margin + (col * (width-2*margin)/gauges_per_row) + gauge_size
        cy = y_offset + (row * row_height) + gauge_size/2
        
        score = channel['metrics']['overall_score']
        channel_name = channel['url'].split('/')[-1]
        success_rate = (channel['metrics']['success_count'] / max(1, channel['metrics']['success_count'] + channel['metrics']['fail_count'])) * 100
        
        svg += f'''
        <circle cx="{cx}" cy="{cy}" r="{gauge_size/2}" fill="none" stroke="#e5e7eb" stroke-width="8"/>
        <path d="{get_gauge_path(cx, cy, gauge_size/2, score)}" fill="url(#score-gradient)" opacity="0.8"/>
        <text x="{cx}" y="{cy-10}" text-anchor="middle" style="font: bold 14px sans-serif;">{channel_name}</text>
        <text x="{cx}" y="{cy+15}" text-anchor="middle" style="font: bold 16px sans-serif;">{score:.1f}%</text>
        <text x="{cx}" y="{cy+35}" text-anchor="middle" style="font: 12px sans-serif;">Success: {success_rate:.1f}%</text>
        '''
    
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
        channel_name = channel['url'].split('/')[-1]
        success_rate = (channel['metrics']['success_count'] / max(1, channel['metrics']['success_count'] + channel['metrics']['fail_count'])) * 100
        
        html += f'''
                <div class="bg-white rounded-lg shadow p-6">
                    <h2 class="text-xl font-semibold mb-4">{channel_name}</h2>
                    <div class="space-y-3">
                        <div class="flex justify-between">
                            <span>Overall Score:</span>
                            <span class="font-bold">{score:.1f}%</span>
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
        svg_content = generate_chart_svg(stats_data)
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