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

def generate_chart_svg(stats_data, is_light=True):
    channels = stats_data['channels']
    width = 900
    height = 600
    margin = 40
    gauge_size = 120
    gauges_per_row = 5
    row_height = gauge_size + 60
    
    svg = f'''<svg width="{width}" height="{height}" xmlns="http://www.w3.org/2000/svg">
    <defs>
        <linearGradient id="score-gradient" x1="0%" y1="0%" x2="100%" y1="0%">
            <stop offset="0%" style="stop-color:#ef4444"/>
            <stop offset="100%" style="stop-color:#22c55e"/>
        </linearGradient>
    </defs>
    <style>
        .title {{ font: bold 20px sans-serif; fill: #1f2937; }}
        .gauge-title {{ font: bold 14px sans-serif; fill: #1f2937; }}
        .gauge-value {{ font: bold 18px sans-serif; fill: #1f2937; }}
        .metric {{ font: 12px sans-serif; fill: #6b7280; }}
    </style>'''
    
    y_offset = 80
    for idx, channel in enumerate(channels):
        row = idx // gauges_per_row
        col = idx % gauges_per_row
        
        cx = margin + (col * (width-2*margin)/gauges_per_row) + gauge_size
        cy = y_offset + (row * row_height) + gauge_size/2
        
        score = channel['metrics']['overall_score']
        channel_name = channel['url'].split('/')[-1]
        success_rate = (channel['metrics']['success_count'] / max(1, channel['metrics']['success_count'] + channel['metrics']['fail_count'])) * 100
        
        svg += f'''
        <circle cx="{cx}" cy="{cy}" r="{gauge_size/2}" fill="none" stroke="#e5e7eb" stroke-width="10"/>
        <path d="{get_gauge_path(cx, cy, gauge_size/2, score)}" fill="url(#score-gradient)" opacity="0.8"/>
        <text x="{cx}" y="{cy-10}" text-anchor="middle" class="gauge-title">{channel_name}</text>
        <text x="{cx}" y="{cy+15}" text-anchor="middle" class="gauge-value">{score:.1f}%</text>
        <text x="{cx}" y="{cy+35}" text-anchor="middle" class="metric">Success: {success_rate:.1f}%</text>
        '''
    
    svg += f'''<text x="{width/2}" y="40" text-anchor="middle" class="title">Channel Performance Dashboard</text>
    </svg>'''
    
    return svg

def generate_html_report(stats_data):
    html = f'''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Channel Performance Report</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-gray-50">
        <div class="max-w-7xl mx-auto px-4 py-8">
            <h1 class="text-3xl font-bold text-gray-900 mb-8 text-center">Channel Performance Dashboard</h1>
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
    '''
    
    for channel in stats_data['channels']:
        score = channel['metrics']['overall_score']
        channel_name = channel['url'].split('/')[-1]
        success_rate = (channel['metrics']['success_count'] / max(1, channel['metrics']['success_count'] + channel['metrics']['fail_count'])) * 100
        
        color = 'green' if score >= 70 else 'yellow' if score >= 50 else 'red'
        
        html += f'''
        <div class="bg-white p-6 rounded-lg shadow">
            <h2 class="text-xl font-semibold mb-4">{channel_name}</h2>
            <div class="space-y-4">
                <div class="flex justify-between items-center">
                    <span class="text-gray-600">Overall Score:</span>
                    <span class="font-bold text-{color}-600">{score:.1f}%</span>
                </div>
                <div class="flex justify-between items-center">
                    <span class="text-gray-600">Success Rate:</span>
                    <span class="font-bold">{success_rate:.1f}%</span>
                </div>
                <div class="flex justify-between items-center">
                    <span class="text-gray-600">Valid/Total:</span>
                    <span class="font-bold">{channel['metrics']['valid_configs']}/{channel['metrics']['total_configs']}</span>
                </div>
                <div class="flex justify-between items-center">
                    <span class="text-gray-600">Response Time:</span>
                    <span class="font-bold">{channel['metrics']['avg_response_time']:.1f}s</span>
                </div>
            </div>
        </div>
        '''
    
    html += f'''
            </div>
            <div class="text-center text-gray-500 text-sm mt-8">
                Last updated: {stats_data['timestamp']}
            </div>
        </div>
    </body>
    </html>
    '''
    
    return html

def main():
    try:
        with open('configs/channel_stats.json', 'r') as f:
            stats_data = json.load(f)
        
        chart_svg = generate_chart_svg(stats_data)
        html_report = generate_html_report(stats_data)
        
        os.makedirs('assets', exist_ok=True)
        with open('assets/channel_stats_chart.svg', 'w') as f:
            f.write(chart_svg)
            
        with open('assets/performance_report.html', 'w') as f:
            f.write(html_report)
            
        print("Chart and report generated successfully!")
        
    except Exception as e:
        print(f"Error generating chart: {str(e)}")

if __name__ == '__main__':
    main()