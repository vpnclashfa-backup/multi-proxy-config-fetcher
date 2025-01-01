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
    width = 1200
    height = 800
    margin = 60
    gauge_size = 160
    gauges_per_row = 5
    row_height = gauge_size + 80
    
    svg = f'''
    <svg width="{width}" height="{height}" xmlns="http://www.w3.org/2000/svg">
        <defs>
            <linearGradient id="score-gradient" x1="0%" y1="0%" x2="100%" y1="0%">
                <stop offset="0%" style="stop-color:#ef4444"/>
                <stop offset="33%" style="stop-color:#f97316"/>
                <stop offset="66%" style="stop-color:#eab308"/>
                <stop offset="100%" style="stop-color:#22c55e"/>
            </linearGradient>
        </defs>
        <style>
            .title {{ font: bold 24px sans-serif; fill: #1f2937; }}
            .subtitle {{ font: 14px sans-serif; fill: #6b7280; }}
            .gauge-title {{ font: bold 16px sans-serif; fill: #1f2937; }}
            .gauge-value {{ font: bold 24px sans-serif; fill: #1f2937; }}
            .gauge-label {{ font: 12px sans-serif; fill: #6b7280; }}
            .metric-value {{ font: bold 14px sans-serif; fill: #1f2937; }}
            .metric-label {{ font: 12px sans-serif; fill: #6b7280; }}
            .timestamp {{ font: 12px sans-serif; fill: #6b7280; }}
        </style>
        
        <text x="{width/2}" y="40" text-anchor="middle" class="title">
            Channel Performance Dashboard
        </text>
        <text x="{width/2}" y="65" text-anchor="middle" class="subtitle">
            Real-time monitoring of proxy configuration sources
        </text>
    '''
    
    y_offset = 100
    for idx, channel in enumerate(channels):
        row = idx // gauges_per_row
        col = idx % gauges_per_row
        
        cx = margin + (col * (width-2*margin)/gauges_per_row) + gauge_size
        cy = y_offset + (row * row_height) + gauge_size/2
        
        score = channel['metrics']['overall_score']
        channel_name = channel['url'].split('/')[-1]
        success_rate = (channel['metrics']['success_count'] / max(1, channel['metrics']['success_count'] + channel['metrics']['fail_count'])) * 100
        
        svg += f'''
        <circle cx="{cx}" cy="{cy}" r="{gauge_size/2}" 
                fill="none" stroke="#e5e7eb" stroke-width="15"/>
                
        <path d="{get_gauge_path(cx, cy, gauge_size/2, score)}"
              fill="url(#score-gradient)"
              opacity="0.8"/>
              
        <text x="{cx}" y="{cy-15}" text-anchor="middle" class="gauge-title">
            {channel_name}
        </text>
        <text x="{cx}" y="{cy+15}" text-anchor="middle" class="gauge-value">
            {score:.1f}%
        </text>
        '''
        
        metrics_y = cy + 50
        metrics = [
            ('Success Rate', f"{success_rate:.1f}%"),
            ('Valid/Total', f"{channel['metrics']['valid_configs']}/{channel['metrics']['total_configs']}"),
            ('Unique', f"{channel['metrics']['unique_configs']}"),
            ('Response', f"{channel['metrics']['avg_response_time']:.1f}s")
        ]
        
        for idx, (label, value) in enumerate(metrics):
            metric_x = cx - gauge_size/2 + (idx * gauge_size/2)
            svg += f'''
            <text x="{metric_x}" y="{metrics_y}" text-anchor="middle" class="metric-value">
                {value}
            </text>
            <text x="{metric_x}" y="{metrics_y+15}" text-anchor="middle" class="metric-label">
                {label}
            </text>
            '''
    
    svg += f'''
        <text x="{width-margin}" y="{height-20}" text-anchor="end" class="timestamp">
            Last updated: {stats_data['timestamp']}
        </text>
    </svg>
    '''
    
    return svg

def main():
    try:
        with open('configs/channel_stats.json', 'r') as f:
            stats_data = json.load(f)
        
        chart_svg = generate_chart_svg(stats_data)
        
        os.makedirs('assets', exist_ok=True)
        with open('assets/channel_stats_chart.svg', 'w') as f:
            f.write(chart_svg)
            
        print("Chart generated successfully!")
        
    except Exception as e:
        print(f"Error generating chart: {str(e)}")

if __name__ == '__main__':
    main()