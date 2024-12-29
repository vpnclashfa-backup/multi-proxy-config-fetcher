import json
import os
from datetime import datetime

def generate_chart_svg(stats_data):
    width = 800
    height = 400
    margin = 60
    bar_width = (width - 2 * margin) / len(stats_data['channels'])
    max_success_rate = 100

    svg = f'''
    <svg width="{width}" height="{height}" xmlns="http://www.w3.org/2000/svg">
        <style>
            .chart-title {{ font: bold 16px sans-serif; }}
            .axis-label {{ font: 12px sans-serif; }}
            .tick-label {{ font: 10px sans-serif; }}
            .bar {{ fill: #4f46e5; }}
            .bar:hover {{ fill: #6366f1; }}
            .timestamp {{ font: 10px sans-serif; fill: #666; }}
        </style>
        
        <!-- Title -->
        <text x="{width/2}" y="30" text-anchor="middle" class="chart-title">
            Channel Success Rates
        </text>
        
        <!-- Y-axis -->
        <line x1="{margin}" y1="{height-margin}" x2="{margin}" y2="{margin}" 
              stroke="black" stroke-width="1"/>
        
        <!-- X-axis -->
        <line x1="{margin}" y1="{height-margin}" x2="{width-margin}" y2="{height-margin}" 
              stroke="black" stroke-width="1"/>
        
        <!-- Y-axis labels -->
        <text x="{margin-10}" y="{height-margin}" text-anchor="end" class="axis-label">0%</text>
        <text x="{margin-10}" y="{margin}" text-anchor="end" class="axis-label">100%</text>
        
        <!-- Bars and labels -->
    '''

    bar_x = margin
    for channel in stats_data['channels']:
        channel_name = channel['url'].split('/')[-1]
        success_rate = channel['success_rate']
        bar_height = ((height - 2 * margin) * success_rate) / max_success_rate
        bar_y = height - margin - bar_height
        
        svg += f'''
        <g>
            <rect x="{bar_x}" y="{bar_y}" width="{bar_width-5}" height="{bar_height}"
                  class="bar"/>
            <text x="{bar_x + bar_width/2}" y="{height-margin+40}" 
                  transform="rotate(45, {bar_x + bar_width/2}, {height-margin+40})"
                  text-anchor="start" class="tick-label">
                {channel_name}
            </text>
            <text x="{bar_x + bar_width/2}" y="{bar_y-5}" 
                  text-anchor="middle" class="tick-label">
                {success_rate:.1f}%
            </text>
        </g>
        '''
        bar_x += bar_width

    svg += f'''
        <text x="{width-margin}" y="{height-10}" text-anchor="end" class="timestamp">
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