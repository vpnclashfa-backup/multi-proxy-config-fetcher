import json
import os
from datetime import datetime

def generate_basic_svg(stats_data):
    width = 800
    height = len(stats_data['channels']) * 50 + 100
    
    svg = f'''<?xml version="1.0" encoding="UTF-8"?>
    <svg width="{width}" height="{height}" version="1.1" xmlns="http://www.w3.org/2000/svg">
    <style>
        .row {{ font: 14px Arial; fill: #64748b; }}
        .score {{ font: bold 14px Arial; fill: #64748b; }}
    </style>
    <text x="400" y="40" text-anchor="middle" font-size="20px" font-weight="bold" fill="#64748b">Channel Performance Overview</text>'''
    
    for idx, channel in enumerate(stats_data['channels']):
        y = 80 + (idx * 50)
        name = channel['url'].split('/')[-1]
        score = channel['metrics']['overall_score']
        success = (channel['metrics']['success_count'] / 
                  max(1, channel['metrics']['success_count'] + channel['metrics']['fail_count'])) * 100
        
        svg += f'<rect x="150" y="{y}" width="500" height="30" fill="#eee" rx="5"/>'
        
        width = min(500, 5 * score)
        color = '#22c55e' if score >= 70 else '#eab308' if score >= 50 else '#ef4444'
        svg += f'<rect x="150" y="{y}" width="{width}" height="30" fill="{color}" rx="5"/>'
        
        svg += f'''
        <text x="140" y="{y+20}" text-anchor="end" class="row">{name}</text>
        <text x="660" y="{y+20}" text-anchor="start" class="score">{score:.1f}% (S:{success:.0f}%)</text>'''
    
    svg += '</svg>'
    return svg

def calculate_historical_data(stats_data):
    historical_data = []
    for channel in stats_data['channels']:
        name = channel['url'].split('/')[-1]
        success_rate = (channel['metrics']['success_count'] / 
                       max(1, channel['metrics']['success_count'] + channel['metrics']['fail_count'])) * 100
        historical_data.append({
            'name': name,
            'score': channel['metrics']['overall_score'],
            'successRate': success_rate,
            'responseTime': channel['metrics']['avg_response_time'],
            'validConfigs': channel['metrics']['valid_configs'],
            'totalConfigs': channel['metrics']['total_configs']
        })
    return historical_data

def generate_html_report(stats_data):
    historical_data = calculate_historical_data(stats_data)
    formatted_timestamp = datetime.fromisoformat(stats_data['timestamp']).strftime("%Y-%m-%d %H:%M:%S")
    
    html = f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Channel Performance Report</title>
    <script src="https://cdn.tailwindcss.com/3.3.0"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js" integrity="sha512-ElRFoEQdI5Ht6kZvyzXhYG9NqjtkmlkfYk0wr6wHxU9JEHakS7UJZNeml5ALk+8IKlU6jDgMabC3vkumRokgJA==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/apexcharts/3.41.0/apexcharts.min.js" integrity="sha512-bp/xZXR0Wn5q5TgPtz7EbgZlRrIU3tsqoROPe9sLwdY6Z+0p6XRzr7/JzqQUfTSD3rWanL6WUVW7peD4zSY/vQ==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" integrity="sha512-iecdLmaskl7CVkqkXNQ/ZH/XLlvWZOJyj7Yy7tcenmpD1ypASozpmT/E0iPtmFIB46ZmdtAc9eNBvH0H/ZpiBw==" crossorigin="anonymous" referrerpolicy="no-referrer" />
    <style>
        .chart-container {
            position: relative;
            height: 300px;
            width: 100%;
        }
        #responseTimeChart, #successRateChart, #scoreDistributionChart {
            width: 100%;
            min-height: 250px;
        }
    </style>
</head>
'''
<body class="bg-gray-50">
    <div class="min-h-screen">
        <nav class="bg-white shadow-lg">
            <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div class="flex justify-between h-16">
                    <div class="flex">
                        <div class="flex-shrink-0 flex items-center">
                            <i class="fas fa-chart-line text-indigo-600 text-2xl mr-2"></i>
                            <span class="text-2xl font-bold text-gray-900">Performance Dashboard</span>
                        </div>
                    </div>
                    <div class="flex items-center">
                        <span class="text-gray-500">
                            <i class="far fa-clock mr-2"></i>
                            Last Updated: {formatted_timestamp}
                        </span>
                    </div>
                </div>
            </div>
        </nav>

        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
                <div class="bg-white rounded-lg shadow p-6">
                    <h3 class="text-lg font-semibold mb-4">Performance Overview</h3>
                    <div>
                        <canvas id="performanceChart" height="300"></canvas>
                    </div>
                </div>
                <div class="bg-white rounded-lg shadow p-6">
                    <h3 class="text-lg font-semibold mb-4">Response Time Analysis</h3>
                    <div id="responseTimeChart" style="height: 300px;"></div>
                </div>
            </div>

            <div class="grid grid-cols-1 gap-6 mb-8">
                <div class="bg-white rounded-lg shadow p-6">
                    <h3 class="text-lg font-semibold mb-4">Channel Success Metrics</h3>
                    <div class="overflow-x-auto">
                        <table class="min-w-full divide-y divide-gray-200">
                            <thead>
                                <tr>
                                    <th class="px-6 py-3 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Channel</th>
                                    <th class="px-6 py-3 bg-gray-50 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Score</th>
                                    <th class="px-6 py-3 bg-gray-50 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Success Rate</th>
                                    <th class="px-6 py-3 bg-gray-50 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Valid/Total</th>
                                    <th class="px-6 py-3 bg-gray-50 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Response Time</th>
                                    <th class="px-6 py-3 bg-gray-50 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                                </tr>
                            </thead>
                            <tbody class="bg-white divide-y divide-gray-200">
                                {generate_table_rows(historical_data)}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div class="bg-white rounded-lg shadow p-6">
                    <h3 class="text-lg font-semibold mb-4">Config Distribution</h3>
                    <div>
                        <canvas id="configDistributionChart" height="250"></canvas>
                    </div>
                </div>
                <div class="bg-white rounded-lg shadow p-6">
                    <h3 class="text-lg font-semibold mb-4">Success Rate Comparison</h3>
                    <div id="successRateChart" style="height: 250px;"></div>
                </div>
                <div class="bg-white rounded-lg shadow p-6">
                    <h3 class="text-lg font-semibold mb-4">Performance Score Distribution</h3>
                    <div id="scoreDistributionChart" style="height: 250px;"></div>
                </div>
            </div>
        </div>
    </div>

    html += '''
    <script>
        // اطمینان از لود شدن کامل صفحه قبل از رندر نمودارها
        document.addEventListener('DOMContentLoaded', function() {
            setTimeout(function() {
                try {
                    // کد نمودارها
                    const historicalData = ''' + json.dumps(historical_data) + ''';
                    
                    // Chart.js نمودار
                    const perfCtx = document.getElementById('performanceChart').getContext('2d');
                    new Chart(perfCtx, {
                        type: 'bar',
                        data: {
                            labels: historicalData.map(d => d.name),
                            datasets: [{
                                label: 'Performance Score',
                                data: historicalData.map(d => d.score),
                                backgroundColor: historicalData.map(d => 
                                    d.score >= 70 ? '#22c55e' : 
                                    d.score >= 50 ? '#eab308' : '#ef4444'
                                ),
                                borderWidth: 1
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            scales: {
                                y: {
                                    beginAtZero: true,
                                    max: 100
                                }
                            }
                        }
                    });

                    // کانفیگ ApexCharts
                    const responseTimeConfig = {
                        series: [{
                            name: 'Response Time',
                            data: historicalData.map(d => parseFloat(d.responseTime.toFixed(2)))
                        }],
                        chart: {
                            type: 'area',
                            height: 250,
                            width: '100%',
                            animations: {
                                enabled: true
                            },
                            toolbar: {
                                show: false
                            }
                        },
                        dataLabels: {
                            enabled: false
                        },
                        stroke: {
                            curve: 'smooth',
                            width: 2
                        },
                        xaxis: {
                            categories: historicalData.map(d => d.name)
                        },
                        tooltip: {
                            y: {
                                formatter: function (val) {
                                    return val.toFixed(2) + "s";
                                }
                            }
                        },
                        fill: {
                            type: 'gradient',
                            gradient: {
                                shadeIntensity: 1,
                                opacityFrom: 0.7,
                                opacityTo: 0.3
                            }
                        }
                    };

                    const successRateConfig = {
                        series: [{
                            name: 'Success Rate',
                            data: historicalData.map(d => parseFloat(d.successRate.toFixed(1)))
                        }],
                        chart: {
                            height: 250,
                            width: '100%',
                            type: 'radar',
                            toolbar: {
                                show: false
                            }
                        },
                        xaxis: {
                            categories: historicalData.map(d => d.name)
                        },
                        fill: {
                            opacity: 0.5
                        }
                    };

                    const scoreDistributionConfig = {
                        series: historicalData.map(d => parseFloat(d.score.toFixed(1))),
                        chart: {
                            height: 250,
                            width: '100%',
                            type: 'polarArea',
                            toolbar: {
                                show: false
                            }
                        },
                        labels: historicalData.map(d => d.name),
                        fill: {
                            opacity: 0.8
                        }
                    };

                    // رندر نمودارهای ApexCharts
                    new ApexCharts(document.getElementById('responseTimeChart'), responseTimeConfig).render();
                    new ApexCharts(document.getElementById('successRateChart'), successRateConfig).render();
                    new ApexCharts(document.getElementById('scoreDistributionChart'), scoreDistributionConfig).render();

                } catch (error) {
                    console.error('Error rendering charts:', error);
                }
            }, 500); // تاخیر کوتاه برای اطمینان از آماده بودن DOM
        });
    </script>
</body>
</html>'''

    return html

def generate_table_rows(historical_data):
    rows = ''
    for data in historical_data:
        score_color = 'text-green-600' if data['score'] >= 70 else 'text-yellow-600' if data['score'] >= 50 else 'text-red-600'
        status = 'Active' if data['score'] >= 30 else 'Disabled'
        status_color = 'text-green-600' if status == 'Active' else 'text-red-600'
        
        rows += f'''
            <tr>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{data['name']}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-right {score_color} font-semibold">{data['score']:.1f}%</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-right text-gray-900">{data['successRate']:.1f}%</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-right text-gray-900">{data['validConfigs']}/{data['totalConfigs']}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-right text-gray-900">{data['responseTime']:.2f}s</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-right {status_color} font-semibold">{status}</td>
            </tr>'''
    return rows

def main():
    try:
        with open('configs/channel_stats.json', 'r') as f:
            stats_data = json.load(f)
        
        os.makedirs('assets', exist_ok=True)
        
        svg_content = generate_basic_svg(stats_data)
        with open('assets/channel_stats_chart.svg', 'w', encoding='utf-8') as f:
            f.write(svg_content)
            
        html_content = generate_html_report(stats_data)
        with open('assets/performance_report.html', 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        print("Successfully generated chart and report!")
        
    except Exception as e:
        print(f"Error generating outputs: {str(e)}")

if __name__ == '__main__':
    main()