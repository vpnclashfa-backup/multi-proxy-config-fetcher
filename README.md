# Multi Proxy Config Fetcher

This project automatically fetches and updates various proxy configurations from public Telegram channels. It supports multiple proxy protocols including WireGuard, Hysteria2, VLESS, VMess, Shadowsocks, and Trojan.

## Channel Performance

Below is the real-time performance statistics of the configured channels. This chart is automatically updated every hour.

### Quick Overview
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/channel_stats_chart.svg?v=1735776821">
  <source media="(prefers-color-scheme: light)" srcset="assets/channel_stats_chart.svg?v=1735776821">
  <img alt="Channel Performance Statistics" src="assets/channel_stats_chart.svg?v=1735776821">
</picture>

### Detailed Report
For a detailed interactive report, view our [Performance Dashboard](https://htmlpreview.github.io/?https://github.com/YOUR_USERNAME/multi-proxy-config-fetcher/blob/main/assets/performance_report.html?v=1735776821)

Each channel is scored based on four key metrics:
- Reliability Score (35%): Success rate in config fetching and updates
- Config Quality (25%): Ratio of valid configs to total configs fetched
- Config Uniqueness (25%): Percentage of unique configs contributed
- Response Time (15%): Server response time and availability

The overall score is calculated in real-time and updated hourly. Channels scoring below 30% are automatically disabled.

> **Note**: These channels are configured as examples. You can easily modify the channel list in `src/config.py` to use your preferred Telegram channels. The performance metrics shown above are based on real-time monitoring of each channel's reliability in providing valid configurations.

## Features

- Supports multiple proxy protocols:
  - WireGuard
  - Hysteria2
  - VLESS
  - VMess
  - Shadowsocks (SS)
  - Trojan
- Smart handling of base64-encoded configs (preserves original format)
- Intelligent config naming (adds #AnonX only to non-base64 configs)
- Protocol-specific validation and verification
- Fetches configs from multiple Telegram channels
- Automatically updates configs every hour
- Validates config age (excludes configs older than 7 days)
- Removes duplicates
- Real-time channel performance monitoring
- Automatic channel health management
- Dynamic protocol distribution balancing

## Setup

1. Fork this repository
2. Edit `src/config.py` and add your Telegram channels to `TELEGRAM_CHANNELS` list
3. Enable GitHub Actions in your forked repository
4. The configs will be automatically updated every hour in `configs/proxy_configs.txt`

## Manual Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/multi-proxy-config-fetcher.git
cd multi-proxy-config-fetcher

# Install dependencies
pip install -r requirements.txt

# Run manually
python src/fetch_configs.py
```

## Configuration

Edit `src/config.py` to modify:
- Telegram channel list
- Minimum/maximum configs per protocol
- Protocol ratios and balancing
- Maximum config age
- Output file location
- Supported protocols
- Request headers and timeouts

## Project Structure

```
├── src/
│   ├── config.py              # Project configuration
│   ├── config_validator.py    # Config validation and verification
│   └── fetch_configs.py       # Main fetcher implementation
├── configs/
│   ├── proxy_configs.txt      # Output configs
│   └── channel_stats.json     # Channel performance stats
└── .github/
    └── workflows/
        └── update-configs.yml # GitHub Actions workflow
```

## Channel Statistics

The project tracks comprehensive channel performance metrics in `configs/channel_stats.json`:
- Overall performance score (0-100%)
- Success rate in config fetching
- Valid vs total configs ratio
- Unique config contribution
- Response time and reliability
- Channel health status

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Disclaimer

This project is for educational purposes only. Make sure to comply with all relevant laws and regulations when using proxy services.
