# Multi Proxy Config Fetcher

This project automatically fetches and updates various proxy configurations from public Telegram channels. It supports multiple proxy protocols including WireGuard, Hysteria2, VLESS, VMess, Shadowsocks, and Trojan.

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
- Validates config age (excludes configs older than 2 days)
- Removes duplicates
- Tracks channel reliability and success rates
- Balances config distribution across protocols

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

The project now tracks channel performance metrics in `configs/channel_stats.json`:
- Success rate for config fetching
- Channel reliability tracking
- Retry counts and status

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Disclaimer

This project is for educational purposes only. Make sure to comply with all relevant laws and regulations when using proxy services.