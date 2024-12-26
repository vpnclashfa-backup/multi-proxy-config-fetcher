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
- Fetches configs from multiple Telegram channels
- Automatically updates configs every hour
- Validates config age (excludes configs older than 2 months)
- Removes duplicates
- Adds consistent naming format (#Anon1, #Anon2, etc.)

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
- Minimum configs per channel
- Maximum config age
- Output file location
- Supported protocols

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Disclaimer

This project is for educational purposes only. Make sure to comply with all relevant laws and regulations when using proxy services.