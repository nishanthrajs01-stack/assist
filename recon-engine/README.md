# ReconEngine 🔍

> Automated bug bounty recon pipeline: subdomain discovery → DNS validation → HTTP probing → endpoint harvesting → Nuclei scanning → change detection → webhook alerts + web dashboard.

## Features
- **5-Phase async pipeline**: subfinder → dnsx → httpx → gau/katana → nuclei
- **Stateful SQLite DB**: tracks all discovered assets and historical changes
- **Risk-tiered diff engine**: alerts only on actionable changes (new hosts, access flips, etc.)
- **Multi-platform alerts**: Discord, Slack, Telegram
- **Dark-mode dashboard**: asset browser, endpoint explorer, diff history viewer

---

## Quick Start

```bash
# 1. Install dependencies
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# 2. Configure your targets
nano config/targets.yaml       # Add root domains
nano config/settings.yaml      # Add webhook URLs, credentials

# 3. Initialize database
python main.py init-db

# 4. Run your first scan
python main.py scan --all

# 5. Launch dashboard (access via SSH tunnel)
python main.py dashboard
# ssh -L 8080:127.0.0.1:8080 user@your-vps → open http://localhost:8080
```

---

## CLI Reference

| Command | Description |
|---------|-------------|
| `python main.py init-db` | Create database tables |
| `python main.py scan --all` | Scan all configured programs |
| `python main.py scan --program "Name"` | Scan one program |
| `python main.py scan --all --no-nuclei` | Skip Nuclei phase |
| `python main.py notify` | Send pending webhook alerts |
| `python main.py status` | Print DB summary table |
| `python main.py dashboard` | Start web dashboard |

---

## Automation (Daily Cron)

```bash
# Install cron job (runs at 2AM daily)
0 2 * * * /opt/recon-engine/scripts/cron_daily.sh >> /var/log/recon-engine.log 2>&1

# Install dashboard as systemd service
sudo cp scripts/dashboard.service /etc/systemd/system/
sudo systemctl enable --now recon-engine-dashboard
```

---

## Required External Tools

Install from [ProjectDiscovery](https://github.com/projectdiscovery):

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/lc/gau/v2/cmd/gau@latest
```

---

## Project Structure

```
recon-engine/
├── config/           # targets.yaml, settings.yaml, resolvers.txt
├── core/             # database, runner, ingester, diff_engine, config
├── alerts/           # Discord/Slack/Telegram notifier
├── dashboard/        # FastAPI app + Jinja2 templates (4 pages)
├── data/             # SQLite database (recon.db)
├── scripts/          # cron_daily.sh, dashboard.service
└── main.py           # Master CLI entrypoint
```
