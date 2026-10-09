# 🛡️ HostingGuard Pro — Server Security Automation

Lightweight security automation for Ubuntu/Debian web hosting servers:
Fail2Ban intrusion prevention, ClamAV + Maldet malware scanning, threat
intelligence, self-healing services and Telegram alerts — tuned to **never
overload a small VPS**.

## Features

- **Fail2Ban multi-layer jails** — SSH, web attacks, auth attacks, scanners,
  behavioral analysis, threat-intel escalation (30-day bans for repeat offenders)
- **Whitelist guard** — IPs in `WHITELIST_IPS` can never be blocked: ACCEPT on
  iptables line 1 (above all `f2b-*` chains), auto-unban, threat-list and
  `ignoreip` sync, enforced hourly
- **ipset backend** (auto-detected, with fallback) — one hash lookup instead of
  hundreds of linear iptables rules per packet
- **ClamAV + Maldet scans** — daily quick scan, monthly full scan, lightweight
  real-time monitor (daemon-based, capped parallelism)
- **Self-healing** — restarts dead services, watches disk/inodes/memory/load
  with 1-hour alert cooldowns (no Telegram spam)
- **Low-resource by design** — every job runs `nice 19` + `ionice idle`, with
  `flock` locks, load guards and hard timeouts

## Requirements

- Ubuntu 20.04+ / Debian 11+ **or** Rocky/Alma/RHEL/CentOS 8+ with root access
- 1GB+ RAM recommended (works on 1GB with `ENABLE_MALDET=0`)
- A Telegram bot token + chat ID (for alerts only — everything works without it)

> On RHEL-family systems the installer uses `dnf`/`yum`, enables EPEL
> automatically and maps service names (`clamd@scan` instead of
> `clamav-daemon`). No manual steps — same commands as below.

## Install from scratch

```bash
# 1. Clone
git clone https://github.com/vadikonline1/hostingguard-pro.git /etc/automation-web-hosting
cd /etc/automation-web-hosting
chmod +x *.sh scripts/*.sh setup/*.sh

# 2. Configure (all values are placeholders — never commit real secrets)
nano hosting.env
```

```ini
FASTPANEL_PASSWORD="change-me"
TELEGRAM_BOT_TOKEN="change-me"
TELEGRAM_CHAT_ID="change-me"
TELEGRAM_THREAD_ID="change-me"
WHITELIST_IPS="YOUR_ADMIN_IP,YOUR_OFFICE_IP"
```

> ⚠️ Put **your own public IP** in `WHITELIST_IPS` (the one you SSH from).
> Without it, one mistyped password too many can lock you out for 30 days.

```bash
# 3. Install (idempotent — safe to re-run)
sudo ./install-full-stack.sh

# 4. Verify
secmgr status
secmgr whitelist
crontab -l
```

## Configuration (`hosting.env`)

| Variable | Default | Purpose |
|---|---|---|
| `WHITELIST_IPS` | `change-me` | Comma-separated IPs that are never blocked (`1.2.3.4,5.6.7.8`) |
| `USE_IPSET` | `1` | Fast ipset bans; auto-fallback if kernel lacks support |
| `DAILY_SCAN_PATHS` | web/home/tmp | Daily scope (never whole `/var` or `/usr`) |
| `FULL_SCAN_PATHS` | web/home/etc | Monthly full scope (no DB dirs, no `/usr`) |
| `MAX_FILE_SIZE` / `MAX_SCANSIZE` | `25M` / `50M` | Hard caps — archives bigger than this are skipped |
| `MAX_LOAD_FACTOR` | `2.0` | Skip scans when 1-min load > CPUs × factor |
| `CLAM_USE_DAEMON` | `1` | Prefer `clamdscan` over heavy `clamscan` forks |
| `ENABLE_MALDET` / `ENABLE_RKHUNTER` | `1` / `0` | Disable on tiny VPS (`0`) |
| `QUARANTINE_MODE` | `safe` | Quarantine web files only; system paths are reported, not moved |
| `REALTIME_MAX_PARALLEL` | `2` | Cap on concurrent real-time scans |
| `TELEGRAM_MAX_PER_HOUR` | `20` | Notification rate limit |
| `DISK_CRIT` / `MEM_CRIT` | `90` / `92` | Auto-heal alert thresholds (%) |
| `LOG_RETENTION_DAYS` | `7` | Log rotation (logrotate + daily prune safety net) |
| `QUARANTINE_RETENTION_DAYS` | `30` | Old quarantined files are deleted |

## Schedule (staggered, low priority)

| Task | Cron | Notes |
|---|---|---|
| Cleanup | `15 1 * * *` daily | 7-day logs (`/etc/logrotate.d/hostingguard` + prune safety net), /tmp markers, old quarantine/backups |
| Backup | `5 2 * * *` daily | `gzip -1`, keeps 14 days, alerts on failure only |
| Daily scan | `30 2 * * *` daily | Web/home/tmp, hard timeout |
| Threat intel | `0 3 * * 0` weekly | Capped at 50k IPs, whitelist excluded |
| Full scan | `0 4 1-7 * 0` monthly | First Sunday, never over `/usr`/DB dirs |
| Auto-heal | `*/15 * * * *` | Services + disk/inodes/memory/load |
| Whitelist guard | `17 * * * *` hourly | Runs in seconds, silent unless it fixes something |
| Report | `0 8 * * *` daily | Fail2Ban summary |

`freshclam` is managed by its systemd daemon (not cron); `rkhunter` is
opt-in via `ENABLE_RKHUNTER=1` — both were daily cron jobs that stalled servers.

## Management (`secmgr`)

```bash
secmgr status            # overall system status
secmgr stats             # detailed statistics
secmgr unban IP          # unban IP from ALL jails at once
secmgr whitelist         # show protected IPs + verify they are not blocked
secmgr whitelist-add IP  # add IP to whitelist and enforce immediately
secmgr backup            # manual config backup
secmgr update-threat     # manual threat-list refresh
secmgr report            # full report
secmgr autoheal          # manual health check
```

## Whitelist — read this if you were ever locked out

Fail2Ban inserts its `f2b-*` chains **above** any ACCEPT rule you add
manually, so a whitelisted IP still gets REJECTed. The guard fixes the order:

```bash
# Emergency: unban yourself RIGHT NOW (replace with your IP)
IP=YOUR_ADMIN_IP
for j in $(fail2ban-client status | sed -n 's/.*Jail list:[^:]*://p' | tr ',' ' '); do
  fail2ban-client set "$j" unbanip "$IP"
done
iptables -I INPUT 1 -s "$IP" -j ACCEPT

# Permanent: add to whitelist and enforce
secmgr whitelist-add YOUR_ADMIN_IP
```

Verify with `iptables -L INPUT -n --line-numbers` — your IP must be line 1,
**above** every `f2b-*` jump. `secmgr whitelist` checks this for you.

## Update procedure

```bash
secmgr backup
cd /etc/automation-web-hosting
git pull origin main
sudo ./install-full-stack.sh   # idempotent: keeps optimized scripts, refreshes crons
secmgr status && secmgr whitelist
```

Reinstalls never overwrite the optimized scripts (they carry a version
marker that setup detects and preserves).

## Performance design

- `nice 19` + `ionice idle` on every scan, backup and update
- `flock` on every cron job — overlapping runs (e.g. Sunday 00:00 + 01:00)
  were the #1 cause of full hangs
- Load guard skips scans when the server is already busy
- `clamdscan` daemon instead of one 200MB `clamscan` fork per file
- Real-time monitor watches `close_write/moved_to/create` only (no `modify`
  storm), 2 parallel scans max, noisy cache/session paths excluded
- System paths (`/usr`, `/var/lib/mysql`, `/var/lib/docker`, …) are excluded
  from scans and never quarantined in `safe` mode

## Troubleshooting

| Symptom | Fix |
|---|---|
| Disk full **right now** | `df -h` to confirm, then run: `truncate -s 0 /etc/automation-web-hosting/log/realtime-monitor.log` + `/etc/automation-web-hosting/scripts/prune-logs.sh` + `journalctl --vacuum-size=200M` if the journal is huge |
| `/tmp` full | `rm -rf /tmp/clamav_processed` (recreated automatically; monitor purges it every 500 events + prune daily) |
| Locked out (own IP banned) | Emergency commands above, then `secmgr whitelist-add` |
| High load during scans | Lower `MAX_LOAD_FACTOR`, set `ENABLE_MALDET=0`, check `uptime` vs cron hours |
| `ACCEPT 0.0.0.0/0` in `iptables -L INPUT` | Orphan rule that bypasses SSH filtering — find its source before removing; never auto-deleted by design |
| Duplicate `-j f2b-*` jumps in INPUT | Re-run `setup/setup_fail2ban.sh` — it dedupes them on every install |
| Telegram silent | `TELEGRAM_BOT_TOKEN`/`TELEGRAM_CHAT_ID` in `hosting.env`; test: `TELEGRAM_BOT_TOKEN=… TELEGRAM_CHAT_ID=… ./telegram_notify.sh "test"` |
| `^M`/CRLF errors after editing on Windows | Repo enforces LF via `.gitattributes`; run `dos2unix` on any file you touched |
| Fail2Ban won't start | `fail2ban-client -t`, then `journalctl -u fail2ban -n 30` |
| SELinux denials on Rocky (clamd/fail2ban) | Check `ausearch -m avc -ts recent`; either write a local policy or set the affected service permissive — installer logs the exact denial |
| firewalld + fail2ban on Rocky | Compatible (fail2ban manages its own chains); keep `firewalld` running, don't flush its rules |
| ipset not used | Normal on OpenVZ/Virtuozzo kernels — setup falls back to `iptables-multiport` automatically |

Logs: `/etc/automation-web-hosting/log/` · `/var/log/fail2ban.log` ·
`/var/log/clamav/` · backups: `/var/backups/fail2ban/` ·
threat lists: `/var/lib/fail2ban/threat-intel/`

## Layout

```
hostingguard-pro/
├── install-full-stack.sh
├── hosting.env               # placeholders only — fill in yours
├── telegram_notify.sh
├── scripts/
│   ├── common.sh             # shared guards: nice, flock, load, clam picker
│   ├── daily-scan.sh         # 02:30 daily, capped + load-guarded
│   ├── full-scan.sh          # monthly, no /usr or DB dirs
│   ├── realtime-scan.sh      # daemon-based, 2 parallel max
│   ├── whitelist-guard.sh    # hourly: whitelisted IPs are never blocked
│   ├── prune-logs.sh         # daily 01:15: 7-day logs, /tmp markers, old data
│   ├── fail2ban_autoheal.sh  # every 15 min, cooldown alerts
│   ├── fail2ban-backup.sh
│   ├── update-threat-intel.sh
│   ├── fail2ban-report.sh
│   ├── security-manager.sh   # → /usr/local/bin/secmgr
│   └── crontab.optimized     # reference schedule
└── setup/
    ├── setup_directories.sh
    ├── setup_fail2ban.sh     # jails + ipset + whitelist + crons
    ├── setup_antivirus.sh
    └── setup_fastpanel.sh
```

## License

GPL-3.0 — see [LICENSE](LICENSE).
