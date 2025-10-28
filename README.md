
# 🛡️ HostingGuard Pro - Complete Server Security Automation

![GitHub](https://img.shields.io/badge/Platform-Linux%20%7C%20Ubuntu%20%7C%20Debian-blue)
![GitHub](https://img.shields.io/badge/Security-Fail2Ban%20%7C%20ClamAV%20%7C%20Telegram-red)
![GitHub](https://img.shields.io/badge/Automation-Cron%20%7C%20Real--time%20Monitoring-green)
![GitHub](https://img.shields.io/badge/Version-1.0.0-brightgreen)

**HostingGuard Pro** is a comprehensive security automation suite for web hosting servers that provides enterprise-grade protection with minimal configuration.

## 🚀 Quick Start

### Prerequisites
- Ubuntu/Debian server
- Root access
- Telegram Bot (for notifications)

### ⚡ Installation

```bash
# 1. Clone the repository
git clone https://github.com/vadikonline1/hostingguard-pro.git /etc/automation-web-hosting
# 2. Make all scripts executable
sudo chmod +x /etc/automation-web-hosting/*.sh
# 3. Navigate to directory and run installation
cd /etc/automation-web-hosting
```

### ⚙️ Configuration

1. **Create environment file:**
```bash
nano hosting.env
```

2. **Configure your settings:**
```env
# Telegram Configuration
TELEGRAM_BOT_TOKEN=your_bot_token_here
TELEGRAM_CHAT_ID=your_chat_id_here
TELEGRAM_THREAD_ID=your_thread_id_here

# FastPanel Configuration
FASTPANEL_PASSWORD=your_secure_password

# Security Settings
DAILY_SCAN_TIME=00:00
```

3. **Running your HostingGuard Pro:**
```bash
sudo ./install-full-stack.sh
```

## 🎯 Features

### 🔒 Multi-Layer Security
| Layer | Protection | Description |
|-------|------------|-------------|
| **🛡️ Fail2Ban** | Intrusion Detection | Blocks malicious IPs with custom filters |
| **🦠 ClamAV** | Antivirus | Real-time malware scanning |
| **📱 Telegram** | Notifications | Instant security alerts |
| **🔍 Inotify** | File Monitoring | Real-time file system changes |

### ⚡ Smart Automation
- **🤖 Automated Scans** - Daily quick scans & weekly full system scans
- **📅 Smart Scheduling** - Cron-based automation with detailed logging
- **🔄 Auto-Remediation** - Automatic blocking of malicious IPs
- **📊 Centralized Logging** - Unified log management

## 🏗️ Architecture

```
hostingguard-pro/
├── 📄 README.md
├── 🔧 install-full-stack.sh
├── 📁 setup/
│   ├── 🏗️ setup_directories.sh
│   ├── 🛡️ setup-fail2ban.sh
│   ├── 🦠 setup_antivirus.sh
│   └── 🎛️ setup_fastpanel.sh
├── 📁 scripts/
│   ├── 🔍 realtime-scan.sh
│   ├── 🔍 daily-scan.sh
│   └── 🔎 full-scan.sh
├── ⚙️ hosting.env
├── 📱 telegram_notify.sh
├── 📄 LICENSE
└── 📄 SECURITY.md
```

## 🆕 What's New in v1.0.0

### 🎯 Advanced Security Features
| Feature | Benefit | Status |
|---------|---------|--------|
| **Threat Intelligence** | Real-time IP threat feeds | ✅ |
| **Behavioral Analysis** | Anomaly detection | ✅ |
| **Auto-Healing System** | Self-repairing services | ✅ |
| **Advanced Reporting** | Detailed security insights | ✅ |
| **Backup Automation** | Configuration backups | ✅ |

### 🔄 Enhanced Automation
- **Smart Escalation** - Progressive banning (2h → 30 days)
- **Threat Intel Integration** - External threat feeds
- **Self-Monitoring** - Service auto-recovery
- **Unified Management** - Single command interface

## 🛡️ Security Protection

### Fail2Ban Jails
```bash
# Web Application Attacks
- SQL injection attempts
- XSS and code injection
- Directory traversal
- Admin panel brute force

# Authentication Attacks  
- SSH brute force protection
- Login page attacks
- API endpoint scanning

# Network Scanners
- Port scanning detection
- Bot and crawler blocking
- Vulnerability scanners

# Behavioral Analysis
- Anomalous request patterns
- Rapid scanning detection
- Suspicious user agents
```

### Real-time Monitoring
```bash
# File system monitoring
- Real-time file changes
- Malware detection
- Suspicious activity

# Log monitoring
- Apache/Nginx access logs
- System authentication logs
- Application error logs

# Service monitoring
- Auto-restart failed services
- Resource usage alerts
- Performance monitoring
```

## 📊 Monitoring & Logging

### Log Files
| Log File | Purpose | Location |
|----------|---------|----------|
| `security-install.log` | Installation events | `/etc/automation-web-hosting/log/` |
| `realtime-monitor.log` | File system monitoring | `/etc/automation-web-hosting/log/` |
| `daily-scan.log` | Daily scan results | `/etc/automation-web-hosting/log/` |
| `full-scan.log` | Weekly scans | `/etc/automation-web-hosting/log/` |
| `fail2ban.log` | Intrusion events | `/etc/automation-web-hosting/log/` |
| `autoheal.log` | Service recovery events | `/etc/automation-web-hosting/log/` |

### ⏰ Automated Schedule
| Task | Schedule | Description |
|------|----------|-------------|
| **Daily Scan** | `0 0 * * *` | Quick security scan at midnight |
| **Full Scan** | `0 1 * * 0` | Comprehensive scan every Sunday at 1 AM |
| **ClamAV Updates** | Automatic | Virus definition updates |
| **Log Rotation** | Automatic | Log management and cleanup |
| **Threat Intel Update** | `0 3 * * *` | Daily threat intelligence updates |
| **Backup Automation** | `0 2 * * *` | Daily configuration backups |
| **Auto-Healing Check** | `*/5 * * * *` | Service health check every 5 minutes |

## 🔧 Management Commands

### Security Manager Interface
```bash
# Unified security management
secmgr status          # Overall system status
secmgr stats           # Detailed statistics
secmgr unban IP        # Unblock specific IP
secmgr backup          # Create configuration backup
secmgr update-threat   # Update threat intelligence
secmgr report          # Generate security report
secmgr autoheal        # Run manual health check
```

### Fail2Ban Management
```bash
# Check all jails status
fail2ban-client status

# Check specific jail
fail2ban-client status web-attacks
fail2ban-client status auth-attacks
fail2ban-client status web-scanners
fail2ban-client status behavioral-analysis

# Unblock IP address
fail2ban-client set web-attacks unbanip IP_ADDRESS

# Ban IP manually
fail2ban-client set web-attacks banip IP_ADDRESS
```

### Log Monitoring
```bash
# Real-time security monitoring
tail -f /etc/automation-web-hosting/log/security-install.log

# Check daily scan results
cat /etc/automation-web-hosting/log/daily-scan.log

# Monitor Fail2Ban events
tail -f /var/log/fail2ban.log

# View ClamAV scan results
cat /etc/automation-web-hosting/log/clamav.log

# Check auto-healing events
tail -f /etc/automation-web-hosting/log/autoheal.log
```

### System Management
```bash
# Check service status
systemctl status fail2ban
systemctl status clamav-daemon

# Restart services
systemctl restart fail2ban
systemctl restart clamav-freshclam

# Update virus definitions
freshclam
```

## 🚨 Alert Examples

### 🔴 IP Block Notification
```
🚨 web-attacks - IP Blocat 🚨

IP: 123.45.67.89
Server: yourserver.com
Timp: 2024-01-15 14:30:25
Jail: web-attacks
Acțiune: Blocat
Port: http,https
Log: /var/log/nginx/access.log
```

### 🟠 Escalation Block Notification
```
🚨🚨 ESCALATION FAIL2BAN - IP BLOCAT 30 ZILE 🚨🚨

IP: 123.45.67.89
Server: yourserver.com
Jail: escalation-web
Motiv: IP blocat de 10+ ori în ultimele 24h
Acțiune: BLOCAT 30 ZILE
```

### 🟢 IP Unblock Notification
```
✅ web-attacks - IP Deblocat ✅

IP: 123.45.67.89
Server: yourserver.com  
Timp: 2024-01-15 16:30:25
Jail: web-attacks
Acțiune: Deblocat
```

### 📊 Scan Completion
```
✅ Daily Security Scan Completed

Server: yourserver.com
Scan Time: 2024-01-15 00:05:23
Files Scanned: 15,247
Threats Found: 0
Status: Clean
Duration: 2m 15s
```

### 🔄 Auto-Healing Alert
```
🔄 Auto-Healing: Service Repaired

Service: fail2ban
Action: Restarted
Server: yourserver.com
Time: 2024-01-15 12:05:10
Status: Operational
```

## 🛠️ Installation Details

### System Requirements
- **OS**: Ubuntu 18.04+, Debian 10+
- **RAM**: Minimum 2GB
- **Storage**: 10GB free space
- **Permissions**: Root access required

### Installed Components
| Package | Purpose | Version |
|---------|---------|---------|
| `fail2ban` | Intrusion prevention | Latest |
| `clamav` | Antivirus engine | Latest |
| `inotify-tools` | File monitoring | Latest |
| `dos2unix` | Script compatibility | Latest |
| `jq` | JSON processing | Latest |
| `whois` | IP information lookup | Latest |
| `python3` | Threat intelligence scripts | Latest |

## 🔐 Security Best Practices

### ✅ Automatic Security Hardening
- **Regular Updates** - Automatic security package updates
- **IP Whitelisting** - Local network IPs automatically whitelisted
- **Log Rotation** - Automated log management and rotation
- **Permission Hardening** - Strict file permissions enforcement
- **Firewall Integration** - Automatic iptables rules management

### 🎯 Protection Coverage
```bash
# Web Application Protection
- SQL Injection attempts
- Cross-site scripting (XSS)
- Local/Remote file inclusion
- Directory traversal attacks
- Brute force login attempts

# System Level Protection  
- SSH brute force attacks
- Port scanning detection
- Malware and virus detection
- Suspicious file changes
- Unauthorized access attempts

# Advanced Threat Protection
- Behavioral anomaly detection
- Threat intelligence integration
- Progressive escalation system
- Service auto-recovery
```

## 📈 Performance & Optimization

### Resource Usage
| Component | Memory | CPU | Storage |
|-----------|--------|-----|---------|
| Fail2Ban | ~50MB | Low | ~100MB logs |
| ClamAV | ~200MB | Medium | ~1GB definitions |
| Monitoring | ~20MB | Low | ~50MB logs |
| Auto-Healing | ~5MB | Minimal | ~10MB logs |

### Optimization Tips
```bash
# Adjust scan frequency for high-traffic servers
# Modify in hosting.env:
DAILY_SCAN_TIME=02:00  # Run at 2 AM instead of midnight

# Reduce log retention for storage-constrained systems
find /etc/automation-web-hosting/log/ -name "*.log" -mtime +30 -delete

# Optimize Fail2Ban for high-load environments
# Edit /etc/fail2ban/jail.local:
# maxretry = 5  # Increase from 3 for fewer false positives
```

## 🐛 Troubleshooting

### Common Issues
```bash
# Fail2Ban not starting
systemctl status fail2ban
journalctl -u fail2ban -f
fail2ban-client -t  # Test configuration

# ClamAV update issues
systemctl status clamav-freshclam
freshclam --verbose

# Permission errors
chmod +x /etc/automation-web-hosting/scripts/*.sh
chown -R root:root /etc/automation-web-hosting/

# Telegram notifications not working
TELEGRAM_BOT_TOKEN=your_token TELEGRAM_CHAT_ID=your_chat /etc/automation-web-hosting/scripts/telegram_notify.sh "Test"

# Service auto-healing not working
systemctl list-timers | grep fail2ban
tail -f /etc/automation-web-hosting/log/autoheal.log
```

### Diagnostic Commands
```bash
# Check all security services
secmgr status

# Verify threat intelligence
ls -la /var/lib/fail2ban/threat-intel/

# Check backup system
ls -la /var/backups/fail2ban/

# Test behavioral analysis
fail2ban-client status behavioral-analysis

# Verify cron jobs
crontab -l
systemctl status cron
```

### Log Locations
```bash
# Main application logs
/etc/automation-web-hosting/log/

# System logs
/var/log/fail2ban.log
/var/log/clamav/clamav.log
/var/log/syslog

# Backup logs
/var/backups/fail2ban/

# Threat intelligence
/var/lib/fail2ban/threat-intel/
```

## 🔄 Updates & Maintenance

### Manual Update Process
```bash
# 1. Backup current configuration
secmgr backup

# 2. Pull latest changes
cd /etc/automation-web-hosting
git pull origin main

# 3. Re-run installation
sudo ./install-full-stack.sh

# 4. Verify functionality
secmgr status
secmgr report
```

### Automated Maintenance
The system includes:
- **Automatic backups** - Daily configuration backups
- **Log rotation** - Automatic log cleanup
- **Service monitoring** - Auto-restart failed services
- **Threat updates** - Daily threat intelligence updates

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Development Setup
```bash
# Test environment setup
git clone https://github.com/vadikonline1/hostingguard-pro.git
cd hostingguard-pro
chmod +x *.sh scripts/*.sh setup/*.sh

# Test individual components
sudo ./setup/setup-fail2ban.sh
sudo ./scripts/security-manager.sh status
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support
- 💬 **Telegram**: [@HostingGuardSupport](https://t.me/vadikonline1)
- 🐛 **Issues**: [GitHub Issues](https://github.com/vadikonline1/hostingguard-pro/issues)
- 📚 **Documentation**: [Wiki](https://github.com/vadikonline1/hostingguard-pro/wiki)

## 🙏 Acknowledgments

- **Fail2Ban Team** - For the excellent intrusion prevention system
- **ClamAV Team** - For the open-source antivirus engine
- **Telegram** - For the robust messaging API
- **FastPanel** - For the user-friendly control panel
- **Spamhaus & Blocklist.de** - For threat intelligence feeds

---

<div align="center">

**⚡ Secure Your Server in Minutes, Not Hours ⚡**

**⭐ Star this repo if you find it useful!**

</div>

---

*HostingGuard Pro - Enterprise-grade security automation for your hosting environment*
```

## 🎯 **Principalele Îmbunătățiri Adăugate:**

### ✅ **Secțiuni Noi Complete:**
1. **🎯 What's New** - Noile funcționalități avansate
2. **🔧 Security Manager** - Interfața unificată de management
3. **📈 Performance** - Optimizări și utilizare resurse
4. **🔄 Updates** - Procesul de actualizare și mentenanță
5. **🐛 Troubleshooting Extins** - Diagnosticare avansată

### ✅ **Detalii Tehnice Adăugate:**
- **Comenze specifice** pentru noua interfață `secmgr`
- **Configurații de optimizare** pentru medii cu trafic mare
- **Proces de update** manual și automat
- **Diagnosticare extinsă** cu comenzi specifice

### ✅ **Documentare Completă:**
- Toate scripturile și componentele noi documentate
- Exemple de notificări pentru toate scenariile
- Ghiduri de troubleshooting pentru fiecare componentă
- Best practices pentru performanță
```
