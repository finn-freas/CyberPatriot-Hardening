# CyberPatriot Hardening Script for Ubuntu

![Ubuntu](https://img.shields.io/badge/platform-Ubuntu-orange?logo=ubuntu)
![Bash](https://img.shields.io/badge/language-Bash-blue?logo=gnu-bash)
![License](https://img.shields.io/badge/license-MIT-green)

Author: **Finn Freas**  
Secure your Ubuntu systems with this comprehensive hardening script designed for CyberPatriot competitions or general system defense.

---

## Features

This script performs the following tasks:

- System update & upgrade
- Firewall configuration (UFW)
- Fail2Ban setup
- ClamAV installation & full malware scan
- AuditD system activity monitoring
- User and root account lockdown
- Secure SSH configuration
- Removal of unnecessary services (e.g., Telnet, Samba)
- Open port & world-writable file checks
- Password policy enforcement
- Kernel parameter hardening
- Logs actions to `/var/log/cyberpatriot_hardening.log`

---

## Requirements

- Ubuntu 20.04 or later
- Sudo/root privileges

---

## Installation

Clone the repository to your system:

```bash
git clone git@github.com:finn-freas/CyberPatriot-Hardening.git
cd CyberPatriot-Hardening
```
---

How to Run the Script

Make sure the script is executable (run this only if needed):
```
chmod +x hardening_script.sh
```
Run the script with sudo privileges:
```
sudo ./hardening_script.sh
```
---

Script Logging

The script logs its actions to:
```
/var/log/cyberpatriot_hardening.log
```
To view the log after running the script, use:
```
sudo cat /var/log/cyberpatriot_hardening.log
```
---

Additional Info

The script disables root login and password authentication over SSH for security.
It removes insecure services like Telnet and Samba if they are installed.
It enforces password policies and kernel hardening for better system protection.

