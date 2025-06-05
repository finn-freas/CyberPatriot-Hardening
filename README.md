# 🛡️ CyberPatriot Hardening Script for Ubuntu

![Ubuntu](https://img.shields.io/badge/platform-Ubuntu-orange?logo=ubuntu)
![Bash](https://img.shields.io/badge/language-Bash-blue?logo=gnu-bash)
![License](https://img.shields.io/badge/license-MIT-green)

Author: **Finn Freas**  
Secure your Ubuntu systems with this comprehensive hardening script designed for CyberPatriot competitions or general system defense.

---

## 🚀 Features

This script performs the following tasks:

- 🔄 System update & upgrade
- 🔐 Firewall configuration (UFW)
- 🛡️ Fail2Ban setup
- 🧼 ClamAV installation & full malware scan
- 🕵️‍♂️ AuditD system activity monitoring
- 👥 User and root account lockdown
- 🔑 Secure SSH configuration
- 🚫 Removal of unnecessary services (e.g., Telnet, Samba)
- 🔎 Open port & world-writable file checks
- 🧾 Password policy enforcement
- 🧠 Kernel parameter hardening
- 📜 Logs actions to `/var/log/cyberpatriot_hardening.log`

---

## ⚙️ Requirements

- Ubuntu 20.04 or later
- Sudo/root privileges

---

## 📦 Installation

Clone the repository to your system:

```bash
git clone git@github.com:finn-freas/CyberPatriot-Hardening.git
cd CyberPatriot-Hardening

