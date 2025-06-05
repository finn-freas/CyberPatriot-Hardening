#!/bin/bash

# CyberPatriot Hardening Script for Ubuntu
# Author: Finn

# Function to log actions
log_action() {
  echo "$(date) - $1" >> /var/log/cyberpatriot_hardening.log
}

echo "Starting CyberPatriot Hardening Script..."
log_action "Script started."

# Update and upgrade the system
echo "Updating system..."
sudo apt update && sudo apt upgrade -y
log_action "System updated and upgraded."

# Install essential packages
echo "Installing essential packages..."
sudo apt install -y ufw fail2ban clamav unattended-upgrades auditd
log_action "Essential packages installed."

# Enable and configure the firewall
echo "Configuring firewall..."
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw enable
log_action "Firewall configured and enabled."

# Enable automatic updates
echo "Enabling automatic updates..."
sudo dpkg-reconfigure --priority=low unattended-upgrades
log_action "Automatic updates enabled."

# Set up Fail2Ban
echo "Configuring Fail2Ban..."
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
log_action "Fail2Ban configured."

# Configure auditing
echo "Configuring auditd..."
sudo systemctl enable auditd
sudo systemctl start auditd
sudo auditctl -e 1
log_action "Auditing enabled."

# Scan for malicious files
echo "Scanning for malware..."
sudo freshclam
sudo clamscan -r / --bell -i
log_action "Malware scan completed."

# Remove unnecessary users
echo "Removing unnecessary users..."
sudo deluser --remove-home guest
log_action "Unnecessary users removed."

# Lock down root account
echo "Locking down root account..."
sudo passwd -l root
log_action "Root account locked."

# Secure SSH configuration
echo "Securing SSH configuration..."
sudo sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config sudo systemctl \ restart sshd
log_action "SSH configuration secured."

# Check and disable unnecessary services
echo "Disabling unnecessary services..."
services=("telnet" "ftp" "rsh-server" "nfs-kernel-server" "rpcbind")
for service in "${services[@]}"; do
  sudo systemctl stop $service
  sudo systemctl disable $service
  log_action "Disabled $service."
done

# Check for open ports
echo "Checking for open ports..."
sudo netstat -tuln
log_action "Open ports checked."

# Set secure permissions
echo "Setting secure permissions..."
sudo chmod -R go-rwx /root
sudo chmod -R go-rwx /home/*

# Check for world-writable files
echo "Checking for world-writable files..."
sudo find / -type f -perm /o+w >> /var/log/cyberpatriot_world_writable.log
log_action "World-writable files checked."

# Configure password policies
echo "Configuring password policies..."
sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
sudo sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs
sudo sed -i 's|pam_unix\.so|pam_unix.so remember=5 minlen=8|' /etc/pam.d/common-password
sudo sed -i ‘s|pam_cracklib\.so|pam_cracklib.so ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1|’ \ /etc/pam.d/common-password

# Check for each line, modify if present, append if not
# Modify 'PermitRootLogin no' if present, else append
if grep -qF 'PermitRootLogin no' /etc/ssh/sshd_config; then
    sudo sed -i '/^PermitRootLogin/s/.*/PermitRootLogin no/' /etc/ssh/sshd_config
else
    echo 'PermitRootLogin no' | sudo tee -a /etc/ssh/sshd_config
fi

# Modify 'ChallengeResponseAuthentication no' if present, else append
if grep -qF 'ChallengeResponseAuthentication no' /etc/ssh/sshd_config; then
    sudo sed -i '/^ChallengeResponseAuthentication/s/.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
else
    echo 'ChallengeResponseAuthentication no' | sudo tee -a /etc/ssh/sshd_config
fi

# Modify 'PasswordAuthentication no' if present, else append
if grep -qF 'PasswordAuthentication no' /etc/ssh/sshd_config; then
    sudo sed -i '/^PasswordAuthentication/s/.*/PasswordAuthentication no/' /etc/ssh/sshd_config
else
    echo 'PasswordAuthentication no' | sudo tee -a /etc/ssh/sshd_config
fi

# Modify 'UsePAM no' if present, else append
if grep -qF 'UsePAM no' /etc/ssh/sshd_config; then
    sudo sed -i '/^UsePAM/s/.*/UsePAM no/' /etc/ssh/sshd_config
else
    echo 'UsePAM no' | sudo tee -a /etc/ssh/sshd_config
fi

# Modify 'PermitEmptyPasswords no' if present, else append
if grep -qF 'PermitEmptyPasswords no' /etc/ssh/sshd_config; then
    sudo sed -i '/^PermitEmptyPasswords/s/.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
else
    echo 'PermitEmptyPasswords no' | sudo tee -a /etc/ssh/sshd_config
fi

log_action "Password policies configured."

# Verify system integrity
echo "Verifying system integrity..."
sudo apt install -y debsums
sudo debsums -s
log_action "System integrity verified."

# Restart critical services
echo "Restarting critical services..."
sudo systemctl restart sshd
sudo systemctl restart ufw
log_action "Critical services restarted."

# Check and remove Telnet
echo “Removing Telnet and Samba if present”
if dpkg -l | grep -q telnetd; then
    echo "Telnet is installed. Removing..."

    # Stop the Telnet service if it’s running
    sudo systemctl stop telnet

    # Disable Telnet from starting at boot
    sudo systemctl disable telnet

    # Uninstall Telnet package
    sudo apt-get remove --purge -y telnetd

    # Remove unused dependencies
    sudo apt-get autoremove -y
    echo "Telnet has been removed."
else
    echo "Telnet is not installed."
fi

# Check and remove Samba
if dpkg -l | grep -q samba; then
    echo "Samba is installed. Removing..."

    # Stop the Samba services if they are running
    sudo systemctl stop smbd nmbd

    # Disable Samba from starting at boot
    sudo systemctl disable smbd nmbd

    # Uninstall Samba packages
    sudo apt-get remove --purge -y samba samba-common samba-common-bin

    # Remove unused dependencies
    sudo apt-get autoremove -y
    echo "Samba has been removed."
else
    echo "Samba is not installed."
fi

log_action “Telnet and Samba removed :)”

#Kernel Hardening
echo “Kernel Hardening beginning”
settings="kernel.exec-shield=1
kernel.randomize_va_space=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.conf.all.accept_source_route=0
net.ipv6.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv6.conf.default.accept_source_route=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_max_syn_backlog=2048
net.ipv4.tcp_synack_retries=2
net.ipv4.tcp_syn_retries=5
net.ipv4.ip_forward=0
net.ipv4.conf.all.log_martians=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.conf.all.accept_redirects=0
net.ipv6.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
net.ipv4.icmp_echo_ignore_all=1"
for setting in $settings; do
    # Remove any existing line with this setting, then add the new one
    sudo sed -i "/^$(echo $setting | cut -d= -f1)/d" /etc/sysctl.conf
    echo "$setting" | sudo tee -a /etc/sysctl.conf > /dev/null
done 
log_action “Kernel Hardening completed”




echo "CyberPatriot Hardening Script completed. Please review /var/log/cyberpatriot_hardening.log for details."
log_action "Script completed."

exit 0

