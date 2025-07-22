# AD/SSSD and PIV Authentication for Ubuntu 22.04

This repository contains comprehensive scripts and configurations for setting up Active Directory (AD) integration with SSSD and PIV smart card authentication on Ubuntu 22.04 systems.

## Overview

This solution provides:
- **Active Directory Integration** via SSSD for centralized authentication
- **PIV Smart Card Authentication** for enhanced security
- **GNOME Desktop Integration** for seamless login experience
- **SSH Configuration** for remote access with AD/PIV credentials
- **Automated Deployment** using Ansible

## Components

### 1. Python Configuration Scripts

#### `configure_ad_sssd.py`
Configures Active Directory integration with SSSD:
- Domain joining and discovery
- SSSD configuration for AD authentication
- Kerberos configuration
- PAM configuration
- SSH integration

**Usage:**
```bash
sudo python3 configure_ad_sssd.py \
    --domain example \
    --realm example.com \
    --domain-controller dc.example.com \
    --admin-user admin
```

#### `configure_piv_auth.py`
Configures PIV smart card authentication:
- OpenSC and PCSC daemon setup
- PAM PKCS11 configuration
- GNOME smart card support
- Certificate management
- Service configuration

**Usage:**
```bash
sudo python3 configure_piv_auth.py --ca-cert /path/to/ca-cert.pem
```

### 2. Ansible Playbook

#### `deploy_ad_piv.yml`
Complete automated deployment using Ansible:
- Package installation
- Configuration deployment
- Service management
- Testing and validation

**Usage:**
```bash
# Create inventory file
cat > inventory << EOF
[ubuntu_hosts]
your-server.example.com

[ubuntu_hosts:vars]
ansible_user=your-user
ansible_ssh_private_key_file=~/.ssh/id_rsa
EOF

# Run playbook
ansible-playbook -i inventory deploy_ad_piv.yml \
    --extra-vars "vault_ad_admin_password=your_admin_password"
```

### 3. Configuration Templates

Located in the `templates/` directory:
- `sssd.conf.j2` - SSSD configuration
- `krb5.conf.j2` - Kerberos configuration
- `nsswitch.conf.j2` - Name service switch configuration
- `pam_pkcs11.conf.j2` - PAM PKCS11 configuration
- `opensc.conf.j2` - OpenSC configuration
- `50-smartcard` - GNOME smart card configuration

## Prerequisites

### System Requirements
- Ubuntu 22.04 LTS
- Root/sudo access
- Network connectivity to Active Directory
- PIV smart card reader (if using PIV authentication)
- CA certificate (if using certificate-based authentication)

### Network Requirements
- DNS resolution for AD domain
- LDAP/AD ports open (389, 636, 3268, 3269)
- Kerberos ports open (88, 464)

## Installation Methods

### Method 1: Manual Python Scripts

1. **Install dependencies:**
   ```bash
   sudo apt update && sudo apt install -y python3 python3-pip
   ```

2. **Configure AD integration:**
   ```bash
   sudo python3 configure_ad_sssd.py \
       --domain yourdomain \
       --realm yourdomain.com \
       --domain-controller dc.yourdomain.com \
       --admin-user youradmin
   ```

3. **Configure PIV authentication (optional):**
   ```bash
   sudo python3 configure_piv_auth.py --ca-cert /path/to/ca-cert.pem
   ```

### Method 2: Ansible Deployment

1. **Install Ansible:**
   ```bash
   sudo apt update && sudo apt install -y ansible
   ```

2. **Create inventory file:**
   ```bash
   cat > inventory << EOF
   [ubuntu_hosts]
   your-server.yourdomain.com
   
   [ubuntu_hosts:vars]
   ansible_user=youruser
   ansible_ssh_private_key_file=~/.ssh/id_rsa
   ad_domain=yourdomain
   ad_realm=yourdomain.com
   ad_domain_controller=dc.yourdomain.com
   ad_admin_user=youradmin
   EOF
   ```

3. **Create Ansible vault for password:**
   ```bash
   ansible-vault create vault.yml
   # Add: vault_ad_admin_password: your_admin_password
   ```

4. **Run playbook:**
   ```bash
   ansible-playbook -i inventory deploy_ad_piv.yml --ask-vault-pass
   ```

## Configuration Parameters

### AD/SSSD Configuration
| Parameter | Description | Example |
|-----------|-------------|---------|
| `--domain` | AD domain name | `example` |
| `--realm` | AD realm (FQDN) | `example.com` |
| `--domain-controller` | Domain controller hostname | `dc.example.com` |
| `--admin-user` | AD admin username | `admin` |

### PIV Configuration
| Parameter | Description | Example |
|-----------|-------------|---------|
| `--ca-cert` | Path to CA certificate file | `/tmp/ca-cert.pem` |

## Testing and Validation

### 1. Verify AD Integration
```bash
# Check domain status
realm list

# Test user lookup
getent passwd username@domain.com

# Test authentication
su - username@domain.com
```

### 2. Verify PIV Authentication
```bash
# Check smart card reader
pcsc_scan

# Test PIV card detection
opensc-tool -l

# Test PIV authentication
# Insert card and attempt login via GDM
```

### 3. Verify SSH Access
```bash
# Test SSH with AD credentials
ssh username@domain.com@server

# Test SSH with PIV card
ssh -I /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so username@server
```

## Troubleshooting

### Common Issues

#### 1. Domain Join Failures
- **Check DNS resolution**: `nslookup yourdomain.com`
- **Verify credentials**: `kinit admin@YOURDOMAIN.COM`
- **Check firewall**: Ensure ports 389, 636, 88, 464 are open

#### 2. SSSD Issues
- **Check logs**: `journalctl -u sssd -f`
- **Test configuration**: `sssctl config-check`
- **Verify user lookup**: `getent passwd username@domain.com`

#### 3. PIV Card Issues
- **Check reader**: `lsusb | grep -i smart`
- **Test PCSC**: `pcsc_scan`
- **Check OpenSC**: `opensc-tool -l`
- **Verify PAM**: `sudo pamtester login username authenticate`

### Log Locations
- SSSD: `/var/log/sssd/`
- PAM: `/var/log/auth.log`
- Kerberos: `/var/log/krb5.log`
- OpenSC: `/var/log/opensc-debug.log`

### Service Management
```bash
# Restart services
sudo systemctl restart sssd
sudo systemctl restart ssh
sudo systemctl restart pcscd
sudo systemctl restart gdm3

# Check service status
sudo systemctl status sssd
sudo systemctl status ssh
sudo systemctl status pcscd
```

## Security Considerations

### Certificate Management
- Store CA certificates securely
- Regular certificate rotation
- Monitor certificate expiration

### PIV Card Security
- Implement card PIN policies
- Enable card lockout after failed attempts
- Regular security audits

### AD Security
- Use least privilege for service accounts
- Monitor AD logs for anomalies
- Regular password rotation

## Additional Resources

### Documentation
- [SSSD Documentation](https://sssd.io/docs)
- [OpenSC Documentation](https://github.com/OpenSC/OpenSC/wiki)
- [Ubuntu AD Integration Guide](https://ubuntu.com/server/docs/service-sssd-ad)
- [PIV/CAC Card Guide](https://developers.yubico.com/PIV/Guides/)

### Useful Commands
```bash
# SSSD tools
sssctl user-show username@domain.com
sssctl domain-status yourdomain.com

# Kerberos tools
kinit username@DOMAIN.COM
klist

# Smart card tools
pkcs11-tool -L
pkcs11-tool -O
```

## Support

For issues or questions:
1. Check the troubleshooting section
2. Review log files
3. Test with provided validation commands
4. Open an issue in the repository

## License

This project is provided as-is for educational and operational use. Please ensure you understand and test all configurations in your environment before production deployment.