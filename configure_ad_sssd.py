#!/usr/bin/env python3
"""
AD/SSSD Configuration Script for Ubuntu 22.04
This script configures Active Directory integration with SSSD for GNOME Desktop and SSH
"""

import os
import subprocess
import shutil
import sys
import argparse
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ADSSSDConfigurator:
    def __init__(self, domain, realm, domain_controller, admin_user):
        self.domain = domain
        self.realm = realm
        self.domain_controller = domain_controller
        self.admin_user = admin_user
        self.config_dir = Path('/etc/sssd')
        self.pkcs11_dir = Path('/etc/pkcs11')
        
    def install_packages(self):
        """Install required packages for AD/SSSD integration"""
        packages = [
            'sssd',
            'sssd-tools',
            'adcli',
            'realmd',
            'packagekit',
            'krb5-user',
            'samba-common-bin',
            'krb5-config',
            'winbind',
            'libpam-sss',
            'libnss-sss',
            'libpam-pkcs11',
            'opensc',
            'pcscd',
            'libccid',
            'libpam-ccreds',
            'libnss-db',
            'libpam-cap'
        ]
        
        logger.info("Installing required packages...")
        try:
            subprocess.run(['apt', 'update'], check=True)
            subprocess.run(['apt', 'install', '-y'] + packages, check=True)
            logger.info("Packages installed successfully")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to install packages: {e}")
            return False
        return True
    
    def discover_domain(self):
        """Discover and join the Active Directory domain"""
        logger.info(f"Discovering domain: {self.realm}")
        try:
            # Discover domain
            subprocess.run(['realm', 'discover', self.realm], check=True)
            
            # Join domain
            join_cmd = [
                'realm', 'join',
                '--user', self.admin_user,
                '--computer-ou', f'OU=Linux,DC={self.domain},DC=com',
                self.realm
            ]
            subprocess.run(join_cmd, check=True)
            logger.info("Successfully joined domain")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to join domain: {e}")
            return False
    
    def configure_sssd(self):
        """Configure SSSD for AD integration"""
        sssd_config = f"""[sssd]
domains = {self.domain}
config_file_version = 2
services = nss, pam, ssh

[domain/{self.domain}]
debug_level = 9
enumerate = true
id_provider = ad
auth_provider = ad
chpass_provider = ad
access_provider = ad
ldap_id_mapping = true
cache_credentials = true
krb5_store_password_if_offline = true
default_shell = /bin/bash
fallback_homedir = /home/%u@%d
use_fully_qualified_names = true
ad_gpo_access_control = permissive
ad_enable_gc = false
dyndns_update = false
subdomain_homedir = /home/%d/%u
ad_hostname = {os.uname().nodename}.{self.domain}.com
ldap_user_ssh_public_key = sshPublicKey
"""
        
        logger.info("Configuring SSSD...")
        try:
            with open('/etc/sssd/sssd.conf', 'w') as f:
                f.write(sssd_config)
            
            # Set correct permissions
            os.chmod('/etc/sssd/sssd.conf', 0o600)
            subprocess.run(['systemctl', 'restart', 'sssd'], check=True)
            logger.info("SSSD configured successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to configure SSSD: {e}")
            return False
    
    def configure_pam(self):
        """Configure PAM for SSSD and smart card authentication"""
        logger.info("Configuring PAM...")
        
        # Configure PAM for SSSD
        try:
            # Common-auth
            auth_config = """# /etc/pam.d/common-auth
auth    [success=2 default=ignore]      pam_pkcs11.so
auth    [success=1 default=ignore]      pam_sss.so use_first_pass
auth    requisite                       pam_deny.so
auth    required                        pam_permit.so
auth    optional                        pam_cap.so
"""
            
            # Common-account
            account_config = """# /etc/pam.d/common-account
account sufficient      pam_sss.so
account required        pam_unix.so
"""
            
            # Common-session
            session_config = """# /etc/pam.d/common-session
session required        pam_mkhomedir.so skel=/etc/skel umask=0022
session optional        pam_sss.so
session required        pam_unix.so
session optional        pam_systemd.so
"""
            
            # Write PAM configurations
            with open('/etc/pam.d/common-auth', 'w') as f:
                f.write(auth_config)
            
            with open('/etc/pam.d/common-account', 'w') as f:
                f.write(account_config)
            
            with open('/etc/pam.d/common-session', 'w') as f:
                f.write(session_config)
                
            logger.info("PAM configured successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to configure PAM: {e}")
            return False
    
    def configure_nsswitch(self):
        """Configure nsswitch.conf for SSSD"""
        logger.info("Configuring nsswitch...")
        
        nsswitch_config = """passwd:         compat sss
group:          compat sss
shadow:         compat sss
gshadow:        files

hosts:          files mdns4_minimal [NOTFOUND=return] dns
networks:       files

protocols:      db files
services:       db files
ethers:         files
rpc:            files

netgroup:       nis sss
sudoers:        files sss
"""
        
        try:
            with open('/etc/nsswitch.conf', 'w') as f:
                f.write(nsswitch_config)
            logger.info("nsswitch configured successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to configure nsswitch: {e}")
            return False
    
    def configure_ssh(self):
        """Configure SSH for AD/SSSD authentication"""
        logger.info("Configuring SSH...")
        
        sshd_config_additions = f"""
# AD/SSSD Configuration
AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys
AuthorizedKeysCommandUser nobody
UsePAM yes
ChallengeResponseAuthentication yes
AuthenticationMethods publickey,keyboard-interactive:pam

# Kerberos Configuration
KerberosAuthentication yes
KerberosOrLocalPasswd yes
KerberosTicketCleanup yes
KerberosGetAFSToken no

# GSSAPI Configuration
GSSAPIAuthentication yes
GSSAPICleanupCredentials yes
GSSAPIStrictAcceptorCheck yes
GSSAPIKeyExchange no
"""
        
        try:
            # Backup original sshd_config
            shutil.copy2('/etc/ssh/sshd_config', '/etc/ssh/sshd_config.backup')
            
            # Append AD/SSSD configuration
            with open('/etc/ssh/sshd_config', 'a') as f:
                f.write(sshd_config_additions)
            
            # Restart SSH service
            subprocess.run(['systemctl', 'restart', 'ssh'], check=True)
            logger.info("SSH configured successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to configure SSH: {e}")
            return False
    
    def configure_krb5(self):
        """Configure Kerberos for AD authentication"""
        logger.info("Configuring Kerberos...")
        
        krb5_config = f"""[libdefaults]
    default_realm = {self.realm.upper()}
    dns_lookup_realm = true
    dns_lookup_kdc = true
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true
    rdns = false
    pkinit_anchors = FILE:/etc/ssl/certs/ca-certificates.crt
    pkinit_pool = FILE:/var/lib/sss/pubconf/krb5.include.d/*.pkinit

[realms]
    {self.realm.upper()} = {{
        kdc = {self.domain_controller}
        admin_server = {self.domain_controller}
    }}

[domain_realm]
    .{self.domain} = {self.realm.upper()}
    {self.domain} = {self.realm.upper()}
"""
        
        try:
            with open('/etc/krb5.conf', 'w') as f:
                f.write(krb5_config)
            logger.info("Kerberos configured successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to configure Kerberos: {e}")
            return False
    
    def run_all(self):
        """Run all configuration steps"""
        steps = [
            ("Installing packages", self.install_packages),
            ("Discovering and joining domain", self.discover_domain),
            ("Configuring SSSD", self.configure_sssd),
            ("Configuring PAM", self.configure_pam),
            ("Configuring nsswitch", self.configure_nsswitch),
            ("Configuring SSH", self.configure_ssh),
            ("Configuring Kerberos", self.configure_krb5),
        ]
        
        success = True
        for step_name, step_func in steps:
            logger.info(f"Starting: {step_name}")
            if not step_func():
                logger.error(f"Failed at: {step_name}")
                success = False
                break
        
        if success:
            logger.info("All configurations completed successfully!")
            subprocess.run(['systemctl', 'enable', 'sssd'], check=True)
            subprocess.run(['systemctl', 'start', 'sssd'], check=True)
        return success

def main():
    parser = argparse.ArgumentParser(
        description='Configure AD/SSSD authentication for Ubuntu 22.04'
    )
    parser.add_argument('--domain', required=True, help='AD domain name (e.g., example)')
    parser.add_argument('--realm', required=True, help='AD realm (e.g., example.com)')
    parser.add_argument('--domain-controller', required=True, help='Domain controller hostname')
    parser.add_argument('--admin-user', required=True, help='AD admin username')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be done without executing')
    
    args = parser.parse_args()
    
    if os.geteuid() != 0:
        logger.error("This script must be run as root")
        sys.exit(1)
    
    configurator = ADSSSDConfigurator(
        args.domain,
        args.realm,
        args.domain_controller,
        args.admin_user
    )
    
    if args.dry_run:
        logger.info("Dry run mode - showing configuration parameters:")
        logger.info(f"Domain: {args.domain}")
        logger.info(f"Realm: {args.realm}")
        logger.info(f"Domain Controller: {args.domain_controller}")
        logger.info(f"Admin User: {args.admin_user}")
    else:
        success = configurator.run_all()
        sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()