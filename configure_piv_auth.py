#!/usr/bin/env python3
"""
PIV Smart Card Authentication Configuration Script for Ubuntu 22.04
This script configures PIV/CAC card authentication for GNOME Desktop, lock screen, and SSH
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

class PIVConfigurator:
    def __init__(self):
        self.config_dir = Path('/etc/pam_pkcs11')
        self.opensc_dir = Path('/etc/opensc')
        self.pkcs11_dir = Path('/etc/pkcs11')
        
    def install_piv_packages(self):
        """Install required packages for PIV smart card authentication"""
        packages = [
            'opensc',
            'pcscd',
            'libccid',
            'libpam-pkcs11',
            'libnss3-tools',
            'coolkey',
            'libpam-ccreds',
            'libnss-db',
            'libengine-pkcs11-openssl',
            'p11-kit',
            'p11-kit-modules',
            'gnome-keyring',
            'seahorse',
            'opensc-pkcs11',
            'libp11-kit-dev'
        ]
        
        logger.info("Installing PIV packages...")
        try:
            subprocess.run(['apt', 'update'], check=True)
            subprocess.run(['apt', 'install', '-y'] + packages, check=True)
            logger.info("PIV packages installed successfully")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to install PIV packages: {e}")
            return False
    
    def configure_pcscd(self):
        """Configure PCSC daemon for smart card support"""
        logger.info("Configuring PCSC daemon...")
        try:
            # Enable and start pcscd
            subprocess.run(['systemctl', 'enable', 'pcscd'], check=True)
            subprocess.run(['systemctl', 'start', 'pcscd'], check=True)
            subprocess.run(['systemctl', 'enable', 'pcscd.socket'], check=True)
            subprocess.run(['systemctl', 'start', 'pcscd.socket'], check=True)
            logger.info("PCSC daemon configured successfully")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to configure PCSC daemon: {e}")
            return False
    
    def configure_opensc(self):
        """Configure OpenSC for PIV card support"""
        logger.info("Configuring OpenSC...")
        
        opensc_config = """app default {
    # PIV card driver
    card_driver = "piv";
    
    # Enable PIV support
    enable_pin_pad = true;
    
    # PKCS11 configuration
    pkcs11 {
        # Enable PIV module
        enable_pkcs11 = true;
        
        # PIN caching
        pin_cache_ignore_user_consent = false;
        pin_cache_counter = 10;
        pin_cache_seconds = 300;
    }
}
"""
        
        try:
            # Create opensc configuration directory if it doesn't exist
            self.opensc_dir.mkdir(exist_ok=True)
            
            with open('/etc/opensc/opensc.conf', 'w') as f:
                f.write(opensc_config)
                
            logger.info("OpenSC configured successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to configure OpenSC: {e}")
            return False
    
    def configure_pam_pkcs11(self):
        """Configure PAM PKCS11 for smart card authentication"""
        logger.info("Configuring PAM PKCS11...")
        
        # Create pam_pkcs11 configuration directory
        self.config_dir.mkdir(exist_ok=True)
        
        pam_config = """# PAM PKCS11 Configuration
pkcs11_module opensc {
    module = /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so;
    description = "OpenSC PKCS#11 module";
    slot_num = 0;
    support_threads = true;
    cert_policy = ca, signature, ocsp_on;
    token_type = hardware;
}

# Certificate mapping
cert_policy = ca, signature, ocsp_on;
use_mappers = digest, cn, uid, mail, subject, serial, issuer, krb5_principal;
use_pkcs11_module = opensc;

# Debug logging
debug = false;
"""
        
        try:
            with open('/etc/pam_pkcs11/pam_pkcs11.conf', 'w') as f:
                f.write(pam_config)
            
            # Create certificate mapping directory
            cert_dir = Path('/etc/pam_pkcs11/cacerts')
            cert_dir.mkdir(exist_ok=True)
            
            logger.info("PAM PKCS11 configured successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to configure PAM PKCS11: {e}")
            return False
    
    def configure_gnome_smartcard(self):
        """Configure GNOME for smart card authentication"""
        logger.info("Configuring GNOME for smart card authentication...")
        
        try:
            # Install gdm-smartcard package
            subprocess.run(['apt', 'install', '-y', 'gdm3'], check=True)
            
            # Create gdm custom configuration
            gdm_config_dir = Path('/etc/gdm3/greeter.dconf-defaults.d')
            gdm_config_dir.mkdir(exist_ok=True)
            
            gdm_config = """# Enable smart card authentication
[org/gnome/login-screen]
enable-smartcard-authentication=true
fallback=true
"""
            
            with open('/etc/gdm3/greeter.dconf-defaults.d/50-smartcard', 'w') as f:
                f.write(gdm_config)
            
            # Update dconf database
            subprocess.run(['dconf', 'update'], check=True)
            logger.info("GNOME smart card authentication configured")
            return True
        except Exception as e:
            logger.error(f"Failed to configure GNOME smart card: {e}")
            return False
    
    def configure_pam_stack(self):
        """Configure PAM stack for PIV authentication"""
        logger.info("Configuring PAM stack for PIV...")
        
        # Configure common-auth for PIV
        auth_config = """# PAM configuration for smart card authentication
auth    [success=done new_authtok_reqd=done ignore=ignore default=bad] pam_pkcs11.so nodebug
auth    [success=1 default=ignore] pam_sss.so use_first_pass
auth    requisite                       pam_deny.so
auth    required                        pam_permit.so
auth    optional                        pam_cap.so
"""
        
        # Configure common-session
        session_config = """# Common session configuration
session [default=1]                     pam_permit.so
session requisite                       pam_deny.so
session required                        pam_permit.so
session optional                        pam_umask.so
session required        pam_mkhomedir.so skel=/etc/skel umask=0022
session optional        pam_sss.so
session optional        pam_systemd.so
session optional        pam_pkcs11.so
"""
        
        try:
            # Backup original configurations
            shutil.copy2('/etc/pam.d/common-auth', '/etc/pam.d/common-auth.backup')
            shutil.copy2('/etc/pam.d/common-session', '/etc/pam.d/common-session.backup')
            
            # Write new configurations
            with open('/etc/pam.d/common-auth', 'w') as f:
                f.write(auth_config)
            
            with open('/etc/pam.d/common-session', 'w') as f:
                f.write(session_config)
                
            logger.info("PAM stack configured for PIV")
            return True
        except Exception as e:
            logger.error(f"Failed to configure PAM stack: {e}")
            return False
    
    def configure_ssh_piv(self):
        """Configure SSH for PIV authentication"""
        logger.info("Configuring SSH for PIV authentication...")
        
        sshd_config_additions = """
# PIV Smart Card Authentication
PubkeyAuthentication yes
PasswordAuthentication no
ChallengeResponseAuthentication yes
AuthenticationMethods publickey,keyboard-interactive:pam

# PIV specific configurations
AuthorizedKeysFile none
AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys
AuthorizedKeysCommandUser nobody

# Enable PAM for SSH
UsePAM yes
"""
        
        try:
            # Append to sshd_config
            with open('/etc/ssh/sshd_config', 'a') as f:
                f.write(sshd_config_additions)
            
            # Restart SSH
            subprocess.run(['systemctl', 'restart', 'ssh'], check=True)
            logger.info("SSH configured for PIV authentication")
            return True
        except Exception as e:
            logger.error(f"Failed to configure SSH for PIV: {e}")
            return False
    
    def install_certificates(self, ca_cert_path=None):
        """Install and configure certificates for PIV"""
        logger.info("Configuring certificates for PIV...")
        
        try:
            # Create certificate directory
            cert_dir = Path('/etc/pki/ca-trust/source/anchors')
            cert_dir.mkdir(parents=True, exist_ok=True)
            
            if ca_cert_path and os.path.exists(ca_cert_path):
                # Copy CA certificate
                shutil.copy2(ca_cert_path, str(cert_dir))
                
                # Update CA trust
                subprocess.run(['update-ca-trust', 'extract'], check=True)
                logger.info("Certificates installed successfully")
            else:
                logger.warning("No CA certificate provided, skipping certificate installation")
                
            return True
        except Exception as e:
            logger.error(f"Failed to install certificates: {e}")
            return False
    
    def configure_smartcard_services(self):
        """Configure smart card services startup"""
        logger.info("Configuring smart card services...")
        
        try:
            # Enable smart card services
            services = ['pcscd', 'pcscd.socket', 'gdm3']
            
            for service in services:
                subprocess.run(['systemctl', 'enable', service], check=True)
                subprocess.run(['systemctl', 'restart', service], check=True)
            
            logger.info("Smart card services configured")
            return True
        except Exception as e:
            logger.error(f"Failed to configure smart card services: {e}")
            return False
    
    def test_smartcard_detection(self):
        """Test smart card detection"""
        logger.info("Testing smart card detection...")
        
        try:
            # Check if pcscd is running
            result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
            if 'pcscd' in result.stdout:
                logger.info("pcscd daemon is running")
            else:
                logger.warning("pcscd daemon is not running")
                return False
            
            # Test card reader
            result = subprocess.run(['pcsc_scan'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                logger.info("Smart card reader detected")
            else:
                logger.warning("Smart card reader not detected")
                
            return True
        except Exception as e:
            logger.error(f"Failed to test smart card detection: {e}")
            return False
    
    def run_all(self, ca_cert_path=None):
        """Run all PIV configuration steps"""
        steps = [
            ("Installing PIV packages", self.install_piv_packages),
            ("Configuring PCSC daemon", self.configure_pcscd),
            ("Configuring OpenSC", self.configure_opensc),
            ("Configuring PAM PKCS11", self.configure_pam_pkcs11),
            ("Configuring GNOME smartcard", self.configure_gnome_smartcard),
            ("Configuring PAM stack", self.configure_pam_stack),
            ("Configuring SSH PIV", self.configure_ssh_piv),
            ("Installing certificates", lambda: self.install_certificates(ca_cert_path)),
            ("Configuring smartcard services", self.configure_smartcard_services),
            ("Testing smartcard detection", self.test_smartcard_detection),
        ]
        
        success = True
        for step_name, step_func in steps:
            logger.info(f"Starting: {step_name}")
            if not step_func():
                logger.error(f"Failed at: {step_name}")
                success = False
                break
        
        if success:
            logger.info("All PIV configurations completed successfully!")
        return success

def main():
    parser = argparse.ArgumentParser(
        description='Configure PIV smart card authentication for Ubuntu 22.04'
    )
    parser.add_argument('--ca-cert', help='Path to CA certificate file')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be done without executing')
    
    args = parser.parse_args()
    
    if os.geteuid() != 0:
        logger.error("This script must be run as root")
        sys.exit(1)
    
    configurator = PIVConfigurator()
    
    if args.dry_run:
        logger.info("Dry run mode - showing configuration parameters")
    else:
        success = configurator.run_all(args.ca_cert)
        sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()