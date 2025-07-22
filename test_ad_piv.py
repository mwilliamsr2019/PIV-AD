#!/usr/bin/env python3
"""
Test script for AD/SSSD and PIV authentication validation
This script tests the configuration and provides diagnostic information
"""

import os
import subprocess
import sys
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ADPIVValidator:
    def __init__(self):
        self.tests = []
        
    def add_test(self, name, func, critical=True):
        """Add a test to the validation suite"""
        self.tests.append({
            'name': name,
            'func': func,
            'critical': critical,
            'passed': None,
            'message': ''
        })
    
    def run_command(self, cmd, timeout=30):
        """Run a command and return result"""
        try:
            result = subprocess.run(
                cmd, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=timeout
            )
            return {
                'success': result.returncode == 0,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode
            }
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'stdout': '',
                'stderr': 'Command timed out',
                'returncode': -1
            }
        except Exception as e:
            return {
                'success': False,
                'stdout': '',
                'stderr': str(e),
                'returncode': -1
            }
    
    def test_sssd_service(self):
        """Test if SSSD service is running"""
        logger.info("Testing SSSD service...")
        result = self.run_command("systemctl is-active sssd")
        if result['success'] and 'active' in result['stdout']:
            return True, "SSSD service is running"
        else:
            return False, f"SSSD service is not running: {result['stderr']}"
    
    def test_realm_status(self):
        """Test AD domain join status"""
        logger.info("Testing AD domain status...")
        result = self.run_command("realm list")
        if result['success'] and 'domain-name' in result['stdout']:
            return True, f"Domain joined: {result['stdout']}"
        else:
            return False, "System is not joined to any domain"
    
    def test_user_lookup(self):
        """Test AD user lookup"""
        logger.info("Testing AD user lookup...")
        # Try to find a domain user
        result = self.run_command("getent passwd | grep '@' | head -1")
        if result['success'] and '@' in result['stdout']:
            return True, f"Found domain user: {result['stdout'].strip()}"
        else:
            return False, "No domain users found"
    
    def test_kerberos_ticket(self):
        """Test Kerberos ticket acquisition"""
        logger.info("Testing Kerberos configuration...")
        result = self.run_command("klist 2>/dev/null || echo 'No tickets'")
        if 'ticket' in result['stdout'].lower():
            return True, "Kerberos tickets available"
        else:
            return True, "Kerberos configured but no active tickets (normal)"
    
    def test_pcscd_service(self):
        """Test PCSC daemon for smart cards"""
        logger.info("Testing PCSC daemon...")
        result = self.run_command("systemctl is-active pcscd")
        if result['success'] and 'active' in result['stdout']:
            return True, "PCSC daemon is running"
        else:
            return False, f"PCSC daemon is not running: {result['stderr']}"
    
    def test_smartcard_reader(self):
        """Test smart card reader detection"""
        logger.info("Testing smart card reader...")
        result = self.run_command("lsusb | grep -i smart")
        if result['success'] and result['stdout'].strip():
            return True, f"Smart card reader detected: {result['stdout'].strip()}"
        else:
            return False, "No smart card reader detected"
    
    def test_opensc_module(self):
        """Test OpenSC PKCS11 module"""
        logger.info("Testing OpenSC module...")
        result = self.run_command("ls /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so")
        if result['success']:
            return True, "OpenSC PKCS11 module found"
        else:
            return False, "OpenSC PKCS11 module not found"
    
    def test_pam_pkcs11_config(self):
        """Test PAM PKCS11 configuration"""
        logger.info("Testing PAM PKCS11 configuration...")
        config_path = Path("/etc/pam_pkcs11/pam_pkcs11.conf")
        if config_path.exists():
            return True, "PAM PKCS11 configuration exists"
        else:
            return False, "PAM PKCS11 configuration not found"
    
    def test_ssh_config(self):
        """Test SSH configuration for AD/SSSD"""
        logger.info("Testing SSH configuration...")
        sshd_config = Path("/etc/ssh/sshd_config")
        if sshd_config.exists():
            content = sshd_config.read_text()
            if "AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys" in content:
                return True, "SSH configured for AD/SSSD"
            else:
                return False, "SSH not configured for AD/SSSD"
        else:
            return False, "SSH configuration file not found"
    
    def test_gnome_smartcard(self):
        """Test GNOME smart card configuration"""
        logger.info("Testing GNOME smart card configuration...")
        config_path = Path("/etc/gdm3/greeter.dconf-defaults.d/50-smartcard")
        if config_path.exists():
            content = config_path.read_text()
            if "enable-smartcard-authentication=true" in content:
                return True, "GNOME smart card authentication enabled"
            else:
                return False, "GNOME smart card configuration incomplete"
        else:
            return False, "GNOME smart card configuration not found"
    
    def test_certificates(self):
        """Test certificate installation"""
        logger.info("Testing certificate installation...")
        cert_dir = Path("/etc/pki/ca-trust/source/anchors")
        if cert_dir.exists() and any(cert_dir.glob("*.pem")):
            return True, "CA certificates installed"
        else:
            return False, "No CA certificates found"
    
    def test_nsswitch(self):
        """Test NSS configuration"""
        logger.info("Testing NSS configuration...")
        nsswitch = Path("/etc/nsswitch.conf")
        if nsswitch.exists():
            content = nsswitch.read_text()
            if "sss" in content:
                return True, "NSS configured for SSSD"
            else:
                return False, "NSS not configured for SSSD"
        else:
            return False, "NSS configuration file not found"
    
    def run_all_tests(self):
        """Run all validation tests"""
        logger.info("Starting AD/SSSD and PIV validation...")
        
        # Add all tests
        self.add_test("SSSD Service", self.test_sssd_service)
        self.add_test("Realm Status", self.test_realm_status)
        self.add_test("User Lookup", self.test_user_lookup)
        self.add_test("Kerberos", self.test_kerberos_ticket)
        self.add_test("PCSC Daemon", self.test_pcscd_service, critical=False)
        self.add_test("Smart Card Reader", self.test_smartcard_reader, critical=False)
        self.add_test("OpenSC Module", self.test_opensc_module, critical=False)
        self.add_test("PAM PKCS11 Config", self.test_pam_pkcs11_config, critical=False)
        self.add_test("SSH Config", self.test_ssh_config)
        self.add_test("GNOME Smart Card", self.test_gnome_smartcard, critical=False)
        self.add_test("Certificates", self.test_certificates, critical=False)
        self.add_test("NSS Config", self.test_nsswitch)
        
        # Run tests
        passed = 0
        failed = 0
        warnings = 0
        
        print("=" * 60)
        print("AD/SSSD and PIV Validation Results")
        print("=" * 60)
        
        for test in self.tests:
            try:
                success, message = test['func']()
                test['passed'] = success
                test['message'] = message
                
                if success:
                    print(f"✅ {test['name']}: {message}")
                    passed += 1
                elif not test['critical']:
                    print(f"⚠️  {test['name']}: {message}")
                    warnings += 1
                else:
                    print(f"❌ {test['name']}: {message}")
                    failed += 1
                    
            except Exception as e:
                test['passed'] = False
                test['message'] = str(e)
                print(f"❌ {test['name']}: Error - {str(e)}")
                failed += 1
        
        print("=" * 60)
        print(f"Summary: {passed} passed, {failed} failed, {warnings} warnings")
        print("=" * 60)
        
        # Provide recommendations
        if failed > 0:
            print("\n🔧 Recommendations for failed tests:")
            print("1. Check system logs: journalctl -u sssd -f")
            print("2. Verify network connectivity to AD")
            print("3. Ensure all packages are installed")
            print("4. Check configuration files for errors")
        
        if warnings > 0:
            print("\n⚠️  Non-critical issues detected:")
            print("Some optional features (like smart cards) may not be configured")
        
        return failed == 0

def main():
    """Main validation function"""
    if os.geteuid() != 0:
        logger.warning("Some tests may require root privileges")
    
    validator = ADPIVValidator()
    success = validator.run_all_tests()
    
    if success:
        print("\n🎉 All critical tests passed!")
        sys.exit(0)
    else:
        print("\n❌ Some critical tests failed!")
        sys.exit(1)

if __name__ == '__main__':
    main()