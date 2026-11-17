#!/usr/bin/env python3
"""CyberAI Calion - Installation script for the Pentest Toolkit

Usage:
    python3 install.py              # Install to default location
    python3 install.py --user       # Install for current user only
    python3 install.py --uninstall  # Remove installation

After installation, run 'cyberai' from anywhere.
"""

import os
import sys
import shutil
import subprocess
import argparse
import stat

# Paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CYBERAI_DIR = os.path.join(SCRIPT_DIR, 'cyberai')
INSTALL_DIR = '/usr/local/bin'
USER_INSTALL_DIR = os.path.expanduser('~/.local/bin')
LINK_NAME = 'cyberai'
BINARY_NAME = 'cyberai-calion'  # The user-specified name


def check_root():
    """Check if running as root"""
    return os.geteuid() == 0


def install_systemwide():
    """Install system-wide (requires root)"""
    if not check_root():
        print("❌ System-wide install requires root. Use 'sudo python3 install.py' or 'python3 install.py --user'")
        return False
    
    # Create symlink in /usr/local/bin
    src = os.path.join(CYBERAI_DIR, 'cyberai.py')
    
    # Method 1: Create wrapper script
    wrapper = os.path.join(INSTALL_DIR, BINARY_NAME)
    wrapper_content = f"""#!/bin/bash
# CyberAI Calion - Pentest Toolkit
# Auto-generated wrapper script
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# Try to find cyberai directory
for dir in /usr/local/share/cyberai /opt/cyberai /usr/share/cyberai; do
    if [ -d "$dir" ]; then
        python3 "$dir/cyberai.py" "$@"
        exit $?
    fi
done
# Fallback: use PYTHONPATH
export PYTHONPATH="/usr/local/share/cyberai:$PYTHONPATH"
python3 /usr/local/share/cyberai/cyberai.py "$@"
"""
    
    with open(wrapper, 'w') as f:
        f.write(wrapper_content)
    os.chmod(wrapper, 0o755)
    
    # Copy cyberai directory to /usr/local/share/cyberai
    dest = os.path.join('/usr/local/share', 'cyberai')
    if os.path.exists(dest):
        shutil.rmtree(dest)
    shutil.copytree(CYBERAI_DIR, dest, ignore=shutil.ignore_patterns('__pycache__', '.git'))
    
    # Create symlink for 'cyberai' command
    cyberai_link = os.path.join(INSTALL_DIR, LINK_NAME)
    if os.path.exists(cyberai_link):
        os.remove(cyberai_link)
    os.symlink(wrapper, cyberai_link)
    
    # Create man page directory entry
    print(f"\n✅ CyberAI Calion installed successfully!")
    print(f"   Wrapper: {wrapper}")
    print(f"   Data: {dest}")
    print(f"   Commands: {BINARY_NAME}, {LINK_NAME}")
    print(f"\n   Run: {BINARY_NAME}")
    print(f"   Or:  {LINK_NAME}")
    
    return True


def install_user():
    """Install for current user only"""
    os.makedirs(USER_INSTALL_DIR, exist_ok=True)
    
    # Copy cyberai directory to ~/.local/share/cyberai
    dest = os.path.join(os.path.expanduser('~/.local/share'), 'cyberai')
    if os.path.exists(dest):
        shutil.rmtree(dest)
    shutil.copytree(CYBERAI_DIR, dest, ignore=shutil.ignore_patterns('__pycache__', '.git'))
    
    # Create wrapper script
    wrapper = os.path.join(USER_INSTALL_DIR, BINARY_NAME)
    wrapper_content = f"""#!/bin/bash
# CyberAI Calion - Pentest Toolkit
# Auto-generated wrapper script
export PYTHONPATH="{os.path.expanduser('~/.local/share/cyberai')}:$PYTHONPATH"
python3 "{os.path.expanduser('~/.local/share/cyberai')}/cyberai.py" "$@"
"""
    
    with open(wrapper, 'w') as f:
        f.write(wrapper_content)
    os.chmod(wrapper, 0o755)
    
    # Create symlink for 'cyberai' command
    cyberai_link = os.path.join(USER_INSTALL_DIR, LINK_NAME)
    if os.path.exists(cyberai_link):
        os.remove(cyberai_link)
    os.symlink(wrapper, cyberai_link)
    
    # Check if ~/.local/bin is in PATH
    home_bin = os.path.expanduser('~/.local/bin')
    if home_bin not in os.environ.get('PATH', ''):
        print(f"\n⚠️  {home_bin} is not in your PATH.")
        print(f"   Add this to your ~/.bashrc or ~/.zshrc:")
        print(f"   export PATH=\"{home_bin}:$PATH\"")
        print(f"\n   Then run: source ~/.bashrc (or ~/.zshrc)")
    
    print(f"\n✅ CyberAI Calion installed successfully!")
    print(f"   Wrapper: {wrapper}")
    print(f"   Data: {dest}")
    print(f"   Commands: {BINARY_NAME}, {LINK_NAME}")
    print(f"\n   Run: {BINARY_NAME}")
    print(f"   Or:  {LINK_NAME}")
    
    return True


def uninstall():
    """Remove installation"""
    success = True
    
    # Remove wrapper
    wrapper_paths = [
        os.path.join('/usr/local/bin', BINARY_NAME),
        os.path.join(USER_INSTALL_DIR, BINARY_NAME),
    ]
    
    for wrapper in wrapper_paths:
        if os.path.exists(wrapper):
            os.remove(wrapper)
            print(f"   Removed: {wrapper}")
    
    # Remove cyberai data directory
    data_paths = [
        '/usr/local/share/cyberai',
        os.path.expanduser('~/.local/share/cyberai'),
    ]
    
    for data in data_paths:
        if os.path.exists(data):
            shutil.rmtree(data)
            print(f"   Removed: {data}")
    
    # Remove symlinks
    link_paths = [
        os.path.join('/usr/local/bin', LINK_NAME),
        os.path.join(USER_INSTALL_DIR, LINK_NAME),
    ]
    
    for link in link_paths:
        if os.path.exists(link):
            os.remove(link)
            print(f"   Removed: {link}")
    
    print("\n🗑️  CyberAI Calion uninstalled successfully!")
    return success


def main():
    parser = argparse.ArgumentParser(
        description='Install CyberAI Calion Pentest Toolkit',
        epilog='After installation, run "cyberai" or "cyberai-calion" from anywhere.'
    )
    parser.add_argument('--user', action='store_true', help='Install for current user only')
    parser.add_argument('--uninstall', '-u', action='store_true', help='Uninstall CyberAI Calion')
    args = parser.parse_args()
    
    if args.uninstall:
        uninstall()
        sys.exit(0)
    
    print("=" * 60)
    print("  CyberAI Calion - Pentest Toolkit Installer")
    print("=" * 60)
    
    # Check dependencies
    print("\n📦 Checking dependencies...")
    missing = []
    
    for dep in ['python3', 'nmap']:
        result = subprocess.run(['which', dep], capture_output=True)
        if result.returncode != 0:
            missing.append(dep)
    
    if missing:
        print(f"   ⚠️  Missing: {', '.join(missing)}")
        print(f"   Install with: sudo apt install {' '.join(missing)}")
    else:
        print("   ✅ All dependencies found")
    
    # Check requirements.txt
    req_file = os.path.join(CYBERAI_DIR, 'requirements.txt')
    if os.path.exists(req_file):
        print(f"   📋 Requirements file found ({os.path.getsize(req_file)} bytes)")
    
    print("\n" + "-" * 60)
    
    if args.user:
        success = install_user()
    else:
        if check_root():
            success = install_systemwide()
        else:
            print("ℹ️  Not running as root. Use --user flag or run with sudo.")
            print("\n   Option 1: python3 install.py --user")
            print("   Option 2: sudo python3 install.py")
            sys.exit(1)
    
    if success:
        print("\n" + "=" * 60)
        print("  🎉 Installation complete!")
        print("=" * 60)
    else:
        print("\n❌ Installation failed.")
        sys.exit(1)


if __name__ == '__main__':
    main()
