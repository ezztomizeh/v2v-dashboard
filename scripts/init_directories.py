#!/usr/bin/env python3
"""
Initialize directories for V2V certificate system
Run this first to create all necessary directories
"""

import os
import sys
from pathlib import Path

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

def main():
    """Create all necessary directories for the certificate system"""
    print("🔧 Initializing V2V Certificate System Directories...")
    
    # Import settings
    try:
        from config.settings import settings
    except ImportError:
        # Fallback if import fails
        base_dir = Path(__file__).parent.parent
        certs_base = base_dir / "certs"
        
        directories = [
            certs_base / "ca",
            certs_base / "vehicles" / "certs",
            certs_base / "vehicles" / "private",
            certs_base / "vehicles" / "public",
        ]
    else:
        directories = [
            Path(settings.CA_CERT_PATH).parent,
            Path(settings.CERTIFICATES_PATH),
            Path(settings.PRIVATE_KEYS_PATH),
            Path(settings.PUBLIC_KEYS_PATH),
        ]
    
    # Create each directory
    for directory in directories:
        try:
            directory.mkdir(parents=True, exist_ok=True)
            print(f"✅ Created: {directory}")
            
            # Set permissions
            if "private" in str(directory) or "ca" in str(directory):
                os.chmod(directory, 0o700)
                print(f"   🔒 Secure permissions set (700)")
        except Exception as e:
            print(f"❌ Error creating {directory}: {e}")
    
    print("\n📁 Directory structure created successfully!")
    print("You can now run: python scripts/init_ca.py")

if __name__ == "__main__":
    main()