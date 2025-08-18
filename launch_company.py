"""
Company Launcher - Choose which company to work with independently.
This ensures you never accidentally work on the wrong database.
"""

import sys
import os
from independent_apps import get_ap_app, get_fdec_app


def launch_ap():
    """Launch A&P POR system exclusively."""
    print("🔵 Launching A&P POR System...")
    print("=" * 50)
    
    app = get_ap_app()
    stats = app.get_statistics()
    
    print(f"Company: {stats['company']}")
    print(f"Database: {stats['database_file']}")
    print(f"Total PORs: {stats['total_pors']}")
    print(f"Received: {stats['received']}")
    print(f"Sent: {stats['sent']}")
    print(f"Filed: {stats['filed']}")
    print("=" * 50)
    print("✅ A&P system ready - FDEC database is completely isolated")
    
    return app


def launch_fdec():
    """Launch FDEC POR system exclusively."""
    print("🟢 Launching FDEC POR System...")
    print("=" * 50)
    
    app = get_fdec_app()
    stats = app.get_statistics()
    
    print(f"Company: {stats['company']}")
    print(f"Database: {stats['database_file']}")
    print(f"Total PORs: {stats['total_pors']}")
    print(f"Received: {stats['received']}")
    print(f"Sent: {stats['sent']}")
    print(f"Filed: {stats['filed']}")
    print("=" * 50)
    print("✅ FDEC system ready - A&P database is completely isolated")
    
    return app


def main():
    """Main launcher - choose company to work with."""
    print("\n🏢 POR System Company Launcher")
    print("=" * 40)
    print("Choose which company to work with:")
    print("1. A&P (Blue)")
    print("2. FDEC (Green)")
    print("3. Show both statistics")
    print("4. Exit")
    print("=" * 40)
    
    while True:
        choice = input("\nEnter your choice (1-4): ").strip()
        
        if choice == '1':
            return launch_ap()
        elif choice == '2':
            return launch_fdec()
        elif choice == '3':
            print("\n📊 Database Statistics:")
            print("-" * 30)
            ap_app = get_ap_app()
            fdec_app = get_fdec_app()
            
            ap_stats = ap_app.get_statistics()
            fdec_stats = fdec_app.get_statistics()
            
            print(f"🔵 A&P: {ap_stats['total_pors']} PORs in {ap_stats['database_file']}")
            print(f"🟢 FDEC: {fdec_stats['total_pors']} PORs in {fdec_stats['database_file']}")
            print("-" * 30)
            continue
        elif choice == '4':
            print("👋 Goodbye!")
            sys.exit(0)
        else:
            print("❌ Invalid choice. Please enter 1, 2, 3, or 4.")


if __name__ == "__main__":
    try:
        selected_app = main()
        print(f"\n🎯 You are now working with {selected_app.display_name}")
        print("💡 The other company's database is completely isolated and safe.")
        
    except KeyboardInterrupt:
        print("\n\n👋 Launcher interrupted. Goodbye!")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)
