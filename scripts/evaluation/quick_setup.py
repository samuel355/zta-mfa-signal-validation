#!/usr/bin/env python3
"""
Quick Setup Script
Seeds database and runs a basic test to ensure everything works
"""
import os
import sys
import asyncio
import subprocess
from pathlib import Path

# Add script paths
script_dir = Path(__file__).parent
sys.path.append(str(script_dir))
sys.path.append(str(script_dir.parent / "simulator"))

def run_command(cmd, description):
    """Run a command and return success status"""
    print(f"[SETUP] {description}...")
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"[SETUP] ✅ {description} completed")
            return True
        else:
            print(f"[SETUP] ❌ {description} failed:")
            print(f"[SETUP]    {result.stderr.strip()}")
            return False
    except Exception as e:
        print(f"[SETUP] ❌ {description} failed with exception: {e}")
        return False

def check_database_connection():
    """Check if database is accessible"""
    print("[SETUP] Checking database connection...")
    try:
        from seed_database import DatabaseSeeder
        seeder = DatabaseSeeder()
        print("[SETUP] ✅ Database connection successful")
        return True
    except Exception as e:
        print(f"[SETUP] ❌ Database connection failed: {e}")
        print("[SETUP]    Make sure DB_DSN environment variable is set")
        print("[SETUP]    Example: export DB_DSN='postgresql://user:pass@host:5432/db'")
        return False

def seed_database():
    """Seed database with test data"""
    print("[SETUP] Seeding database with test data...")
    try:
        from seed_database import DatabaseSeeder
        seeder = DatabaseSeeder()
        seeder.seed_all_tables()
        print("[SETUP] ✅ Database seeded successfully")
        return True
    except Exception as e:
        print(f"[SETUP] ❌ Database seeding failed: {e}")
        return False

async def test_metrics_endpoint():
    """Test if metrics endpoint returns data"""
    print("[SETUP] Testing metrics endpoint...")
    try:
        import httpx
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get("http://localhost:8030/metrics/comparison?hours=24")
            if response.status_code == 200:
                data = response.json()
                summary = data.get("summary", {})
                total_events = summary.get("total_events", 0)
                if total_events > 0:
                    print(f"[SETUP] ✅ Metrics endpoint working - {total_events} events found")
                    return True
                else:
                    print("[SETUP] ⚠️  Metrics endpoint working but no data found")
                    print("[SETUP]    This is expected if services aren't generating data yet")
                    return True
            else:
                print(f"[SETUP] ❌ Metrics endpoint returned {response.status_code}")
                return False
    except Exception as e:
        print(f"[SETUP] ❌ Metrics endpoint test failed: {e}")
        print("[SETUP]    Make sure metrics service is running on port 8030")
        return False

def check_data_files():
    """Check if data files exist"""
    print("[SETUP] Checking data files...")

    base_dir = Path(__file__).parent.parent.parent
    data_dir = base_dir / "data"

    required_dirs = [
        data_dir / "cicids",
        data_dir / "wifi",
        data_dir / "device_posture",
        data_dir / "tls"
    ]

    missing_dirs = []
    for dir_path in required_dirs:
        if not dir_path.exists():
            missing_dirs.append(str(dir_path))

    if missing_dirs:
        print("[SETUP] ⚠️  Some data directories are missing:")
        for missing in missing_dirs:
            print(f"[SETUP]    - {missing}")
        print("[SETUP]    Enhanced simulation may not work optimally")
        return False
    else:
        print("[SETUP] ✅ All data directories found")
        return True

async def run_quick_test():
    """Run a quick evaluation test"""
    print("[SETUP] Running quick evaluation test...")
    try:
        cmd = f"cd {script_dir} && python3 run_evaluation.py --mode quick --skip-health-check"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        if result.returncode == 0:
            print("[SETUP] ✅ Quick evaluation test passed")
            return True
        else:
            print("[SETUP] ❌ Quick evaluation test failed:")
            print(f"[SETUP]    {result.stderr.strip()}")
            return False
    except Exception as e:
        print(f"[SETUP] ❌ Quick evaluation test failed: {e}")
        return False

async def main():
    """Main setup routine"""
    print("🚀 ZTA Framework Quick Setup")
    print("=" * 50)

    setup_steps = []

    # Step 1: Check database connection
    if check_database_connection():
        setup_steps.append("✅ Database connection")

        # Step 2: Seed database
        if seed_database():
            setup_steps.append("✅ Database seeding")
        else:
            setup_steps.append("❌ Database seeding")
    else:
        setup_steps.append("❌ Database connection")

    # Step 3: Check data files
    if check_data_files():
        setup_steps.append("✅ Data files")
    else:
        setup_steps.append("⚠️  Data files (partial)")

    # Step 4: Test metrics endpoint
    if await test_metrics_endpoint():
        setup_steps.append("✅ Metrics endpoint")
    else:
        setup_steps.append("❌ Metrics endpoint")

    # Step 5: Run quick test
    if await run_quick_test():
        setup_steps.append("✅ Quick evaluation")
    else:
        setup_steps.append("❌ Quick evaluation")

    # Summary
    print("\n" + "=" * 50)
    print("📋 SETUP SUMMARY")
    print("=" * 50)

    for step in setup_steps:
        print(f"  {step}")

    successful_steps = sum(1 for step in setup_steps if step.startswith("✅"))
    total_steps = len(setup_steps)

    print(f"\n📊 Success Rate: {successful_steps}/{total_steps} ({successful_steps/total_steps*100:.1f}%)")

    if successful_steps >= 3:
        print("\n🎉 SETUP SUCCESSFUL!")
        print("You can now run evaluations:")
        print("  - python3 run_evaluation.py --mode quick --skip-health-check")
        print("  - python3 run_evaluation.py --mode quick --seed-database")
        print("  - python3 run_evaluation.py --mode quick --enhanced-sim --sim-samples 50")

        if successful_steps == total_steps:
            print("\n🔥 PERFECT SETUP!")
            print("All systems are working. Ready for full evaluation!")

        return 0
    else:
        print("\n⚠️  SETUP INCOMPLETE")
        print("Some components failed. Check the errors above.")
        print("You may still be able to run basic evaluations.")
        return 1

if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n[SETUP] Setup interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[SETUP] Setup failed with error: {e}")
        sys.exit(1)
