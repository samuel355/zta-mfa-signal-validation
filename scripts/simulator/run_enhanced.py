#!/usr/bin/env python3
"""
Standalone script to run the enhanced simulator with proper parameter handling
This can be used for manual testing or external orchestration
"""
import os
import sys
import asyncio
import argparse
from pathlib import Path

# Add the simulator directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from enhanced_sim import EnhancedSimulator

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Enhanced Multi-Source MFA ZTA Framework Simulator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run with default settings (100 samples, 1s sleep)
  python run_enhanced.py

  # Run with custom parameters
  python run_enhanced.py --samples 50 --sleep 0.5 --data-dir /custom/data

  # Run with environment-based configuration
  SIM_MAX_SAMPLES=200 SIM_SLEEP=2.0 python run_enhanced.py

Environment Variables:
  DATA_DIR              - Path to data directory (default: /app/data)
  CICIDS_DIR           - Path to CICIDS dataset directory
  WIFI_CSV             - Path to WiFi data CSV file
  DEVICE_CSV           - Path to device posture CSV file
  TLS_CSV              - Path to TLS fingerprints CSV file
  VALIDATE_URL         - Validation service URL
  GATEWAY_URL          - Gateway service URL
  BASELINE_URL         - Baseline service URL
  DB_DSN               - Database connection string
  SIM_MAX_SAMPLES      - Number of samples to generate
  SIM_SLEEP            - Sleep time between requests (seconds)
        """
    )

    parser.add_argument(
        "--samples",
        type=int,
        default=int(os.getenv("SIM_MAX_SAMPLES", "100")),
        help="Number of samples to generate (default: 100)"
    )

    parser.add_argument(
        "--sleep",
        type=float,
        default=float(os.getenv("SIM_SLEEP", "1.0")),
        help="Sleep time between requests in seconds (default: 1.0)"
    )

    parser.add_argument(
        "--data-dir",
        default=os.getenv("DATA_DIR", "/app/data"),
        help="Path to data directory (default: /app/data)"
    )

    parser.add_argument(
        "--validate-url",
        default=os.getenv("VALIDATE_URL", "http://validation:8000/validate"),
        help="Validation service URL"
    )

    parser.add_argument(
        "--gateway-url",
        default=os.getenv("GATEWAY_URL", "http://gateway:8000/decision"),
        help="Gateway service URL"
    )

    parser.add_argument(
        "--baseline-url",
        default=os.getenv("BASELINE_URL", "http://baseline:8000/decision"),
        help="Baseline service URL"
    )

    parser.add_argument(
        "--db-dsn",
        default=os.getenv("DB_DSN", ""),
        help="Database connection string"
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show configuration and exit without running simulation"
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )

    parser.add_argument(
        "--skip-health-check",
        action="store_true",
        help="Skip service health checks before starting simulation"
    )

    return parser.parse_args()

def check_data_files(args):
    """Check if required data files exist"""
    data_dir = Path(args.data_dir)

    required_paths = {
        "Data directory": data_dir,
        "CICIDS directory": data_dir / "cicids",
        "WiFi CSV": data_dir / "wifi" / "wigle_sample.csv",
        "Device CSV": data_dir / "device_posture" / "device_posture.csv",
        "TLS CSV": data_dir / "tls" / "ja3_fingerprints.csv"
    }

    missing_files = []
    existing_files = []

    for name, path in required_paths.items():
        if path.exists():
            existing_files.append(f"✓ {name}: {path}")
        else:
            missing_files.append(f"✗ {name}: {path}")

    return existing_files, missing_files

def print_configuration(args):
    """Print current configuration"""
    print("="*60)
    print("📊 Enhanced Simulator Configuration")
    print("="*60)
    print(f"Samples to generate: {args.samples}")
    print(f"Sleep between requests: {args.sleep}s")
    print(f"Data directory: {args.data_dir}")
    print(f"Database DSN: {'✓ Configured' if args.db_dsn else '✗ Not configured'}")
    print()
    print("🌐 Service URLs:")
    print(f"  Validation: {args.validate_url}")
    print(f"  Gateway: {args.gateway_url}")
    print(f"  Baseline: {args.baseline_url}")
    print()

    # Check data files
    existing, missing = check_data_files(args)

    print("📁 Data Files:")
    for item in existing:
        print(f"  {item}")

    if missing:
        print("\n⚠️  Missing Data Files:")
        for item in missing:
            print(f"  {item}")
        print("\n⚠️  Some data files are missing. Simulation will use fallback data generation.")

    print("="*60)

async def main():
    """Main entry point"""
    args = parse_args()

    # Update environment variables with command line arguments
    os.environ.update({
        "DATA_DIR": args.data_dir,
        "VALIDATE_URL": args.validate_url,
        "GATEWAY_URL": args.gateway_url,
        "BASELINE_URL": args.baseline_url,
        "SIM_SLEEP": str(args.sleep),
        "SIM_MAX_SAMPLES": str(args.samples)
    })

    if args.db_dsn:
        os.environ["DB_DSN"] = args.db_dsn

    # Print configuration
    print_configuration(args)

    # Dry run - just show config and exit
    if args.dry_run:
        print("\n🏃‍♂️ Dry run mode - exiting without running simulation")
        return

    # Health check (unless skipped)
    if not args.skip_health_check:
        print("\n🏥 Checking service health...")
        # Import here to avoid issues if services are down
        try:
            from start_simulation import wait_for_services
            services_ready = await wait_for_services()
            if not services_ready:
                print("❌ Some services are not ready. Use --skip-health-check to proceed anyway.")
                sys.exit(1)
        except ImportError:
            print("⚠️  Health check module not available, proceeding without health check...")
        except Exception as e:
            print(f"⚠️  Health check failed: {e}")
            if not args.skip_health_check:
                response = input("Continue anyway? [y/N]: ")
                if response.lower() != 'y':
                    sys.exit(1)

    # Create and run simulator
    print("\n🚀 Starting enhanced simulation...")

    try:
        simulator = EnhancedSimulator()

        # Run simulation
        result = await simulator.run_simulation(args.samples)

        print("\n✅ Simulation completed successfully!")
        print(f"📊 Results:")
        print(f"  Comparison ID: {result.get('comparison_id', 'N/A')}")
        print(f"  Total samples: {result.get('total_samples', 0)}")
        print(f"  Successful comparisons: {result.get('successful_comparisons', 0)}")

        if result.get('total_samples', 0) > 0:
            success_rate = (result.get('successful_comparisons', 0) / result.get('total_samples', 1)) * 100
            print(f"  Success rate: {success_rate:.1f}%")

    except KeyboardInterrupt:
        print("\n⏹️  Simulation interrupted by user")
    except Exception as e:
        print(f"\n❌ Simulation failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
