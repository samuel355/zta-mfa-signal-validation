#!/usr/bin/env python3
"""
Startup script for the enhanced simulation that waits for all services to be ready
"""
import os
import sys
import time
import asyncio
import httpx
from typing import Dict, List

# Service health check endpoints
HEALTH_CHECKS = {
    "elasticsearch": "http://elasticsearch:9200/_cluster/health",
    "validation": "http://validation:8000/health",
    "trust": "http://trust:8000/health",
    "gateway": "http://gateway:8000/health",
    "siem": "http://siem:8000/health",
    "baseline": "http://baseline:8000/health",
    "metrics": "http://metrics:8000/health"
}

# Configuration
MAX_WAIT_TIME = 300  # 5 minutes total wait time
CHECK_INTERVAL = 5   # Check every 5 seconds
REQUIRED_SERVICES = ["validation", "gateway", "baseline"]  # Minimum required services
OPTIONAL_SERVICES = ["elasticsearch", "trust", "siem", "metrics"]

async def check_service_health(client: httpx.AsyncClient, name: str, url: str) -> bool:
    """Check if a service is healthy"""
    try:
        if name == "elasticsearch":
            # Special handling for Elasticsearch
            response = await client.get(url, timeout=10.0)
            if response.status_code == 200:
                data = response.json()
                return data.get("status") in ["green", "yellow"]
            return False
        else:
            # Standard health check
            response = await client.get(url, timeout=10.0)
            return response.status_code == 200
    except Exception as e:
        print(f"[HEALTH] {name}: {e}")
        return False

async def wait_for_services():
    """Wait for all required services to be ready"""
    print("[STARTUP] Waiting for services to be ready...")

    start_time = time.time()
    ready_services = set()

    async with httpx.AsyncClient() as client:
        while time.time() - start_time < MAX_WAIT_TIME:
            print(f"[STARTUP] Checking service health... ({int(time.time() - start_time)}s elapsed)")

            # Check all services
            for service_name, health_url in HEALTH_CHECKS.items():
                if service_name not in ready_services:
                    is_healthy = await check_service_health(client, service_name, health_url)
                    if is_healthy:
                        ready_services.add(service_name)
                        print(f"[STARTUP] ✓ {service_name} is ready")

            # Check if we have minimum required services
            required_ready = all(service in ready_services for service in REQUIRED_SERVICES)

            if required_ready:
                print(f"[STARTUP] ✓ All required services are ready!")

                # Show status of optional services
                for service in OPTIONAL_SERVICES:
                    if service in ready_services:
                        print(f"[STARTUP] ✓ {service} (optional) is ready")
                    else:
                        print(f"[STARTUP] ⚠ {service} (optional) is not ready - continuing anyway")

                return True

            # Show current status
            missing_required = [s for s in REQUIRED_SERVICES if s not in ready_services]
            if missing_required:
                print(f"[STARTUP] Still waiting for: {', '.join(missing_required)}")

            await asyncio.sleep(CHECK_INTERVAL)

    print(f"[STARTUP] ❌ Timeout waiting for services after {MAX_WAIT_TIME}s")
    return False

async def run_continuous_simulation():
    """Run the enhanced simulation continuously for 24 hours"""
    print("[STARTUP] Starting 24-hour continuous simulation...")

    # Import and run the enhanced simulator
    try:
        from enhanced_sim import EnhancedSimulator
        from datetime import datetime, timedelta

        # Get simulation parameters from environment
        batch_size = int(os.getenv("SIM_MAX_ROWS", "100"))
        sleep_time = float(os.getenv("SIM_SLEEP", "1.0"))
        sim_duration_hours = float(os.getenv("SIM_DURATION_HOURS", "24.0"))

        print(f"[STARTUP] Configuration:")
        print(f"[STARTUP]   Batch size: {batch_size} samples")
        print(f"[STARTUP]   Sleep between requests: {sleep_time}s")
        print(f"[STARTUP]   Duration: {sim_duration_hours} hours")
        print(f"[STARTUP]   Data directory: {os.getenv('DATA_DIR', '/app/data')}")

        start_time = datetime.now()
        end_time = start_time + timedelta(hours=sim_duration_hours)

        print(f"[STARTUP] Started at: {start_time}")
        print(f"[STARTUP] Will run until: {end_time}")

        simulator = EnhancedSimulator()
        batch_count = 0
        total_samples = 0

        # Run continuous batches until time limit
        while datetime.now() < end_time:
            batch_count += 1
            remaining_time = end_time - datetime.now()

            print(f"[BATCH] Starting batch {batch_count} (Remaining: {remaining_time})")

            try:
                result = await simulator.run_simulation(batch_size, sleep_time)
                if result:
                    total_samples += result.get('total_samples', 0)
                    print(f"[BATCH] Completed batch {batch_count}: {result.get('total_samples', 0)} samples")
                else:
                    print(f"[BATCH] Batch {batch_count} failed - no result")
            except Exception as e:
                print(f"[BATCH] Batch {batch_count} error: {e}")
                # Continue with next batch instead of failing completely
                await asyncio.sleep(30)  # Wait 30s before retry

            # Brief pause between batches
            await asyncio.sleep(10)

        duration = datetime.now() - start_time
        print(f"[STARTUP] ✅ 24-hour simulation completed!")
        print(f"[STARTUP] Total duration: {duration}")
        print(f"[STARTUP] Total batches: {batch_count}")
        print(f"[STARTUP] Total samples: {total_samples}")

    except Exception as e:
        print(f"[STARTUP] ❌ Simulation failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

async def main():
    """Main startup sequence"""
    print("="*60)
    print("🚀 Multi-Source MFA ZTA Framework - Enhanced Simulation")
    print("="*60)

    # Wait for services to be ready
    services_ready = await wait_for_services()

    if not services_ready:
        print("[STARTUP] ❌ Required services not ready, exiting...")
        sys.exit(1)

    # Add a small delay to ensure services are fully initialized
    print("[STARTUP] Services ready! Waiting 10 seconds for full initialization...")
    await asyncio.sleep(10)

    # Run the continuous simulation
    await run_continuous_simulation()

    print("[STARTUP] 🎉 All done!")

if __name__ == "__main__":
    asyncio.run(main())
